#!/usr/bin/env node
/**
 * The sandbox self test. Runs selftest/hostile.py once per case in the real sandbox: gVisor (runsc),
 * the container settings every target gets (user 65534, no capabilities, read-only root, limits,
 * one work volume), a run network with the network logger, and net-guard.sh's firewall on the host.
 * Each case tries one way out; src/selftest.mjs decides from the harness's own evidence (the runsc
 * syscall trace, the network logger, the host firewall log, docker inspect, a listener on the host)
 * whether it was blocked and whether it was logged. A case passes only when both hold.
 *
 *   node bin/sandbox-selftest.mjs --out DIR [--cases a,b] [--images images.json] [--lane ci|local]
 *   node bin/sandbox-selftest.mjs --out DIR --lane selftest-mutation --disable PROTECTION [--cases a,b]
 *
 * --disable turns off exactly one protection, to prove the self test can fail (the `mutation` job
 * of sandbox-selftest.yml; scripts/check-mutation.mjs checks it failed for the expected reason). It
 * is refused on every lane but selftest-mutation, and that lane needs it. See MUTATIONS.
 *
 * Writes DIR/telemetry.jsonl (docs/TELEMETRY.md), DIR/results.json and, kept apart and never parsed
 * as results, DIR/untrusted/<case>.stdout and .stderr (what the hostile target printed).
 * Prints one line per case, "selftest <case>: pass" or "selftest <case>: FAIL (...)", then a total.
 * Exits 0 only when every case passed. When the sandbox is not there (no runsc, other runsc flags,
 * net-guard.sh not run, no trace, no kernel log) it records a skip with the reason and exits 1:
 * nothing falls back to runc.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, rmSync, statfsSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { arch, platform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

import { Docker, HarnessError, checkDockerVersion, dockerEnvFrom, helperRunArgs, sandboxRunArgs, LIMITS, LABEL_RUN, LABEL_TARGET } from '../src/docker.mjs';
import { loadRunscConfig, RUNTIME } from '../src/runsc.mjs';
import { NETS, readHostLog } from '../src/sandbox-net.mjs';
import { inspectMismatches, settingsDigest, settingsManifest } from '../src/sandbox-env.mjs';
import { Telemetry, fromNetlog, fromProxy, newRunId, readTelemetry } from '../src/telemetry.mjs';
import { CASES, CANARY_PORT, CASE_LISTEN_PORT, INSTALL_CASES, PROXY_ALLOWED, PROXY_DENIED_HOSTS, READOUT_PATHS, caseNet, evaluateCase } from '../src/selftest.mjs';
import { firewallCounts, limitsHit, hostDropsFor, inspectOne, preflight, rolesOn, startNetlogOn, stopNetlog, sweepTraces, takeTrace, watchTraces, workReadCmd, writeDrops, writeNetlog } from '../src/sandbox-run.mjs';
import { P } from '../src/targets.mjs';
import { lookup } from 'node:dns/promises';
import { PROXY_PORT, PROXY_URL, loadImages, resolveRegistries } from './run-shard.mjs';

export const RESULTS_FORMAT = 'isokron-sandbox-selftest/1';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const say = (line) => process.stdout.write(`${line}\n`);
const CASE_MS = 120_000;
const OUT_CAP = 1024 * 1024;
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

/**
 * The protections --disable can turn off, test-only: what each changes. Host changes run through
 * `sudo -n` before the preflight; the others change the case container or its network only.
 */
export const MUTATIONS = {
  'runtime-runc': 'the case container runs under runc instead of runsc',
  'firewall-forward': "net-guard.sh's ISK-SBX chain is flushed and DOCKER-USER no longer jumps to it",
  'firewall-input': "net-guard.sh's INPUT jumps to ISK-SBX-IN are removed",
  'firewall-order': 'an ACCEPT for the sandbox range is put above net-guard.sh\'s jumps in DOCKER-USER',
  'firewall-order-goto': 'a goto (-g) for the sandbox range, to a chain that accepts, is put above net-guard.sh\'s jumps in DOCKER-USER',
  'cap-drop': 'the case container keeps Docker\'s default capabilities (no --cap-drop ALL)',
  'env-filter': "the runner's tokens (the canaries) reach the case container's environment",
  'read-only': 'the case container has a writable root filesystem',
  'internal-net': 'the run network is made without --internal',
  'proxy-allowlist': 'the install network\'s egress proxy also allows the hosts the install cases must be refused',
  'proxy-allowlist-empty': 'the install network\'s egress proxy allows nothing (its allowlist names only a host that does not exist)',
  'readout-follows-links': 'the result readout reads a path as it is, links and all (head -c, no check that the path resolves to itself)',
  'no-teardown': 'a server-like case is not torn down when its stage ends: its container keeps running',
  'volume-cap': 'the case\'s work volume is a folder on the runner\'s own disk (a bind volume under --out), not on the volume filesystem install-runsc.sh makes',
};

/**
 * Cases that run like a server and do not end by themselves: the harness ends their stage after
 * this long and tears the container down (docker kill), as the corpus does when a probe is done.
 */
export const STAGE_MS = { 'unix-socket': 20_000 };

export function parseArgs(argv) {
  const o = { out: null, cases: [...CASES], images: join(root, 'images.json'), lane: 'local', disable: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; const v = () => { if (i + 1 >= argv.length) throw new HarnessError(`${a} needs a value`); return argv[++i]; };
    if (a === '--out') o.out = v();
    else if (a === '--cases') o.cases = v().split(',').filter(Boolean);
    else if (a === '--images') o.images = v();
    else if (a === '--lane') o.lane = v();
    else if (a === '--disable') o.disable = v();
    else throw new HarnessError(`unknown option ${a}`);
  }
  if (!o.out) throw new HarnessError('usage: sandbox-selftest.mjs --out DIR [--cases a,b] [--images images.json] [--lane ci|local]');
  if (!o.cases.length || !o.cases.every((c) => CASES.includes(c))) throw new HarnessError(`--cases takes some of: ${CASES.join(', ')}`);
  if (!['ci', 'local', 'selftest-mutation'].includes(o.lane)) throw new HarnessError('--lane must be ci, local or selftest-mutation');
  if (o.disable !== null && o.lane !== 'selftest-mutation') throw new HarnessError('--disable is refused except on the selftest-mutation lane');
  if (o.lane === 'selftest-mutation' && !Object.prototype.hasOwnProperty.call(MUTATIONS, String(o.disable))) throw new HarnessError(`the selftest-mutation lane needs --disable with one of: ${Object.keys(MUTATIONS).join(', ')}`);
  return o;
}

/**
 * What a runner's environment would hold, as canary values: the docker client that starts the case
 * container has them in its own environment, and none may reach the container.
 */
export function canaryEnv(nonce) {
  return {
    GITHUB_TOKEN: `isk-canary-${nonce}-github-token`,
    GH_TOKEN: `isk-canary-${nonce}-gh-token`,
    ACTIONS_RUNTIME_TOKEN: `isk-canary-${nonce}-actions-runtime-token`,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: `isk-canary-${nonce}-id-token-request`,
    ACTIONS_ID_TOKEN_REQUEST_URL: `https://isk-canary-${nonce}.invalid/id-token`,
    CORPUS_TARGETS_KEY: `isk-canary-${nonce}-corpus-targets-key`,
  };
}

/** The case container's `docker run` arguments with one protection taken out (MUTATIONS), test-only. */
export function mutateCaseArgs(argv, disable, canaries) {
  const a = [...argv];
  const drop = (flag, val) => { for (let i = 0; i < a.length; i++) if (a[i] === flag && (val === undefined || a[i + 1] === val)) { a.splice(i, val === undefined ? 1 : 2); return; } throw new HarnessError(`mutation: ${flag} not found`); };
  const image = a.findIndex((x) => /@sha256:[0-9a-f]{64}$/.test(x));
  if (disable === 'runtime-runc') a[a.indexOf('--runtime') + 1] = 'runc';
  else if (disable === 'cap-drop') drop('--cap-drop', 'ALL');
  else if (disable === 'read-only') drop('--read-only');
  else if (disable === 'env-filter') a.splice(image, 0, ...Object.entries(canaries).flatMap(([k, v]) => ['--env', `${k}=${v}`]));
  return a;
}

/** The host changes of a mutation, through sudo -n (the runner's sudo): true when they all worked. */
export function mutateHost(disable, run = spawnSync) {
  const cmds = disable === 'firewall-forward'
    ? [['iptables', '-F', 'ISK-SBX'], ['iptables', '-D', 'DOCKER-USER', '-s', '10.213.52.0/22', '-j', 'ISK-SBX'], ['iptables', '-D', 'DOCKER-USER', '-d', '10.213.52.0/22', '-j', 'ISK-SBX']]
    : disable === 'firewall-input' ? [['iptables', '-D', 'INPUT', '-i', 'docker0', '-j', 'ISK-SBX-IN'], ['iptables', '-D', 'INPUT', '-i', 'br-+', '-j', 'ISK-SBX-IN']]
      : disable === 'firewall-order' ? [['iptables', '-I', 'DOCKER-USER', '1', '-s', '10.213.52.0/22', '-j', 'ACCEPT']]
        : disable === 'firewall-order-goto' ? [['iptables', '-N', 'ISK-MUT-GOTO'], ['iptables', '-A', 'ISK-MUT-GOTO', '-j', 'ACCEPT'], ['iptables', '-I', 'DOCKER-USER', '1', '-s', '10.213.52.0/22', '-g', 'ISK-MUT-GOTO']] : [];
  return cmds.every((c) => run('sudo', ['-n', ...c], { encoding: 'utf8', timeout: 30_000 }).status === 0);
}

/**
 * The helper's command that hands the case its work volume (as root, with CAP_CHOWN only): chmod
 * first, because once /work belongs to 65534, root without CAP_FOWNER may no longer change its mode.
 */
export const WORK_VOLUME_CMD = 'chmod 0750 /work && chown 65534:65534 /work';

/** The env the hostile target gets: what any target gets, nothing of the runner's. */
const CASE_ENV = { HOME: P.home, TMPDIR: '/tmp', NO_COLOR: '1', PYTHONDONTWRITEBYTECODE: '1', PYTHONUNBUFFERED: '1', SURFACE_SANDBOX: '1' };
/** An install case's env adds what an install gets: the proxy, and nothing else of the runner's. */
const INSTALL_CASE_ENV = { ...CASE_ENV, HTTPS_PROXY: PROXY_URL, https_proxy: PROXY_URL, HTTP_PROXY: PROXY_URL, http_proxy: PROXY_URL, NO_PROXY: '', no_proxy: '' };

/**
 * The install network's egress proxy, as bin/run-shard.mjs starts it for an install: our code under
 * gVisor, on the network with egress and at .3 of the case's install network, allowing the registry
 * (as fixed host entries the host resolved) on 443 and nothing else. Returns its name.
 */
async function startProxy(dk, ctx, { inNet, name, lbl }) {
  const allow = ctx.disable === 'proxy-allowlist' ? [...PROXY_ALLOWED, ...PROXY_DENIED_HOSTS]
    : ctx.disable === 'proxy-allowlist-empty' ? ['allowlist.invalid'] : [...PROXY_ALLOWED];
  const proxy = dk.name(name, 'proxy');
  const args = helperRunArgs({ name: proxy, image: ctx.images.node24, network: ctx.outNet, create: true, labels: lbl, memory: '256m', publicHosts: ctx.publicHosts, mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', `${P.tools}/sandbox/egress-proxy.mjs`, String(PROXY_PORT), ...allow] });
  ctx.tel.write('settings', { digest: settingsDigest(settingsManifest(args, { role: 'proxy' })), manifest: settingsManifest(args, { role: 'proxy' }) }, { subject: `case:${name}`, role: 'proxy' });
  await dk.must(dk.d(args, { deadline: Date.now() + 120_000 }), 'egress proxy');
  await dk.must(dk.d(['network', 'connect', '--ip', NETS.install.proxy, inNet, proxy], { deadline: Date.now() + 60_000 }), 'egress proxy network');
  await dk.must(dk.d(['start', proxy], { deadline: Date.now() + 60_000 }), 'egress proxy start');
  for (const until = Date.now() + 30_000; ;) {
    const r = await dk.d(['logs', proxy], { keepStdout: true, logStdout: false, cap: 64 * 1024, deadline: Date.now() + 10_000 });
    if (String(r.stdout).split('\n').some((l) => { try { return Number.isInteger(JSON.parse(l).listening); } catch { return false; } })) return proxy;
    if (Date.now() >= until) throw new HarnessError('the egress proxy did not start');
    await sleep(250);
  }
}

/** A listener on the host side of the run network: any connection that reaches it is a hit. */
function listenCanary(host, port) {
  let hits = 0;
  const onConn = (c) => { hits++; c.on('error', () => {}); c.destroy(); };
  const at = (h) => new Promise((done) => {
    const s = createServer(onConn);
    s.once('error', () => done(null));
    s.listen(port, h, () => done(s));
  });
  return (async () => {
    // The bridge's own address first; where the daemon gives the bridge none, every address.
    let bound = host; let s = await at(host);
    if (!s) { bound = '0.0.0.0'; s = await at('0.0.0.0'); }
    if (!s) bound = null;
    return { bound, hits: () => (s ? hits : null), close: () => { if (s) s.close(); } };
  })();
}

const lastJson = (text) => {
  const lines = String(text).trim().split('\n');
  try { const o = JSON.parse(lines[lines.length - 1]); return o && typeof o === 'object' && !Array.isArray(o) ? o : null; } catch { return null; }
};

/** symlink-escape: a canary file on the host (in --out), at the path a GitHub runner gives it, which no link may reach. */
function plantHostCanary(out, nonce) {
  const dir = join(out, 'host-canary');
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const content = `isk-canary-${nonce}-host\n`;
  writeFileSync(join(dir, 'canary'), content, { mode: 0o644 });
  return { dir, content };
}
function checkHostCanary(c, out, nonce) {
  let intact = false; let planted = 0;
  try { intact = readFileSync(join(c.dir, 'canary'), 'utf8') === c.content; } catch { intact = false; }
  try { planted += readdirSync(c.dir).filter((n) => n !== 'canary').length; } catch { planted += 1; }
  try { planted += readdirSync(out).filter((n) => n.includes(nonce)).length; } catch { /* the out folder is ours */ }
  rmSync(c.dir, { recursive: true, force: true });
  return { intact, planted };
}

/** The free bytes of the filesystems at `paths`, watched while a case runs: how far the lowest fell, in MB (null if unreadable). */
function watchFree(paths, { intervalMs = 500, statfs = statfsSync } = {}) {
  const free = (p) => { try { const s = statfs(p); return Number(s.bavail) * Number(s.bsize); } catch { return null; } };
  const base = paths.map(free);
  const low = [...base];
  const tick = () => paths.forEach((p, i) => { const f = free(p); if (f !== null && low[i] !== null) low[i] = Math.min(low[i], f); });
  const timer = setInterval(tick, intervalMs);
  timer.unref?.();
  return { stop: () => { clearInterval(timer); tick(); if (base.some((b) => b === null)) return null; return Math.max(0, ...base.map((b, i) => Math.round((b - low[i]) / 1048576))); } };
}

/** mutation volume-cap: the case's work volume as a folder on the runner's own disk (a bind volume), test-only. */
async function uncappedVolume(dk, name, target, out) {
  const dir = join(out, `uncapped-${target}`);
  mkdirSync(dir, { recursive: true, mode: 0o755 });
  // Owned by root like a volume Docker makes, so the work volume helper (root with CAP_CHOWN only) may chmod it.
  if (spawnSync('sudo', ['-n', 'chown', '0:0', dir], { timeout: 30_000 }).status !== 0) throw new HarnessError('mutation volume-cap: the folder could not be given to root');
  await dk.must(dk.d(['volume', 'create', '--driver', 'local', '--opt', 'type=none', '--opt', 'o=bind', '--opt', `device=${dir}`, '--label', `${LABEL_RUN}=${dk.runId}`, '--label', `${LABEL_TARGET}=${target}`, name]), 'volume create');
  return { name, dir };
}

const lastLine = (buf) => lastJson(String(buf));
const clip = (v, n = 120) => String(v ?? '').slice(0, n);

/**
 * Later stages: our code, in a helper container, after the case's container ended or was torn
 * down, looking at what the case left behind. What each returns goes into case_evidence.stage.
 */
const STAGES = {
  // The result readout over the paths the corpus reads out of a work volume, where the case planted links.
  'symlink-escape': async (ctx, { work, lbl, name }) => {
    const readout = [];
    for (const path of READOUT_PATHS) {
      const cmd = ctx.disable === 'readout-follows-links' ? ['sh', '-c', 'exec head -c "$2" -- "$1"', 'sh', path, String(1024 * 1024)] : workReadCmd(path, 1024 * 1024);
      const r = await ctx.dk.d(helperRunArgs({ name: ctx.dk.name(name, 'readout'), image: ctx.images.node22, labels: lbl, mounts: [{ src: work, dst: P.work, ro: true }], cmd }), { keepStdout: true, logStdout: false, cap: 1024 * 1024, deadline: Date.now() + 60_000 });
      readout.push({ path, exit: Number.isInteger(r.exit) ? r.exit : null, bytes: r.stdout_bytes });
    }
    return { readout };
  },
  // A later stage on the run network tries what the case left listening.
  'unix-socket': async (ctx, { work, lbl, name, network, nonce }) => {
    const r = await ctx.dk.d(helperRunArgs({ name: ctx.dk.name(name, 'reach'), image: ctx.images.node22, network, ip: NETS.run.probe, resolv: 'run', labels: lbl, mounts: [{ src: work, dst: P.work, ro: true }, { src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', `${P.tools}/selftest/stage.mjs`, 'reach', NETS.run.target, String(CASE_LISTEN_PORT), `${P.work}/isk-${nonce}.sock`, `isk-listen-${nonce}`] }), { keepStdout: true, logStdout: false, cap: 64 * 1024, deadline: Date.now() + 60_000 });
    const o = lastLine(r.stdout);
    const reach = o && Array.isArray(o.reach) ? o.reach.slice(0, 8).map((x) => ({ to: clip(x && x.to), ok: !!(x && x.ok === true), code: clip(x && x.code, 40), bytes: Number.isInteger(x && x.bytes) ? x.bytes : 0 })) : [];
    return { reach, exit: r.exit };
  },
  // The filesystem the work volume lives on, as a helper sees it, and how far the runner's disk fell.
  'install-archive-bomb': async (ctx, { work, lbl, name }) => {
    const r = await ctx.dk.d(helperRunArgs({ name: ctx.dk.name(name, 'measure'), image: ctx.images.node22, labels: lbl, mounts: [{ src: work, dst: P.work, ro: true }, { src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', `${P.tools}/selftest/stage.mjs`, 'measure', P.work] }), { keepStdout: true, logStdout: false, cap: 64 * 1024, deadline: Date.now() + 120_000 });
    const o = lastLine(r.stdout);
    const n = (v) => (Number.isFinite(Number(v)) ? Math.round(Number(v)) : null);
    const d = o && o.disk && typeof o.disk === 'object' ? o.disk : null;
    return { disk: d ? { work_fs_mb: n(d.work_fs_mb), work_fs_inodes: n(d.work_fs_inodes), work_used_mb: n(d.work_used_mb), work_files: n(d.work_files) } : null, exit: r.exit };
  },
};

async function runCase(name, ctx) {
  const { dk, tel, cfg, images, out } = ctx;
  const nonce = randomBytes(8).toString('hex');
  const canaries = canaryEnv(nonce);
  const subject = `case:${name}`;
  const meta = { subject, role: 'case' };
  const lbl = dk.labels(name);
  const netName = caseNet(name);
  const NET = NETS[netName];
  const roles = rolesOn(netName, { target: 'case' });
  const since = Date.now() / 1000;
  const fw0 = firewallCounts();
  let proxy = null;
  const ev = { trace: null, dns: [], conns: [], drops: [], egress: [], canaryHits: null, inspect: null, container: null, telemetryHasNonce: null, output: null, outputRecorded: false, report: null, pidsLimit: Number(LIMITS.nproc) };
  let canary = null;
  let netlog = null;
  let watch = null;
  let hostCanary = null;
  let disk = null;
  const extra = { canary_bound: null };
  // The canaries go where a runner keeps its tokens: in the driver's own environment, for the whole
  // case. Every path that could carry them on (the docker client's environment, the target's
  // environment check) reads process.env, so a leak anywhere shows up in docker inspect.
  const savedEnv = Object.fromEntries(Object.keys(canaries).map((k) => [k, process.env[k]]));
  Object.assign(process.env, canaries);
  try {
    const network = netName === 'install'
      ? await dk.network(`surface-${dk.runId}-${name}-in`, true, name, { sandbox: 'install' })
      : ctx.disable === 'internal-net'
        ? await externalRunNetwork(dk, `surface-${dk.runId}-${name}-run`, name)
        : await dk.network(`surface-${dk.runId}-${name}-run`, true, name, { sandbox: 'run' });
    let work;
    if (ctx.disable === 'volume-cap') {
      const u = await uncappedVolume(dk, `surface-${dk.runId}-${name}-work`, name, out);
      work = u.name; ctx.cleanup.push(u.dir);
    } else work = await dk.volume(`surface-${dk.runId}-${name}-work`, name);
    await dk.must(dk.d(helperRunArgs({ name: dk.name(name, 'h'), image: images.node22, user: '0:0', capAdd: ['CHOWN'], labels: lbl, mounts: [{ src: work, dst: P.work }], cmd: ['sh', '-c', WORK_VOLUME_CMD] }), { deadline: Date.now() + 120_000 }), 'work volume');
    netlog = await startNetlogOn(dk, { net: netName, network, image: images.node22, toolsVol: ctx.toolsVol, labels: lbl, target: name });
    if (netName === 'install') proxy = await startProxy(dk, ctx, { inNet: network, name, lbl });
    canary = await listenCanary(NET.gateway, CANARY_PORT);
    extra.canary_bound = canary.bound;
    if (name === 'symlink-escape') hostCanary = plantHostCanary(out, nonce);
    // install-archive-bomb: the runner's own disk (Docker's root folder, and --out), watched while it runs.
    if (name === 'install-archive-bomb') disk = watchFree([ctx.dockerRoot ?? out, out]);

    const cname = dk.name(name, 'case');
    // An install case runs as an npm install with scripts runs: in the node24-build image, at .4 of
    // the install network, with the proxy in its environment.
    let argv = sandboxRunArgs({
      name: cname, image: netName === 'install' ? images['node24-build'] : images.python, network, ip: NET.target, resolv: netName, detach: true, labels: lbl, workdir: P.work,
      mounts: [{ src: work, dst: P.work }, { src: ctx.toolsVol, dst: P.tools, ro: true }], env: netName === 'install' ? INSTALL_CASE_ENV : CASE_ENV,
      cmd: ['python3', `${P.tools}/selftest/hostile.py`, name, nonce, NET.gateway, String(CANARY_PORT)],
      hostEnv: process.env,
    });
    if (ctx.disable) argv = mutateCaseArgs(argv, ctx.disable, canaries);
    const manifest = settingsManifest(argv, { role: 'case' });
    tel.write('settings', { digest: settingsDigest(manifest), manifest }, meta);
    const t0 = Date.now();
    watch = watchTraces(cfg, { sinceMs: t0, onOverflow: () => dk.kill(cname) });
    // The docker client's environment is built from process.env the way every run builds it, and is
    // then given the canaries outright too, as a runner's own docker client would hold its tokens.
    const started = await dk.d(argv, { env: { ...dockerEnvFrom(process.env), ...canaries }, keepStdout: true, logStdout: false, cap: 4096, deadline: Date.now() + 120_000 });
    const id = started.stdout.toString().trim();
    if (started.exit !== 0 || !/^[0-9a-f]{64}$/.test(id)) throw new HarnessError(`the case container did not start (exit ${started.exit})`);
    // A server-like case's stage ends after STAGE_MS: it is torn down then (unless the no-teardown
    // mutation leaves it running), as the corpus tears a server down when its probe is done.
    const linger = STAGE_MS[name] ?? null;
    const teardown = () => (linger !== null && ctx.disable === 'no-teardown' ? null : dk.d(['kill', id], { deadline: Date.now() + 30_000 }));
    const w = await dk.d(['wait', id], { keepStdout: true, logStdout: false, cap: 64, deadline: Date.now() + (linger ?? CASE_MS), onTimeout: teardown });
    const ins = await inspectOne(dk, id);
    const exit = ins && ins.State && Number.isInteger(ins.State.ExitCode) ? ins.State.ExitCode : null;
    const runtime = String((ins && ins.HostConfig && ins.HostConfig.Runtime) || 'unknown').slice(0, 20);
    ev.container = { exit, timed_out: !!w.timed_out, oom_killed: ins && ins.State ? !!ins.State.OOMKilled : null };
    tel.write('container', { runtime, exit, signal: null, timed_out: !!w.timed_out, oom_killed: ev.container.oom_killed, ms: Date.now() - t0 }, meta);
    const values = Object.values(canaries);
    ev.inspect = {
      runtime,
      mismatches: ins ? inspectMismatches(ins, manifest, { canaries: values }) : ['the container could not be inspected'],
      canaryInEnv: !ins || ((ins.Config && ins.Config.Env) || []).some((e) => values.some((c) => String(e).includes(c))),
    };

    // What the target printed: kept apart as untrusted, recorded by size and hash only.
    const errFile = join(out, 'untrusted', `${name}.stderr`);
    const logs = await dk.d(['logs', id], { keepStdout: true, logStdout: false, cap: OUT_CAP, log: errFile, logCap: OUT_CAP, deadline: Date.now() + 60_000 });
    writeFileSync(join(out, 'untrusted', `${name}.stdout`), logs.stdout);
    tel.write('target_output', { stream: 'stdout', bytes: logs.stdout_bytes, sha256: sha256(logs.stdout), untrusted: true, truncated: logs.stdout_truncated }, meta);
    let errBuf = Buffer.alloc(0);
    try { errBuf = readFileSync(errFile); } catch { writeFileSync(errFile, ''); }
    tel.write('target_output', { stream: 'stderr', bytes: errBuf.length, sha256: sha256(errBuf), untrusted: true }, meta);
    ev.output = { bytes: logs.stdout_bytes };
    ev.outputRecorded = true;
    const rep = lastJson(logs.stdout.toString('utf8'));
    ev.report = rep && rep.case === name && rep.nonce === nonce ? rep : null;

    // The later stage, if the case has one: what a stage after it would meet of what it left behind.
    if (STAGES[name]) {
      ev.stage = await STAGES[name](ctx, { work, lbl, name, network, nonce });
      if (hostCanary) { ev.stage.host = checkHostCanary(hostCanary, out, nonce); hostCanary = null; }
      if (disk) { const drop = disk.stop(); disk = null; if (ev.stage.disk) ev.stage.disk.host_free_drop_mb = drop; }
    }

    const lines = await stopNetlog(dk, netlog);
    ev.netlogLines = lines.filter((o) => o.kind === 'stopped');
    netlog = null;
    writeNetlog(tel, lines, { subject, roles });
    const mine = lines.filter((o) => o.from === NET.target).map(fromNetlog).filter(Boolean);
    // What the case asked the proxy for, as `egress` records: the proxy's own log, our code.
    if (proxy) {
      const pl = await dk.d(['logs', proxy], { keepStdout: true, logStdout: false, cap: 4 * 1024 * 1024, deadline: Date.now() + 60_000 });
      for (const l of String(pl.stdout).split('\n').filter(Boolean).slice(0, 5000)) {
        let o = null;
        try { o = JSON.parse(l); } catch { continue; }
        const x = fromProxy(o);
        if (x && tel.tryWrite(x[0], x[1], { source: 'proxy', subject, role: 'proxy' })) ev.egress.push(x[1]);
      }
      await dk.kill(proxy);
      proxy = null;
    }
    ev.dns = mine.filter(([t]) => t === 'dns_query').map(([, f]) => f);
    ev.conns = mine.filter(([t]) => t === 'connection').map(([, f]) => f);

    watch.stop();
    if (watch.overflow()) tel.write('skip', { reason: 'trace_overflow', detail: `the case's syscall trace passed ${cfg.trace_max_mb} MB, or the trace filesystem ran short; the container was stopped` }, meta);
    ev.trace = await takeTrace(cfg, id);
    if (ev.trace) tel.tryWrite('trace_summary', { summary: ev.trace }, { source: 'runsc', ...meta });
    else tel.write('skip', { reason: 'trace_unavailable', detail: 'runsc wrote no syscall trace for the case container' }, meta);

    ev.canaryHits = canary.hits();
    await sleep(1500); // the kernel log trails the packets a little
    const hl = ctx.readLog(since - 1);
    if (hl.ok) {
      ev.drops = hostDropsFor(hl.text, { since, until: Date.now() / 1000 });
      writeDrops(tel, ev.drops, { subject, roles });
    } else tel.write('skip', { reason: 'host_log_unavailable', detail: 'the kernel log could not be read for this case' }, meta);

    // Forged results must not have reached the telemetry: not the nonce, not another run's records.
    const back = readTelemetry(tel.file);
    ev.telemetryHasNonce = readFileSync(tel.file, 'utf8').includes(nonce) || back.bad.length > 0 || back.records.some((r) => r.run !== tel.run);

    // The evidence that is not in other records, so scripts/check-selftest.mjs can recompute the verdict.
    const limits = limitsHit({ fw0, fw1: firewallCounts(), netlogLines: ev.netlogLines || [], trace: ev.trace }).map((x) => x.slice(0, 200)).slice(0, 20);
    tel.write('case_evidence', { case: name, limits_hit: limits, canary_hits: ev.canaryHits, inspect: { runtime: ev.inspect.runtime, mismatches: ev.inspect.mismatches.map((m) => String(m).slice(0, 200)).slice(0, 20), canary_in_env: ev.inspect.canaryInEnv }, telemetry_has_nonce: ev.telemetryHasNonce, pids_limit: ev.pidsLimit, ...(ev.stage ? { stage: ev.stage } : {}) }, meta);
    const v = evaluateCase(name, ev);
    tel.write('bypass_result', { case: name, ...v }, meta);
    return { case: name, ...v, ...extra };
  } catch (e) {
    const v = { blocked: false, logged: false, pass: false, evidence: [], detail: `harness: ${String(e && e.message).slice(0, 580)}` };
    tel.write('bypass_result', { case: name, ...v }, meta);
    return { case: name, ...v, ...extra };
  } finally {
    if (watch) watch.stop();
    if (disk) disk.stop();
    if (hostCanary) { try { rmSync(hostCanary.dir, { recursive: true, force: true }); } catch { /* ours */ } }
    for (const [k, val] of Object.entries(savedEnv)) { if (val === undefined) delete process.env[k]; else process.env[k] = val; }
    if (canary) canary.close();
    if (netlog) await dk.kill(netlog);
    if (proxy) await dk.kill(proxy);
    await dk.sweep(name);
    // mutation volume-cap: the bind volume's folder holds what the case wrote, as 65534; root removes it.
    for (const dir of ctx.cleanup.splice(0)) spawnSync('sudo', ['-n', 'rm', '-rf', '--one-file-system', dir], { timeout: 120_000 });
  }
}

/** mutation internal-net: the run network with its fixed subnet, but not --internal. Test-only. */
async function externalRunNetwork(dk, name, target) {
  const sn = NETS.run;
  await dk.must(dk.d(['network', 'create', '--driver', 'bridge', '--subnet', sn.subnet, '--gateway', sn.gateway, '--ipv6=false', '--opt', 'com.docker.network.bridge.enable_ip_masquerade=false', '--label', `${LABEL_RUN}=${dk.runId}`, '--label', `${LABEL_TARGET}=${target}`, name]), 'network create');
  return name;
}

/** Our code for the containers (the network logger, the hostile target), read-only, through stdin into a volume. */
async function toolsVolume(dk, images) {
  const vol = await dk.volume(`surface-${dk.runId}-tools`);
  const tar = spawnSync('tar', ['-C', root, '-cf', '-', '--owner=0', '--group=0', '--mode=a+rX,go-w', 'sandbox', 'src', 'selftest'], { maxBuffer: 64 * 1024 * 1024 });
  if (tar.status !== 0) throw new HarnessError('packing the self test tools failed');
  await dk.must(dk.d(helperRunArgs({ name: dk.name(null, 'h'), image: images.node22, user: '0:0', labels: dk.labels(), stdin: true, mounts: [{ src: vol, dst: P.tools }], cmd: ['tar', '-x', '-f', '-', '--no-same-owner', '-C', P.tools] }), { input: tar.stdout, deadline: Date.now() + 120_000 }), 'tools volume');
  return vol;
}

export async function main(argv = process.argv.slice(2), { readLog = readHostLog } = {}) {
  const o = parseArgs(argv);
  const out = resolve(o.out);
  mkdirSync(join(out, 'untrusted'), { recursive: true });
  const runId = newRunId();
  const started = new Date();
  const cfg = loadRunscConfig();
  const tel = new Telemetry(join(out, 'telemetry.jsonl'), { run: runId });
  const dk = new Docker({ runId, log: join(out, 'docker.log') });
  const results = { format: RESULTS_FORMAT, run: runId, lane: o.lane, started_at: started.toISOString(), finished_at: null, gvisor_release: cfg.release, runtime: RUNTIME, skipped: null, cases: [], passed: 0, total: o.cases.length };
  tel.write('run_start', { kind: 'selftest', lane: o.lane, node: process.version, platform: `${platform()}/${arch()}`, runtime: RUNTIME, gvisor_release: cfg.release, ...(o.disable ? { disabled: o.disable } : {}) });
  let ok = false;
  try {
    const images = loadImages(o.images);
    const v = await dk.d(['version', '--format', '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'], { keepStdout: true, logStdout: false, deadline: Date.now() + 60_000 });
    if (v.exit !== 0) throw Object.assign(new HarnessError('the Docker daemon is not available'), { reason: 'runtime_unavailable' });
    checkDockerVersion(v.stdout.toString().trim().split(' ')[0]);
    await dk.image(images.python, 'python');
    await dk.image(images.node22, 'node22');
    const install = o.cases.some((c) => INSTALL_CASES.includes(c));
    if (install) { await dk.image(images['node24-build'], 'node24-build'); await dk.image(images.node24, 'node24'); }
    if (o.disable && !mutateHost(o.disable)) throw new HarnessError(`the mutation ${o.disable} could not be applied to the host`);
    const pf = await preflight(dk, { cfg, arch: arch(), image: images.python, cmd: ['python3', '-c', 'import os; print(os.getuid(), os.getgid())'], expect: '65534 65534', tel, labels: dk.labels(), readLog, needHostLog: true, strict: true });
    if (!pf.ok) {
      results.skipped = { reason: pf.reason, detail: pf.detail };
      say(`selftest: skipped (${pf.reason}): ${pf.detail}`);
    } else {
      const root = await dk.d(['info', '--format', '{{.DockerRootDir}}'], { keepStdout: true, logStdout: false, cap: 4096, deadline: Date.now() + 30_000 });
      const dockerRoot = String(root.stdout).trim();
      const ctx = { dk, tel, cfg, images, out, readLog, disable: o.disable, toolsVol: await toolsVolume(dk, images), dockerRoot: /^\/[A-Za-z0-9/_.-]+$/.test(dockerRoot) ? dockerRoot : null, cleanup: [] };
      if (install) {
        // The proxy's network with egress, and the registry's addresses resolved on the host, as for a shard.
        ctx.outNet = await dk.network(`surface-${runId}-out`, false);
        ctx.publicHosts = await resolveRegistries(PROXY_ALLOWED, (h) => lookup(h, { all: true, family: 4 }));
      }
      for (const name of o.cases) {
        const r = await runCase(name, ctx);
        results.cases.push(r);
        say(r.pass ? `selftest ${name}: pass` : `selftest ${name}: FAIL (blocked: ${r.blocked ? 'yes' : 'no'}, logged: ${r.logged ? 'yes' : 'no'}) ${r.detail}`.slice(0, 400));
      }
      results.passed = results.cases.filter((r) => r.pass).length;
      ok = results.passed === results.total;
      say(`selftest: ${results.passed} of ${results.total} cases passed`);
    }
  } catch (e) {
    const reason = e && e.reason ? e.reason : 'sandbox_setup_missing';
    const detail = `harness error: ${String(e && e.message).slice(0, 250)}`;
    results.skipped = { reason, detail };
    tel.write('skip', { reason, detail });
    say(`selftest: skipped (${reason}): ${detail}`);
  } finally {
    try { await dk.sweep(); } catch { /* the workflow's runner is thrown away anyway */ }
    sweepTraces(cfg, started.getTime());
  }
  results.finished_at = new Date().toISOString();
  tel.end(ok);
  writeFileSync(join(out, 'results.json'), `${JSON.stringify(results, null, 1)}\n`);
  return ok ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().then((rc) => process.exit(rc), (e) => { process.stderr.write(`${e instanceof HarnessError ? e.message : e && e.stack}\n`); say('selftest: harness error'); process.exit(1); });
}
