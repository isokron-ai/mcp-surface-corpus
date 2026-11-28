#!/usr/bin/env node
/**
 * Surface corpus driver: one shard of the target list. For each target it acquires the tool list
 * through every layer that works, runs the checker engine over each list, and writes everything
 * under --out (which the workflow encrypts before upload).
 *
 *   node bin/run-shard.mjs --targets T.json --out DIR [--shard N --shards M] [--only s001,s002]
 *                          [--consume-targets] [--images images.json] [--source-cache DIR] [--lane ci|local]
 *                          [--writable-work]
 *
 * --writable-work (or main's writableWork option): each package kind's server gets a writable layer of its own per
 * probe, an overlay over its work volume at /work and a /data tmpfs (src/docker.mjs writableLayer); the work volume
 * itself stays as the install left it. Off by default: the server runs on the read-only volume.
 *
 * Local only, never set on CI: SURFACE_SOURCE_CACHE (same as --source-cache: <sha>.tar.gz and
 * <sha>.facts.json for a machine that cannot reach GitHub), SURFACE_IMAGE_MIRROR (a registry mirror
 * holding the same digests), SURFACE_INSTALL_CA_FILE (a TLS-inspecting proxy's CA for the installs).
 *
 * Layers, each recorded with whether it worked:
 *   (a) registry  the official MCP Registry entry (how to run it, declared env; rarely a tool list)
 *   (b) live      install in a sandbox container, start the server with no network, and send
 *                 initialize, tools/list, prompts/list, resources/list, resources/templates/list
 *   (c) static    tool registrations read from the source archive of the pinned commit
 *   (d) readme    tool names read from the README
 *
 * Isolation. No target code runs on the host. The host does three things with target data: it
 * fetches bytes from fixed hosts (GitHub, the MCP Registry), pipes them into containers, and parses
 * JSON that containers print. Target code runs only in `sandboxRunArgs` containers: under gVisor
 * (runsc), user 65534, every capability dropped, no-new-privileges, read-only root, memory, pid and
 * CPU limits, named volumes only, an environment made from names the harness sets. The install
 * step is on the internal install network and reaches the package registry only through our
 * allowlist proxy; the server runs on the internal run network (stdio and http alike), shared with
 * our probe container only. On both networks every name resolves to our network logger, which logs
 * each query and connection, and the host firewall (scripts/net-guard.sh) logs and drops anything
 * that tries to leave. At a time limit the container is removed, which ends every process in it.
 * Nothing is called: no tool, no prompt, no resource read.
 *
 * Before any of that the shard checks the sandbox (src/sandbox-run.mjs preflight): the daemon's runsc
 * with the flags gvisor.json gives, net-guard.sh's resolv.conf files, a smoke container under runsc
 * as 65534 with its syscall trace. If anything is missing the shard records a `skip` with the reason
 * and reports a harness error; nothing falls back to runc. The run telemetry (docs/TELEMETRY.md:
 * settings, containers, syscall trace summaries, DNS queries, connections, egress, host drops) is
 * _shard/telemetry.jsonl, encrypted with the rest of --out.
 *
 * Public output (stdout): one "run finished, exit N" line per target, in an order shuffled per run,
 * with no target id or name. N: 0 the target ran to completion (whatever the layers found), 124 it
 * hit its time limit, 125 harness error. The process exits 0 when every N is 0.
 */
import { createHash, randomBytes } from 'node:crypto';
import { appendFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync, statfsSync } from 'node:fs';
import { arch, platform, release } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

import { DATA_TMPFS, Docker, HarnessError, WRITABLE_KINDS, checkDockerVersion, checkPinned, helperRunArgs, isPublicIp4, sandboxRunArgs, volumePlan, LIMITS, LABEL_RUN, LABEL_TARGET } from '../src/docker.mjs';
import { lookup } from 'node:dns/promises';
import { ID, P, idNumber, launchPlan, shardTargets, timeoutOf, validateList } from '../src/targets.mjs';
import { githubFacts, registryEntry, sourceArchive } from '../src/sources.mjs';
import { dummyValue, isSecretName } from '../src/env-refs.mjs';
import { envNameAllowed, settingsDigest, settingsManifest } from '../src/sandbox-env.mjs';
import { loadRunscConfig, RUNTIME } from '../src/runsc.mjs';
import { NETS, readHostLog } from '../src/sandbox-net.mjs';
import { Telemetry, fromProxy } from '../src/telemetry.mjs';
import { jsonLines, diskProblem, workReadCmd, PROXY_LOG_CAP, firewallCounts, limitsHit, watchTraces, hostDropsFor, inspectOne, preflight, rolesOn, startNetlogOn, stopNetlog, sweepTraces, takeTrace, writeDrops, writeNetlog } from '../src/sandbox-run.mjs';
import { sdkFromFile } from '../src/sdk.mjs';
import { buildRow, buildState, RECORD_FORMAT } from '../src/record.mjs';
import { probeStdio, listed, PROTOCOL_OFFERED } from '../sandbox/probe.mjs';

export const RUN_FORMAT = 'isokron-surface-run/1';
export const LABEL = 'surface corpus: calibration data, not a finding';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const say = (line) => process.stdout.write(`${line}\n`);

const PROBE_MS = Number(process.env.SURFACE_PROBE_MS || 60_000);
const STEP_MS = 120_000;
const OUT_CAP = 96 * 1024 * 1024;
const LOCK_CAP = 16 * 1024 * 1024;
const MAX_ENV = 40;
export const PROXY_PORT = 8080;

export function parseArgs(argv) {
  const o = { lane: 'local', shard: 1, shards: 1, only: null, consume: false, writableWork: false, images: join(root, 'images.json'), sourceCache: process.env.SURFACE_SOURCE_CACHE || null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; const v = () => { if (i + 1 >= argv.length) throw new HarnessError(`${a} needs a value`); return argv[++i]; };
    if (a === '--targets') o.targets = v();
    else if (a === '--out') o.out = v();
    else if (a === '--shard') o.shard = Number(v());
    else if (a === '--shards') o.shards = Number(v());
    else if (a === '--only') o.only = v().split(',').filter(Boolean);
    else if (a === '--consume-targets') o.consume = true;
    else if (a === '--images') o.images = v();
    else if (a === '--source-cache') o.sourceCache = v();
    else if (a === '--lane') o.lane = v();
    else if (a === '--writable-work') o.writableWork = true;
    else throw new HarnessError(`unknown option ${a}`);
  }
  if (!o.targets || !o.out) throw new HarnessError('usage: run-shard.mjs --targets T.json --out DIR [--shard N --shards M] [--only IDS]');
  if (!(Number.isInteger(o.shards) && o.shards >= 1 && o.shards <= 64 && Number.isInteger(o.shard) && o.shard >= 1 && o.shard <= o.shards)) throw new HarnessError('--shard must be between 1 and --shards (at most 64)');
  if (!['ci', 'local'].includes(o.lane)) throw new HarnessError('--lane must be ci or local');
  if (o.only && !o.only.every((x) => ID.test(x))) throw new HarnessError('--only takes target ids such as s001,s002');
  return o;
}

/** Images from images.json, every one pinned by digest. SURFACE_IMAGE_MIRROR (never set on CI) swaps docker.io for a mirror of the same digests. */
/** The images.json keys the driver uses (each pinned by digest). */
export const IMAGE_KEYS = ['node24', 'node24-build', 'node22', 'node22-build', 'python', 'go', 'rust-build', 'dotnet-sdk'];

export function loadImages(file, mirror = process.env.SURFACE_IMAGE_MIRROR || '') {
  const j = JSON.parse(readFileSync(file, 'utf8'));
  const out = {};
  for (const k of IMAGE_KEYS) {
    let ref = checkPinned(j[k], k);
    if (mirror) { if (!/^[a-z0-9.-]+(?::[0-9]+)?$/.test(mirror)) throw new HarnessError('SURFACE_IMAGE_MIRROR is not a host name'); ref = ref.replace(/^docker\.io\//, `${mirror}/`); }
    out[k] = ref;
  }
  return out;
}

export function shuffled(list, seedHex) {
  const a = [...list];
  let s = BigInt(`0x${seedHex.slice(0, 16)}`) || 1n;
  const next = () => { s ^= s << 13n; s &= 0xffffffffffffffffn; s ^= s >> 7n; s ^= s << 17n; s &= 0xffffffffffffffffn; return Number(s % 1000003n); };
  for (let i = a.length - 1; i > 0; i--) { const j = next() % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}

/**
 * The env names a probe sets: the list's own, the registry's required ones, and the README's secret-named ones
 * (keys, tokens, passwords). A README also names switches and paths (LOG_LEVEL, *_PATH, *_URL, *_ENABLED); a dummy
 * value for those changes how the server starts without standing in for a credential, so they are recorded but not set.
 * Values are dummies.
 */
export function envPlan(launch, registry, stat) {
  const fromList = Object.keys((launch && launch.env) || {});
  const fromRegistry = ((registry && registry.env) || []).filter((e) => e.required).map((e) => e.name);
  const fromReadme = (stat && stat.env_refs && stat.env_refs.readme) || [];
  const fromSource = (stat && stat.env_refs && stat.env_refs.source) || [];
  // envNameAllowed: the names sandboxRunArgs refuses (runner, Actions, token, loader names) are never offered.
  const ok = (n) => envNameAllowed(n) && !/^(PATH|HOME|TMPDIR|LD_.*|NODE_OPTIONS|NODE_EXTRA_CA_CERTS|PYTHON.*|HTTPS?_PROXY|ALL_PROXY|NO_PROXY|SSL_CERT_.*|DOCKER_.*|GITHUB_.*|ACTIONS_.*|RUNNER_.*|SURFACE_.*|CORPUS_.*)$/i.test(n);
  const used = [...new Set([...fromList, ...fromRegistry, ...fromReadme.filter(isSecretName)])].filter(ok).slice(0, MAX_ENV);
  const env = {};
  for (const n of used) { const v = launch && launch.env ? launch.env[n] : undefined; env[n] = typeof v === 'string' ? v : dummyValue(n); }
  return { env, names: { list: fromList, registry: fromRegistry, readme: fromReadme, source: fromSource, used } };
}

function writeJson(file, data) { writeFileSync(file, `${JSON.stringify(data)}\n`); }
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const safeParse = (buf) => { try { const j = JSON.parse(buf.toString('utf8')); return j && typeof j === 'object' ? j : null; } catch { return null; } };

async function prepare(ctx, dk) {
  const v = await dk.d(['version', '--format', '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'], { keepStdout: true });
  if (v.exit !== 0) throw Object.assign(new HarnessError('docker is not available'), { reason: 'runtime_unavailable' });
  const [ver, osArch] = v.stdout.toString().trim().split(' ');
  checkDockerVersion(ver);
  if (!String(osArch).startsWith('linux/')) throw new HarnessError('containers must be Linux');
  ctx.runner.docker = ver; ctx.runner.container_platform = osArch;
  const ncpu = Number((await dk.d(['info', '--format', '{{.NCPU}}'], { keepStdout: true, logStdout: false })).stdout.toString().trim());
  ctx.cpus = Number.isInteger(ncpu) && ncpu >= 1 ? Math.min(LIMITS.cpus, ncpu) : 1;
  ctx.imageIds = { node24: await dk.image(ctx.images.node24, 'node24') };
}

/**
 * The `reader` option of main (a caller's source reader for the static step): { dir, id, entry }, a folder holding the
 * entry file, a 64-hex id and a plain .cjs file name, or null. Anything else is a harness error.
 */
export function readerOption(r) {
  if (r == null) return null;
  const ok = r && typeof r.dir === 'string' && typeof r.id === 'string' && /^[0-9a-f]{64}$/.test(r.id) && typeof r.entry === 'string' && /^[A-Za-z0-9_.-]{1,64}\.cjs$/.test(r.entry) && existsSync(join(r.dir, r.entry));
  if (!ok) throw new HarnessError('the reader option needs { dir, id, entry } with the entry file in dir');
  return { dir: resolve(r.dir), id: r.id, entry: r.entry };
}

/**
 * The `writableWork` option of main (or --writable-work): true gives each package kind's server a writable layer of its
 * own per probe (src/docker.mjs writableLayer), false (the default) the read-only work volume. Nothing else is accepted.
 */
export function writableWorkOption(w) {
  if (w === true || w === false) return w;
  throw new HarnessError('the writableWork option is true or false');
}

/** After the sandbox check: our tools volume, the install CA (local only) and the proxies' egress network. */
async function prepareTools(ctx, dk) {
  // Our in-container code (sandbox/, src/, engine/), read-only in every container. Copied through
  // stdin into a named volume: no host path is ever mounted.
  ctx.toolsVol = await dk.volume(`surface-${ctx.runId}-tools`);
  const tar = spawnSync('tar', ['-C', root, '-cf', '-', '--owner=0', '--group=0', '--mode=a+rX,go-w', 'sandbox', 'src', 'engine'], { maxBuffer: 64 * 1024 * 1024 });
  if (tar.status !== 0) throw new HarnessError('packing the sandbox tools failed');
  ctx.toolsSha = sha256(tar.stdout);
  await dk.must(dk.d(helperRunArgs({ name: dk.name(null, 'h'), image: ctx.images.node24, user: '0:0', labels: dk.labels(), stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools }], cmd: ['tar', '-x', '-f', '-', '--no-same-owner', '-C', P.tools] }), { input: tar.stdout }), 'tools volume');
  // The caller's source reader (mcp-check's own, from its live-probe driver), as reader/ beside our code, read-only
  // like it: the static step reads the archive with it too (static.mjs --reader). Only files of the given folder.
  ctx.readerSha = null;
  if (ctx.reader) {
    const rt = spawnSync('tar', ['-C', ctx.reader.dir, '-cf', '-', '--owner=0', '--group=0', '--mode=a+rX,go-w', '.'], { maxBuffer: 64 * 1024 * 1024 });
    if (rt.status !== 0) throw new HarnessError('packing the source reader failed');
    ctx.readerSha = sha256(rt.stdout);
    await dk.must(dk.d(helperRunArgs({ name: dk.name(null, 'h'), image: ctx.images.node24, user: '0:0', labels: dk.labels(), stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools }], cmd: ['sh', '-c', `mkdir -p ${P.tools}/reader && tar -x -f - --no-same-owner -C ${P.tools}/reader`] }), { input: rt.stdout }), 'reader in the tools volume');
  }
  ctx.caEnv = {};
  ctx.installCa = null;
  if (process.env.SURFACE_INSTALL_CA_FILE) {
    // A machine behind a TLS-inspecting proxy (never CI): the CA is added to the tools volume, read-only everywhere.
    const ca = readFileSync(process.env.SURFACE_INSTALL_CA_FILE);
    await dk.must(dk.d(helperRunArgs({ name: dk.name(null, 'h'), image: ctx.images.node24, user: '0:0', labels: dk.labels(), stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools }], cmd: ['sh', '-c', 'cat > /opt/surface/ca.pem && chmod 0444 /opt/surface/ca.pem'] }), { input: ca }), 'install CA');
    ctx.installCa = sha256(ca);
    const f = `${P.tools}/ca.pem`;
    ctx.caEnv = { NODE_EXTRA_CA_CERTS: f, SSL_CERT_FILE: f, PIP_CERT: f, REQUESTS_CA_BUNDLE: f, npm_config_cafile: f };
  }
  // One network with egress for the allowlist proxies of this shard; target containers never join it.
  ctx.outNet = await dk.network(`surface-${ctx.runId}-out`, false);
}

/** The settings of a container, read back from its exact `docker run` arguments, as a `settings` record. */
function writeSettings(ctx, argv, meta) {
  const manifest = settingsManifest(argv, { role: meta.role });
  ctx.tel.write('settings', { digest: settingsDigest(manifest), manifest }, meta);
}

/**
 * The registries' public IPv4 addresses, resolved on the host, as [name, ip] pairs for the egress
 * proxy's fixed host entries (at most 8 each). A name with no public address is a harness error.
 */
export async function resolveRegistries(names, resolveHost) {
  const out = [];
  for (const n of names) {
    let addrs = [];
    try { addrs = (await resolveHost(n)).map((a) => (typeof a === 'string' ? a : a.address)); } catch { /* reported below */ }
    const pub = [...new Set(addrs.filter(isPublicIp4))].slice(0, 8);
    if (!pub.length) throw new HarnessError(`the registry ${String(n).slice(0, 60)} has no public IPv4 address`);
    out.push(...pub.map((ip) => [n, ip]));
  }
  return out;
}

/** A container's id from its cidfile (docker writes it at create), or null. */
function readCid(file) {
  try { const s = readFileSync(file, 'utf8').trim(); return /^[0-9a-f]{64}$/.test(s) ? s : null; } catch { return null; }
}

/**
 * After a target container ended: its `container` record and the summary of the syscall trace runsc
 * wrote for it (then the raw trace is removed), or a `trace_unavailable` skip. `ins` is its docker
 * inspect when there is one (a detached container); a --rm one is gone, and the trace is the evidence
 * that it ran under runsc.
 */
async function recordContainer(ctx, { id, ins = null, t0, exit = null, signal = null, timedOut = false, meta }) {
  const summary = id ? await takeTrace(ctx.cfg, id, { waitMs: ctx.traceWaitMs }) : null;
  const st = (ins && ins.State) || null;
  const runtime = ins && ins.HostConfig && ins.HostConfig.Runtime ? String(ins.HostConfig.Runtime).slice(0, 20) : summary ? RUNTIME : 'unknown';
  const code = st ? (st.Running ? null : st.ExitCode) : exit;
  ctx.tel.write('container', { runtime, exit: Number.isInteger(code) ? code : null, signal: signal ? String(signal).slice(0, 20) : null, timed_out: !!timedOut, oom_killed: st ? !!st.OOMKilled : null, ms: Date.now() - t0 }, meta);
  if (summary) {
    // A summary the schema refused is evidence lost: the target counts as missing its trace.
    if (!ctx.tel.tryWrite('trace_summary', { summary }, { source: 'runsc', ...meta })) ctx.missing?.push(`a syscall trace record (${meta.role ?? 'container'})`);
  }
  else {
    ctx.tel.write('skip', { reason: 'trace_unavailable', detail: 'runsc wrote no syscall trace for this container' }, meta);
    if (ctx.missing) ctx.missing.push(`a syscall trace (${meta.role ?? 'container'})`);
  }
}

/**
 * The host firewall's drops for the sandbox range since t0 (milliseconds), as `host_drop` records.
 * false when the kernel log could not be read (or was known to be unreadable from the start).
 */
function recordDrops(ctx, t0, subject) {
  if (!ctx.hostLog) return false;
  const log = ctx.readLog(Math.floor(t0 / 1000) - 1);
  if (!log.ok) { ctx.tel.write('skip', { reason: 'host_log_unavailable', detail: 'the kernel log could not be read for this target' }, { subject }); return false; }
  writeDrops(ctx.tel, hostDropsFor(log.text, { since: t0 / 1000, until: Date.now() / 1000 }), { subject, roles: { ...rolesOn('install'), ...rolesOn('run') } });
  return true;
}

/**
 * The run network (one at a time: its subnet is fixed) with the network logger at .2, for the
 * duration of fn(network). What the logger saw becomes telemetry; then the network is removed.
 */
async function withRunNet(ctx, dk, { target, subject, at3 }, fn) {
  const network = await dk.network(dk.name(target, 'run'), true, target, { sandbox: 'run' });
  let netlog = null;
  try {
    netlog = await startNetlogOn(dk, { net: 'run', network, image: ctx.images.node24, toolsVol: ctx.toolsVol, labels: dk.labels(target), target });
    return await fn(network);
  } finally {
    if (netlog) {
      try { writeNetlog(ctx.tel, await stopNetlog(dk, netlog), { subject, roles: rolesOn('run', { target: at3 }) }); } finally { await dk.kill(netlog); }
    }
    await dk.d(['network', 'rm', network], { deadline: Date.now() + 60_000 });
  }
}

/**
 * A stdio server at .3 of the run network, probed over the stdin and stdout of its `docker run`.
 * Its settings, container and trace records go to telemetry.
 */
async function probeStdioIn(ctx, dk, { network, name, image, labels, mounts, env, cmd, entrypoint = null, workdir = undefined, tmpfs = [], timeoutMs, meta }) {
  const cidfile = join(ctx.cidDir, `${name}.cid`);
  const argv = sandboxRunArgs({ name, image, network, ip: NETS.run.target, resolv: 'run', cidfile, labels, stdin: true, cpus: ctx.cpus, mounts, env, cmd, entrypoint, ...(workdir ? { workdir } : {}), tmpfs });
  writeSettings(ctx, argv, meta);
  const t0 = Date.now();
  const p = await ctx.probe(['docker', ...argv], { protocol: PROTOCOL_OFFERED, timeoutMs, env: dk.env });
  await dk.kill(name);
  const tr = p.transport || {};
  await recordContainer(ctx, { id: readCid(cidfile), t0, exit: tr.exit ?? null, signal: tr.signal ?? null, timedOut: /^time limit/.test(String(p.error ?? '')), meta });
  return p;
}

/** What `docker run` itself costs in this sandbox: our null server, probed the way targets are. */
async function baseline(ctx, dk) {
  const t0 = Date.now();
  try {
    return await withRunNet(ctx, dk, { target: null, subject: null, at3: 'baseline' }, async (network) => {
      const p = await probeStdioIn(ctx, dk, { network, name: dk.name(null, 'base'), image: ctx.images.node24, labels: dk.labels(), mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], env: runEnv({}), cmd: ['node', `${P.tools}/sandbox/null-server.mjs`], timeoutMs: PROBE_MS, meta: { role: 'baseline' } });
      return listed(p) ? p.timing.initialize_ms : null;
    });
  } finally { recordDrops(ctx, t0, null); }
}

const runEnv = (extra) => ({ HOME: P.home, TMPDIR: '/tmp', NO_COLOR: '1', DO_NOT_TRACK: '1', PYTHONDONTWRITEBYTECODE: '1', PYTHONUNBUFFERED: '1', npm_config_update_notifier: 'false', SURFACE_SANDBOX: '1', ...extra });
// The proxy by its fixed address: on the install network every name resolves to the network logger.
export const PROXY_URL = `http://${NETS.install.proxy}:${PROXY_PORT}`;
const installEnv = (ctx, extra) => ({
  HOME: `${P.work}/home`, TMPDIR: '/tmp', NO_COLOR: '1', DO_NOT_TRACK: '1', SURFACE_SANDBOX: '1', CI: '1',
  npm_config_cache: `${P.work}/home/.npm`, npm_config_update_notifier: 'false', npm_config_fund: 'false', npm_config_audit: 'false',
  PIP_CACHE_DIR: `${P.work}/home/.cache/pip`, PIP_DISABLE_PIP_VERSION_CHECK: '1', PIP_NO_INPUT: '1',
  HTTPS_PROXY: PROXY_URL, https_proxy: PROXY_URL, HTTP_PROXY: PROXY_URL, http_proxy: PROXY_URL, NO_PROXY: '', no_proxy: '',
  ...ctx.caEnv, ...extra,
});

async function runTarget(t, list, ctx, dk) {
  const id = t.id;
  const dir = join(ctx.out, id);
  mkdirSync(dir, { recursive: true });
  const log = join(dir, 'steps.log');
  const tdk = Object.create(dk); tdk.log = log;
  const t0 = Date.now();
  const deadline = t0 + timeoutOf(t, list) * 1000;
  const left = (cap = Infinity) => Math.min(deadline, Date.now() + cap);
  const rec = {
    format: RECORD_FORMAT, target: id, run: ctx.runId, started_at: new Date().toISOString(), finished_at: null,
    list_entry: t, time_limit_s: timeoutOf(t, list),
    source: null, registry: null, static: null, install: null, probes: {}, env: null, analysis: null,
    layers: { registry: false, live: false, static: false, readme: false }, errors: [], public_exit: 125, timed_out: false,
    files: [],
  };
  const timing = { static_ms: null, install_ms: null, probe_ms: null, analyse_ms: null, total_ms: null };
  let pulled = null; // a target's own image, pulled for it and removed after it
  let stat = null; let registry = null; let facts = null; let bare = null; let withEnv = null; let primary = null; let analysis = null; let lockHits = []; let resolved = null; let names = null;
  const keep = (name, data) => { writeJson(join(dir, name), data); rec.files.push(name); };
  const keepRaw = (name, buf) => { writeFileSync(join(dir, name), buf); rec.files.push(name); };
  const lbl = dk.labels(id);
  const helper = (o, opts = {}) => tdk.d(helperRunArgs({ name: dk.name(id, 'h'), image: ctx.images.node24, labels: lbl, cpus: ctx.cpus, ...o }), opts);
  const timedOut = () => Date.now() >= deadline;
  // Evidence the sandbox could not give for this target (a syscall trace, the firewall's log). On the
  // ci lane any of it missing makes the target a harness error whose row is left out.
  const missing = [];
  ctx.missing = missing;
  // A trace past trace_max_mb (or a trace filesystem running short) stops the target's containers.
  const fw0 = ctx.lane === 'ci' ? firewallCounts(ctx.hostRun) : null;
  const watch = watchTraces(ctx.cfg, { sinceMs: t0, statfs: ctx.statfs, onOverflow: () => dk.killAll(id) });

  try {
    // 1. Repository facts and the commit (host fetch, fixed hosts).
    facts = await githubFacts(t, { fetchFn: ctx.fetchFn, token: ctx.githubToken, cacheDir: ctx.sourceCache });
    rec.source = { github: facts };
    if (!facts.sha) throw new HarnessError('the commit could not be resolved');

    // 2. Layers (c) and (d): the source archive goes to the static reader's container on stdin.
    const s0 = Date.now();
    try {
      const a = await sourceArchive(t.repo, facts.sha, { fetchFn: ctx.fetchFn, cacheDir: ctx.sourceCache });
      rec.source.archive = { sha256: a.sha256, bytes: a.bytes, via: a.via };
      const r = await helper({ stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', '--max-old-space-size=1536', `${P.tools}/sandbox/static.mjs`, ...(t.subdir ? ['--subdir', t.subdir] : []), ...(ctx.reader ? ['--reader', `${P.tools}/reader/${ctx.reader.entry}`, '--repo', t.repo, '--sha', facts.sha] : [])] }, { input: a.buf, keepStdout: true, logStdout: false, cap: OUT_CAP, deadline: left(STEP_MS * 2), onTimeout: () => dk.sweep(id) });
      stat = r.exit === 0 && !r.stdout_truncated ? safeParse(r.stdout) : null;
      if (stat && stat.format && !stat.error) {
        keep('static.json', stat);
        rec.static = { ok: true, reader: stat.reader ? { reader_id: stat.reader.reader_id ?? null, error: stat.reader.error ?? null, best: stat.reader.scan && stat.reader.scan.candidates[stat.reader.scan.best_index] ? { kind: stat.reader.scan.candidates[stat.reader.scan.best_index].kind, fidelity: stat.reader.scan.candidates[stat.reader.scan.best_index].fidelity, tools: stat.reader.scan.candidates[stat.reader.scan.best_index].tools.length } : null } : null, best: stat.static.best, candidates: stat.static.candidates.map((c) => ({ kind: c.kind, fidelity: c.fidelity, tools: c.tools.length, path: c.path ?? null })), readme_tools: stat.readme ? stat.readme.tools.length : 0, languages: stat.languages, primary_language: stat.primary_language, sdk: stat.sdk, manifests: stat.manifests, license_files: stat.license_files, subdir_found: stat.archive.subdir_found, documented_commands: stat.documented_commands, env_refs: stat.env_refs };
        rec.layers.static = !!stat.static.best;
        rec.layers.readme = !!(stat.readme && stat.readme.tools.length);
      } else { rec.static = { ok: false, exit: r.exit, timed_out: r.timed_out, error: stat && stat.error ? stat.error : 'the static reader gave no result' }; stat = null; }
    } catch (e) { rec.static = { ok: false, error: String(e.message).slice(0, 200) }; rec.errors.push({ step: 'source', error: String(e.message).slice(0, 200) }); }
    timing.static_ms = Date.now() - s0;

    // 3. Layer (a): the MCP Registry entry (by the list's name, else the package's own mcpName).
    const regName = t.registry ?? (stat && stat.package_json && typeof stat.package_json.mcpName === 'string' && /^[A-Za-z0-9][A-Za-z0-9.-]{0,120}\/[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/.test(stat.package_json.mcpName) ? stat.package_json.mcpName : null);
    if (regName && !timedOut()) {
      registry = await registryEntry(regName, { fetchFn: ctx.fetchFn });
      keep('registry.json', registry);
      rec.registry = { name_from: t.registry ? 'list' : 'mcpName', ok: registry.ok, found: registry.found, version: registry.version, packages: registry.packages, remotes: registry.remotes, env: registry.env, tools: Array.isArray(registry.tools) ? registry.tools.length : 0, error: registry.error };
      rec.layers.registry = !!registry.found;
    }

    // 4. Layer (b): install with allowlisted egress, then run with no network and probe.
    const plan0 = envPlan(t.launch, registry, stat);
    names = plan0.names;
    rec.env = { names, secret_named: names.used.filter(isSecretName), values: 'dummy values only; never a credential' };
    if (t.launch && !timedOut()) {
      const i0 = Date.now();
      const plan = launchPlan(t.launch);
      const inst = { kind: t.launch.kind, steps: [], ok: false, egress: [], image: null, resolved_version: null };
      rec.install = inst;
      let work = null; let entry = null; let image = null; const instIds = [];
      try {
        if (plan.targetImage) {
          image = checkPinned(plan.targetImage, 'target');
          inst.image = image;
          const p0 = Date.now();
          // linux/amd64 only: a digest that names a multi-platform index then gives the runner's own image, and an
          // arm64-only image fails here instead of exiting with "Exec format error" as if the server had crashed.
          pulled = image;
          const pull = await tdk.d(['pull', '-q', '--platform', 'linux/amd64', image], { deadline: left(600_000) });
          inst.steps.push({ name: 'pull', exit: pull.exit, timed_out: pull.timed_out, ms: Date.now() - p0 });
          if (pull.exit !== 0) throw new HarnessError('the target image could not be pulled');
          // The image's own WORKDIR and VOLUMEs: its server runs where its Dockerfile put it, with a size-capped tmpfs
          // where it declared a data folder (the root stays read-only).
          const ic = await dk.imageConfig(image);
          // Never a tmpfs over the folders that hold its code (its WORKDIR, its entrypoint's), nor over one the image
          // ships content in: a tmpfs would hide it. Only folders that are empty in the image get one.
          const vp = volumePlan(ic.volumes, [ic.workdir, ...ic.code_dirs]);
          const seen = vp.volumes.length ? await dk.volumeContent(image, vp.volumes, { name: dk.name(id, 'v'), labels: lbl }) : {};
          const volumes = vp.volumes.filter((v) => seen[v] === 'empty');
          const dropped = [...vp.dropped, ...vp.volumes.filter((v) => seen[v] !== 'empty').map((v) => ({ path: v, why: seen[v] === 'seeded' ? 'seeded' : 'unknown' }))];
          inst.oci = { workdir: ic.workdir, volumes, platform: ic.platform, ...(ic.ok ? {} : { inspect_failed: true }), ...(ic.workdir_refused ? { workdir_refused: ic.workdir_refused } : {}), ...(dropped.length ? { volumes_dropped: dropped.slice(0, 20) } : {}), ...(dropped.some((d) => d.why === 'seeded') ? { volume_seeded: true } : {}) };
          // linux/amd64 only (R-SBX-46): another platform the inspect names is our limit, recorded, and not run.
          if (ic.platform && ic.platform !== 'linux/amd64') {
            inst.oci.platform_unsupported = true;
            inst.steps.push({ name: 'platform', exit: 1, timed_out: false, ms: 0 });
          } else inst.ok = true;
        } else {
          image = ctx.images[plan.image];
          inst.image = image;
          ctx.imageIds[plan.image] ??= await dk.image(image, plan.image);
          work = await dk.volume(`surface-${ctx.runId}-${id}-work`, id);
          await dk.must(tdk.d(helperRunArgs({ name: dk.name(id, 'h'), image: ctx.images.node24, user: '0:0', labels: lbl, mounts: [{ src: work, dst: P.work }], capAdd: ['CHOWN'], cmd: ['sh', '-c', 'mkdir -p /work/home /work/lock && chown -R 65534:65534 /work'] })), 'work volume');
          // The install network has no route out: the network logger at .2 answers every name and logs
          // it, the proxy at .3 is the only door, the install container is .4.
          const inNet = await dk.network(`surface-${ctx.runId}-${id}-in`, true, id, { sandbox: 'install' });
          const netlog = await startNetlogOn(tdk, { net: 'install', network: inNet, image: ctx.images.node24, toolsVol: ctx.toolsVol, labels: lbl, target: id });
          let okAll = false;
          let proxyUp = false;
          const proxy = dk.name(id, 'proxy');
          try {
            // The proxy runs under gVisor like everything else. gVisor's own network stack does not
            // reach the daemon's DNS, so the host resolves the allowlisted registry names and the
            // proxy gets them as fixed host entries (public IPv4 only); it looks nothing else up. It
            // is created, given its install-network address, then started: gVisor takes its network
            // interfaces when the sandbox starts.
            const publicHosts = await ctx.resolveRegistries(plan.registries);
            const proxyArgs = helperRunArgs({ name: proxy, image: ctx.images.node24, network: ctx.outNet, create: true, labels: lbl, memory: '256m', publicHosts, mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', `${P.tools}/sandbox/egress-proxy.mjs`, String(PROXY_PORT), ...plan.registries] });
            writeSettings(ctx, proxyArgs, { subject: id, role: 'proxy' });
            await dk.must(tdk.d(proxyArgs), 'egress proxy');
            proxyUp = true;
            await dk.must(tdk.d(['network', 'connect', '--ip', NETS.install.proxy, inNet, proxy]), 'egress proxy network');
            await dk.must(tdk.d(['start', proxy]), 'egress proxy start');
            // Under gVisor the proxy takes a moment to start: the install waits until it listens.
            for (let until = Date.now() + 30_000; ;) {
              const pl0 = await tdk.d(['logs', proxy], { keepStdout: true, logStdout: false, cap: 64 * 1024, deadline: Date.now() + 10_000 });
              if (jsonLines(pl0.stdout).some((o) => Number.isInteger(o.listening))) break;
              if (Date.now() >= until) throw new HarnessError('the egress proxy did not start');
              await sleep(250);
            }
            okAll = true;
            for (const step of plan.install) {
              if (timedOut()) { okAll = false; break; }
              const s1 = Date.now();
              const name = dk.name(id, 'i');
              const cidfile = join(ctx.cidDir, `${name}.cid`);
              // A step may run in another of our images (a helper of ours in the node image after a build in the
              // Rust or .NET image): the same container, network, mounts and hardening as every install step.
              let stepImage = image;
              if (step.image) {
                stepImage = ctx.images[step.image];
                if (!stepImage) throw new HarnessError(`an install step names an image that is not ours (${String(step.image).slice(0, 40)})`);
                ctx.imageIds[step.image] ??= await dk.image(stepImage, step.image);
              }
              const argv = sandboxRunArgs({ name, image: stepImage, network: inNet, ip: NETS.install.target, resolv: 'install', cidfile, labels: lbl, cpus: ctx.cpus, workdir: P.work, mounts: [{ src: work, dst: P.work }, { src: ctx.toolsVol, dst: P.tools, ro: true }], env: installEnv(ctx, step.env || {}), cmd: step.cmd });
              writeSettings(ctx, argv, { subject: id, role: 'install' });
              // A step's own cap (a build may take BUILD_CAP_MS), never past the target's time limit.
              const r = await tdk.d(argv, { deadline: left(Number.isSafeInteger(step.capMs) && step.capMs > 0 ? step.capMs : Infinity), keepStdout: !!step.out, logStdout: !step.out, cap: 1024 * 1024, onTimeout: () => dk.kill(name) });
              instIds.push(readCid(cidfile));
              await recordContainer(ctx, { id: readCid(cidfile), t0: s1, exit: r.exit, signal: r.signal, timedOut: r.timed_out, meta: { subject: id, role: 'install' } });
              const s = { name: step.name, exit: r.exit, timed_out: r.timed_out, ms: Date.now() - s1, ...(step.image ? { image: step.image } : {}) };
              if (step.out) { const j = safeParse(r.stdout); if (step.name === 'entry') entry = j && typeof j.script === 'string' && j.script.startsWith(`${P.work}/pkg/`) && !/[\u0000\n]/.test(j.script) && !j.script.split('/').includes('..') && (j.runner === undefined || ['dotnet', 'executable'].includes(j.runner)) ? j : null; s.result = j; }
              inst.steps.push(s);
              if (r.exit !== 0 || (step.name === 'entry' && !entry)) { okAll = false; break; }
            }
          } finally {
            // What the install looked up and reached, then what it asked the proxy for: written whatever
            // happened above, the logger's lines first, and each record on its own, so a line the schema
            // refuses is counted and left out instead of taking the others with it.
            try { writeNetlog(ctx.tel, await stopNetlog(tdk, netlog), { subject: id, roles: rolesOn('install') }); } finally { await dk.kill(netlog); }
            if (proxyUp) {
              // Stopped first, so it prints how many lines its cap left out (`proxy_dropped`).
              await tdk.d(['stop', '-t', '3', proxy], { deadline: Date.now() + 30_000 });
              const pl = await tdk.d(['logs', proxy], { keepStdout: true, logStdout: false, cap: PROXY_LOG_CAP });
              if (pl.stdout_truncated) inst.proxy_log_truncated = true;
              const plines = pl.stdout.toString('utf8').split('\n').filter(Boolean).slice(0, 25_000).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
              const stopped = plines.find((o) => o && o.kind === 'stopped');
              if (stopped && Number.isInteger(stopped.dropped)) inst.proxy_dropped = stopped.dropped;
              inst.egress = plines.filter((o) => o && o.kind !== 'stopped').slice(0, 5000);
              inst.egress_refused = inst.egress.filter((e) => e && e.allowed === false && e.host).length;
              for (const e of inst.egress) { const x = fromProxy(e); if (x) ctx.tel.tryWrite(x[0], x[1], { source: 'proxy', subject: id, role: 'proxy' }); }
            }
            await dk.kill(proxy);
          }
          inst.ok = okAll;
          // Lock files, read out through a helper with no network (target-written: data only, size-capped;
          // a link anywhere in the path is refused, never followed: src/sandbox-run.mjs workReadCmd).
          // Resolving a path and then reading it is safe only while nothing can change the volume: it
          // is mounted read-only, and no install container may still be running.
          const still = await tdk.anyRunning(instIds);
          if (still.length) throw new HarnessError(`an install container is still running (${still.length}): the work volume is not read`);
          for (const lk of plan.locks) {
            const r = await helper({ mounts: [{ src: work, dst: P.work, ro: true }], cmd: workReadCmd(lk.path, 16 * 1024 * 1024) }, { keepStdout: true, logStdout: false, cap: LOCK_CAP, deadline: left(STEP_MS) });
            if (r.exit === 0 && r.stdout.length) {
              keepRaw(`lock-${lk.name}`, r.stdout);
              const hits = sdkFromFile(lk.name, r.stdout.toString('utf8')).map((h) => ({ ...h, kind: 'installed', depth: -1, path: lk.name }));
              lockHits.push(...hits);
              inst.lock = { name: lk.name, bytes: r.stdout.length, sha256: sha256(r.stdout), sdk_hits: hits };
            }
          }
          if (entry) { inst.resolved_version = entry.version; inst.engines_node = entry.engines; }
          if (t.launch.kind === 'pypi' && inst.lock) {
            const m = new RegExp(`^${t.launch.package.replace(/[-_.]+/g, '[-_.]+')}==([\\w.+!-]+)$`, 'mi').exec(readFileSync(join(dir, 'lock-freeze.txt'), 'utf8'));
            if (m) inst.resolved_version = m[1].slice(0, 64);
          }
          if (t.launch.kind === 'go' && inst.lock) {
            const m = /^\s*mod\s+\S+\s+(v[\w.+-]+)/m.exec(readFileSync(join(dir, 'lock-go-version-m.txt'), 'utf8'));
            if (m) inst.resolved_version = m[1].slice(0, 80);
          }
          resolved = inst.resolved_version;
        }
        timing.install_ms = Date.now() - i0;

        if (inst.ok && !timedOut()) {
          const p0 = Date.now();
          const runImage = plan.targetImage ? image : ctx.images[plan.runImage ?? plan.image];
          if (!plan.targetImage) ctx.imageIds[plan.runImage ?? plan.image] ??= await dk.image(runImage, 'run');
          const cmd = plan.run(entry);
          const roMounts = [...(work ? [{ src: work, dst: P.work, ro: true }] : [])];
          // With the writableWork option, a package kind's server gets a writable layer of its own per probe (src/docker.mjs
          // writableLayer): /work an overlay over its work volume, which stays as it is, and a /data tmpfs. A layer that
          // cannot be made is recorded and the probe runs on the read-only volume, as without the option.
          const layered = ctx.writableWork === true && !!work && !plan.targetImage && WRITABLE_KINDS.includes(t.launch.kind);
          if (layered) rec.writable_work = { layer: 'overlay', lower: 'work volume, unchanged', data: [...DATA_TMPFS], data_size: LIMITS.volTmp, probes: {} };
          // What the launch plan itself sets for the server (a .NET runtime's roll-forward, a bundle's PYTHONPATH inside
          // the read-only volume): on top of a target's env, never under it. Its working folder, when it names one.
          const serverEnv = (env) => runEnv({ ...env, ...(plan.runEnv || {}) });
          const workdir = plan.workdir && work ? plan.workdir : undefined;
          const meta = { subject: id, role: 'server' };
          // An OCI target runs in its image's WORKDIR (ours, /tmp, only when it sets none) with its VOLUMEs as tmpfs.
          // ...or, for a package kind, the working folder its plan names inside its volume (an MCP bundle's folder): one or the
          // other, never both (an OCI target has no work volume).
          const oci = plan.targetImage && inst.oci ? { ...(inst.oci.workdir ? { workdir: inst.oci.workdir } : {}), tmpfs: inst.oci.volumes } : workdir ? { workdir } : {};
          const probeOnce = async (net, env, tag) => {
            if (timedOut()) return null;
            let layer = null;
            if (layered) {
              try {
                layer = await tdk.writableLayer(work, { root: ctx.cfg.docker_root, image: ctx.images.node24, target: id, deadlineMs: Math.max(1000, Math.min(STEP_MS, deadline - Date.now())) });
                rec.writable_work.probes[tag] = { layer: true, error: null, removed: null };
              } catch (e) {
                if (!(e instanceof HarnessError)) throw e;
                // What was made of it carries the target's labels: the target's sweep removes it.
                rec.writable_work.probes[tag] = { layer: false, error: String(e.message).slice(0, 200), removed: null };
              }
            }
            const sname = dk.name(id, 's');
            try {
              return await probeIn(net, env, tag, layer, sname, layer ? { ...oci, tmpfs: [...DATA_TMPFS] } : oci);
            } finally {
              if (layer) {
                // The server's container first (probeStdioIn and the HTTP branch remove it already; this is for a probe
                // that threw), then the layer: nothing the server wrote outlives its probe.
                await tdk.kill(sname);
                const removed = await tdk.dropLayer(layer);
                rec.writable_work.probes[tag].removed = removed;
                if (!removed) rec.errors.push({ step: 'live', error: `the writable layer of probe ${tag} could not be removed` });
              }
            }
          };
          // oci: the start settings of this probe (with a layer, its /data tmpfs too).
          const probeIn = async (net, env, tag, layer, sname, oci) => {
            const mounts = layer ? [{ src: layer.volume, dst: P.work, nocopy: true }] : roMounts;
            const transport = t.launch.transport ?? 'stdio';
            let p;
            if (transport === 'stdio') {
              p = await probeStdioIn(ctx, tdk, { network: net, name: sname, image: runImage, labels: lbl, mounts, env: serverEnv(env), cmd, entrypoint: plan.entrypoint ?? null, ...oci, timeoutMs: Math.max(1000, Math.min(PROBE_MS, deadline - Date.now())), meta });
            } else {
              // Streamable HTTP: the server at .3 and our probe at .4 of the run network. `server` is a
              // fixed host entry in the probe's container: every other name resolves to the logger.
              const name = sname;
              const argv = sandboxRunArgs({ name, image: runImage, network: net, ip: NETS.run.target, resolv: 'run', detach: true, labels: lbl, cpus: ctx.cpus, mounts, env: serverEnv(env), cmd, entrypoint: plan.entrypoint ?? null, ...oci });
              writeSettings(ctx, argv, meta);
              const t1 = Date.now();
              const started = await tdk.d(argv, { deadline: left(STEP_MS), keepStdout: true, cap: 4096 });
              const sid = started.stdout.toString().trim();
              const ms = Math.max(1000, Math.min(PROBE_MS, deadline - Date.now()));
              const r = await helper({ network: net, ip: NETS.run.probe, resolv: 'run', hosts: [['server', NETS.run.target]], mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', `${P.tools}/sandbox/probe.mjs`, 'http', String(ms), PROTOCOL_OFFERED, `http://server:${t.launch.http.port}${t.launch.http.path}`] }, { keepStdout: true, logStdout: false, cap: OUT_CAP, deadline: Date.now() + ms + 15_000 });
              p = safeParse(r.stdout) || { format: 'isokron-surface-probe/1', mode: 'http', error: 'the HTTP probe gave no result', lists: {}, transcript: [], transport: {} };
              // `docker logs` writes the container's stderr to its own stderr: keep both, or a server that printed
              // its error and exited leaves nothing to read (stdout first, then stderr).
              // The last 2 MiB of each stream, cut by bytes: the lines a server prints as it stops are the ones that say why.
              const logs = await tdk.d(['logs', name], { keepStdout: true, keepStderr: true, tail: true, logStdout: false, cap: 2 * 1024 * 1024 });
              p.stderr = Buffer.concat([logs.stdout, logs.stderr || Buffer.alloc(0)]).toString('utf8'); p.stderr_bytes = logs.stdout_bytes + (logs.stderr_bytes || 0);
              if (logs.stdout_truncated || logs.stderr_truncated) p.stderr_truncated = true;
              const okId = /^[0-9a-f]{64}$/.test(sid) ? sid : null;
              const ins = okId ? await inspectOne(tdk, okId) : null;
              await dk.kill(name);
              await recordContainer(ctx, { id: okId, ins, t0: t1, exit: started.exit === 0 ? null : started.exit, meta });
            }
            p.env_names = Object.keys(env);
            keep(`probe-${tag}.json`, p);
            return p;
          };
          await withRunNet(ctx, tdk, { target: id, subject: id, at3: 'server' }, async (net) => {
            bare = await probeOnce(net, {}, 'bare');
            if (names.used.length) withEnv = await probeOnce(net, plan0.env, 'env');
          });
          primary = withEnv && listed(withEnv) ? withEnv : bare && listed(bare) ? bare : null;
          for (const [tag, p] of [['bare', bare], ['env', withEnv]]) {
            if (!p) continue;
            const tl = p.lists && p.lists['tools/list'];
            rec.probes[tag] = { ok: listed(p), era: p.era ?? null, error: p.error ?? null, initialize_error: p.initialize_error ?? null, tools_error: tl ? tl.error : null, exit: p.transport ? p.transport.exit ?? null : null, signal: p.transport ? p.transport.signal ?? null : null, timing: p.timing ?? null, transcript_bytes: p.transcript_bytes ?? null, stderr_bytes: p.stderr_bytes ?? null, env_names: p.env_names };
          }
          rec.layers.live = !!primary;
          if (primary) rec.server = { initialize: primary.initialize ?? null, era: primary.era };
          timing.probe_ms = Date.now() - p0;
        }
      } catch (e) {
        if (!(e instanceof HarnessError)) throw e;
        rec.errors.push({ step: 'live', error: String(e.message).slice(0, 200) });
      }
    }

    // 5. The checker engine over every list acquired, in a container with no network.
    const a0 = Date.now();
    const cands = stat ? stat.static.candidates.slice(0, 4).map((c) => ({ kind: c.kind, fidelity: c.fidelity, tools: c.tools })) : [];
    const input = {
      live_pages: primary && primary.lists['tools/list'].raw_pages ? primary.lists['tools/list'].raw_pages : null,
      static: cands, readme: stat && stat.readme && stat.readme.tools.length ? stat.readme.tools.map((x) => x.tool) : null,
      registry: registry && Array.isArray(registry.tools) ? registry.tools : null,
      probe: primary ? { lists: Object.fromEntries(Object.entries(primary.lists).map(([m, L]) => [m, { ok: L.ok, items: L.items, pages: L.pages, error_code: L.error_code, ms: L.ms }])), initialize: primary.initialize } : null,
    };
    if (input.live_pages || cands.length || input.readme || input.registry) {
      const r = await helper({ stdin: true, mounts: [{ src: ctx.toolsVol, dst: P.tools, ro: true }], cmd: ['node', '--max-old-space-size=1536', `${P.tools}/sandbox/analyse.mjs`] }, { input: Buffer.from(JSON.stringify(input)), keepStdout: true, logStdout: false, cap: OUT_CAP, deadline: Math.max(left(STEP_MS * 2), Date.now() + 30_000), onTimeout: () => dk.sweep(id) });
      analysis = r.exit === 0 && !r.stdout_truncated ? safeParse(r.stdout) : null;
      if (analysis && !analysis.error) { keep('analysis.json', analysis); rec.analysis = { ok: true, runs: Object.fromEntries(Object.entries(analysis.runs).map(([k, v]) => [k, { ok: v.ok, error: v.error ?? null, error_type: v.error_type ?? null, tool_count: v.tool_count ?? null, catalog_hash: v.catalog_hash ?? null, grades: v.grades ?? null }])) }; } else { rec.analysis = { ok: false, exit: r.exit, timed_out: r.timed_out }; rec.errors.push({ step: 'analyse', error: 'the analyser gave no result' }); analysis = null; }
    }
    timing.analyse_ms = Date.now() - a0;
    rec.timed_out = timedOut();
    rec.public_exit = rec.timed_out ? 124 : rec.errors.some((e) => e.step === 'analyse') ? 125 : 0;
  } catch (e) {
    rec.errors.push({ step: 'harness', error: String(e && e.message).slice(0, 300), harness: e instanceof HarnessError });
    rec.public_exit = timedOut() ? 124 : 125;
    rec.timed_out = timedOut();
  } finally {
    try { await dk.sweep(id); } catch { /* the shard's last sweep runs too */ }
    // A target's own image goes once the target is done: its layers would otherwise pile up on the
    // Docker data filesystem target after target (R-SBX-29). Ours (images.json) stay.
    if (pulled && !Object.values(ctx.images).includes(pulled)) { try { await dk.d(['image', 'rm', '-f', pulled], { deadline: Date.now() + 120_000 }); } catch { /* the runner is thrown away */ } }
    // What the host firewall dropped while this target ran, and the traces of our helpers (not summarised).
    watch.stop();
    const over = watch.overflow();
    if (over) {
      ctx.tel.write('skip', { reason: 'trace_overflow', detail: `a syscall trace reached ${Math.round(over.bytes / 1048576)} MB (limit ${ctx.cfg.trace_max_mb} MB) or the trace filesystem ran short; the target's containers were stopped` }, { subject: id });
      rec.errors.push({ step: 'trace', error: 'trace_overflow', harness: true });
      missing.push('a complete syscall trace (overflow)');
    }
    let drops = false;
    try { drops = recordDrops(ctx, t0, id); } catch (e) { appendFileSync(join(ctx.out, '_shard', 'driver-errors.log'), `${id}: host drops: ${String(e && e.message).slice(0, 300)}\n`); }
    if (!drops && ctx.hostLog !== false) missing.push('the host firewall log');
    sweepTraces(ctx.cfg, t0);
    ctx.missing = null;
    // Where a log or rate limit cut this target's evidence short (the record keeps it).
    if (ctx.lane === 'ci') rec.limits_hit = limitsHit({ fw0, fw1: firewallCounts(ctx.hostRun), proxyLines: rec.install && Number.isInteger(rec.install.proxy_dropped) ? [{ kind: 'stopped', dropped: rec.install.proxy_dropped }] : [], proxyTruncated: !!(rec.install && rec.install.proxy_log_truncated) });
  }
  // Fail closed on the ci lane: a target whose sandbox evidence is incomplete is a harness error, and
  // its row stays out of the results (the record keeps why).
  const excluded = ctx.lane === 'ci' && missing.length > 0;
  if (excluded) {
    rec.errors.push({ step: 'evidence', error: `missing ${[...new Set(missing)].join(', ')}`.slice(0, 300), harness: true });
    rec.public_exit = 125;
    rec.excluded = 'sandbox evidence missing';
  }
  timing.total_ms = Date.now() - t0;
  rec.timing = timing;
  rec.finished_at = new Date().toISOString();
  const row = buildRow({ id, publicExit: rec.public_exit, launch: t.launch ?? null, facts, registry, stat, bare, withEnv, primary, analysis, envNames: names, lockHits, timing, baselineMs: ctx.baselineMs });
  const state = buildState({ id, row, analysis, sha: facts ? facts.sha : null, resolved });
  rec.row = row;
  keep('record.json', rec);
  if (!excluded) {
    appendFileSync(join(ctx.out, '_shard', 'rows.jsonl'), `${JSON.stringify(row)}\n`);
    appendFileSync(join(ctx.out, '_shard', 'state.jsonl'), `${JSON.stringify(state)}\n`);
  }
  return rec.public_exit;
}

/**
 * Options are for the tests (a scripted daemon, no network): makeDocker, probe (the stdio probe),
 * runscConfig, readResolv, readLog, traceWaitMs. The defaults are what CI runs. reader and writableWork are a
 * caller's (mcp-check's live-probe driver): readerOption, writableWorkOption.
 */
export async function main(argv = process.argv.slice(2), { fetchFn = fetch, makeDocker = (o) => new Docker(o), probe = probeStdio, runscConfig = null, reader = null, writableWork = false, readResolv = undefined, readLog = readHostLog, traceWaitMs = 5000, statfs = statfsSync, hostRun = spawnSync, resolveHost = (h) => lookup(h, { all: true, family: 4 }) } = {}) {
  const o = parseArgs(argv);
  const list = validateList(JSON.parse(readFileSync(o.targets, 'utf8')));
  if (o.consume) rmSync(o.targets, { force: true });
  const runId = randomBytes(6).toString('hex');
  const out = resolve(o.out);
  mkdirSync(join(out, '_shard'), { recursive: true });
  const cfg = runscConfig ?? loadRunscConfig();
  const startedMs = Date.now();
  const tel = new Telemetry(join(out, '_shard', 'telemetry.jsonl'), { run: runId });
  const ctx = {
    runId, out, lane: o.lane, images: loadImages(o.images), sourceCache: o.sourceCache ? resolve(o.sourceCache) : null, fetchFn,
    githubToken: process.env.GH_TOKEN || null,
    runner: { os: platform(), arch: arch(), kernel: release(), node: process.version },
    baselineMs: null,
    reader: readerOption(reader),
    writableWork: writableWorkOption(writableWork) || o.writableWork,
    cfg, tel, probe, readLog, traceWaitMs, statfs, hostRun, hostLog: false, resolveRegistries: (names) => resolveRegistries(names, resolveHost), cidDir: join(out, '_shard', 'cid'),
  };
  const dk = makeDocker({ runId, log: join(out, '_shard', 'docker.log') });
  const targets = shardTargets(list.targets, o.shard, o.shards, o.only);
  const engine = JSON.parse(readFileSync(join(root, 'engine', 'VENDORED.json'), 'utf8'));
  const shard = { format: RUN_FORMAT, label: LABEL, run: runId, lane: o.lane, shard: o.shard, shards: o.shards, only: o.only, started_at: new Date().toISOString(), finished_at: null, targets: targets.map((t) => t.id), list_total: list.targets.length, engine: { commit: engine.commit, rubric_version: engine.rubric_version, checks: engine.checks, core_sha256: engine.files[0].sha256 }, images: ctx.images, limits: LIMITS, probe_ms: PROBE_MS, protocol_offered: PROTOCOL_OFFERED, runner: ctx.runner, results: {}, harness_error: null };
  shard.sandbox = { runtime: RUNTIME, gvisor_release: cfg.release, ok: false, reason: null, host_log: null, telemetry: 'telemetry.jsonl' };
  tel.write('run_start', { kind: 'corpus', lane: o.lane, node: process.version, platform: `${platform()}/${arch()}`, runtime: RUNTIME, gvisor_release: cfg.release });
  const exits = [];
  let checked = false;
  say(LABEL);
  try {
    // cidfiles: docker writes each target container's id there, which names its runsc trace.
    if (!/^\/[A-Za-z0-9._/-]{1,250}$/.test(ctx.cidDir)) throw new HarnessError('--out must be an absolute path of letters, digits, dots, dashes, underscores and slashes');
    mkdirSync(ctx.cidDir, { recursive: true });
    await prepare(ctx, dk);
    // Nothing runs unless gVisor is there: no runsc with our flags, no resolv.conf, no smoke container
    // under runsc as 65534, no trace: a skip record, a harness error, and no fallback.
    const pf = await preflight(dk, { cfg, arch: arch(), image: ctx.images.node24, cmd: ['node', '-e', 'console.log(process.getuid(), process.getgid())'], expect: '65534 65534', tel, labels: dk.labels(), readResolv, readLog, needHostLog: o.lane === 'ci', strict: o.lane === 'ci', statfs, run: hostRun, traceWaitMs });
    checked = true;
    Object.assign(shard.sandbox, { ok: pf.ok, reason: pf.reason, host_log: pf.hostLog });
    if (!pf.ok) throw new HarnessError(`the sandbox is not there (${pf.reason}): ${pf.detail}`);
    ctx.hostLog = pf.hostLog;
    await prepareTools(ctx, dk);
    ctx.baselineMs = await baseline(ctx, dk);
    Object.assign(shard, { writable_work: ctx.writableWork, reader: ctx.reader ? { id: ctx.reader.id, tar_sha256: ctx.readerSha } : null, tools_sha256: ctx.toolsSha, install_ca: ctx.installCa, baseline_initialize_ms: ctx.baselineMs, image_ids: ctx.imageIds, cpus: ctx.cpus });
    for (const t of shuffled(targets, runId)) {
      // Room for one more target, or the shard stops here: a full disk would lose every result.
      const low = o.lane === 'ci' ? diskProblem(cfg, out, { statfs }) : null;
      if (low) throw new HarnessError(`not enough disk before ${t.id}: ${low}`);
      let rc = 125;
      try { rc = await runTarget(t, list, ctx, dk); } catch (e) { appendFileSync(join(out, '_shard', 'driver-errors.log'), `${t.id}: ${String(e && e.stack).slice(0, 2000)}\n`); }
      shard.results[t.id] = rc;
      exits.push(rc);
      say(`run finished, exit ${rc}`);
    }
  } catch (e) {
    shard.harness_error = String(e && e.message).slice(0, 300);
    appendFileSync(join(out, '_shard', 'driver-errors.log'), `${String(e && e.stack).slice(0, 4000)}\n`);
    // Stopped before the sandbox check could say anything: that is a skip too.
    if (!checked) tel.write('skip', { reason: e && e.reason ? e.reason : 'sandbox_setup_missing', detail: `harness error before the sandbox check: ${String(e && e.message).slice(0, 240)}` });
    exits.push(125);
    say('run finished, exit 125');
  } finally {
    try { await dk.sweep(); } catch { /* the workflow's own sweep follows */ }
    sweepTraces(cfg, startedMs);
    rmSync(ctx.cidDir, { recursive: true, force: true });
  }
  shard.finished_at = new Date().toISOString();
  shard.image_ids = ctx.imageIds;
  writeJson(join(out, '_shard', 'shard.json'), shard);
  for (const f of ['rows.jsonl', 'state.jsonl']) if (!existsSync(join(out, '_shard', f))) writeFileSync(join(out, '_shard', f), '');
  const ok = exits.every((x) => x === 0);
  tel.end(ok && !shard.harness_error);
  return ok ? 0 : 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().then((rc) => process.exit(rc), (e) => { process.stderr.write(`${e instanceof HarnessError ? e.message : e && e.stack}\n`); say('run finished, exit 125'); process.exit(1); });
}

export { LABEL_RUN, LABEL_TARGET, idNumber };
