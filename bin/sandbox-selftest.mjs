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
 *
 * Writes DIR/telemetry.jsonl (docs/TELEMETRY.md), DIR/results.json and, kept apart and never parsed
 * as results, DIR/untrusted/<case>.stdout and .stderr (what the hostile target printed).
 * Prints one line per case, "selftest <case>: pass" or "selftest <case>: FAIL (...)", then a total.
 * Exits 0 only when every case passed. When the sandbox is not there (no runsc, other runsc flags,
 * net-guard.sh not run, no trace, no kernel log) it records a skip with the reason and exits 1:
 * nothing falls back to runc.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { arch, platform } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { setTimeout as sleep } from 'node:timers/promises';

import { Docker, HarnessError, checkDockerVersion, dockerEnvFrom, helperRunArgs, sandboxRunArgs, LIMITS } from '../src/docker.mjs';
import { loadRunscConfig, RUNTIME } from '../src/runsc.mjs';
import { NETS, readHostLog } from '../src/sandbox-net.mjs';
import { inspectMismatches, settingsDigest, settingsManifest } from '../src/sandbox-env.mjs';
import { Telemetry, fromNetlog, newRunId, readTelemetry } from '../src/telemetry.mjs';
import { CASES, CANARY_PORT, evaluateCase } from '../src/selftest.mjs';
import { firewallCounts, limitsHit, hostDropsFor, inspectOne, preflight, rolesOn, startNetlogOn, stopNetlog, sweepTraces, takeTrace, watchTraces, writeDrops, writeNetlog } from '../src/sandbox-run.mjs';
import { P } from '../src/targets.mjs';
import { loadImages } from './run-shard.mjs';

export const RESULTS_FORMAT = 'isokron-sandbox-selftest/1';
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..');
const say = (line) => process.stdout.write(`${line}\n`);
const CASE_MS = 120_000;
const OUT_CAP = 1024 * 1024;
const sha256 = (b) => createHash('sha256').update(b).digest('hex');

export function parseArgs(argv) {
  const o = { out: null, cases: [...CASES], images: join(root, 'images.json'), lane: 'local' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; const v = () => { if (i + 1 >= argv.length) throw new HarnessError(`${a} needs a value`); return argv[++i]; };
    if (a === '--out') o.out = v();
    else if (a === '--cases') o.cases = v().split(',').filter(Boolean);
    else if (a === '--images') o.images = v();
    else if (a === '--lane') o.lane = v();
    else throw new HarnessError(`unknown option ${a}`);
  }
  if (!o.out) throw new HarnessError('usage: sandbox-selftest.mjs --out DIR [--cases a,b] [--images images.json] [--lane ci|local]');
  if (!o.cases.length || !o.cases.every((c) => CASES.includes(c))) throw new HarnessError(`--cases takes some of: ${CASES.join(', ')}`);
  if (!['ci', 'local'].includes(o.lane)) throw new HarnessError('--lane must be ci or local');
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

/** The env the hostile target gets: what any target gets, nothing of the runner's. */
const CASE_ENV = { HOME: P.home, TMPDIR: '/tmp', NO_COLOR: '1', PYTHONDONTWRITEBYTECODE: '1', PYTHONUNBUFFERED: '1', SURFACE_SANDBOX: '1' };

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

async function runCase(name, ctx) {
  const { dk, tel, cfg, images, out } = ctx;
  const nonce = randomBytes(8).toString('hex');
  const canaries = canaryEnv(nonce);
  const subject = `case:${name}`;
  const meta = { subject, role: 'case' };
  const lbl = dk.labels(name);
  const roles = rolesOn('run', { target: 'case' });
  const since = Date.now() / 1000;
  const fw0 = firewallCounts();
  const ev = { trace: null, dns: [], conns: [], drops: [], canaryHits: null, inspect: null, container: null, telemetryHasNonce: null, output: null, outputRecorded: false, report: null, pidsLimit: Number(LIMITS.nproc) };
  let canary = null;
  let netlog = null;
  let watch = null;
  const extra = { canary_bound: null };
  // The canaries go where a runner keeps its tokens: in the driver's own environment, for the whole
  // case. Every path that could carry them on (the docker client's environment, the target's
  // environment check) reads process.env, so a leak anywhere shows up in docker inspect.
  const savedEnv = Object.fromEntries(Object.keys(canaries).map((k) => [k, process.env[k]]));
  Object.assign(process.env, canaries);
  try {
    const network = await dk.network(`surface-${dk.runId}-${name}-run`, true, name, { sandbox: 'run' });
    const work = await dk.volume(`surface-${dk.runId}-${name}-work`, name);
    // chmod before chown: once /work belongs to 65534, root without CAP_FOWNER may no longer change its mode.
    await dk.must(dk.d(helperRunArgs({ name: dk.name(name, 'h'), image: images.node22, user: '0:0', capAdd: ['CHOWN'], labels: lbl, mounts: [{ src: work, dst: P.work }], cmd: ['sh', '-c', 'chmod 0750 /work && chown 65534:65534 /work'] }), { deadline: Date.now() + 120_000 }), 'work volume');
    netlog = await startNetlogOn(dk, { net: 'run', network, image: images.node22, toolsVol: ctx.toolsVol, labels: lbl, target: name });
    canary = await listenCanary(NETS.run.gateway, CANARY_PORT);
    extra.canary_bound = canary.bound;

    const cname = dk.name(name, 'case');
    const argv = sandboxRunArgs({
      name: cname, image: images.python, network, ip: NETS.run.target, resolv: 'run', detach: true, labels: lbl, workdir: P.work,
      mounts: [{ src: work, dst: P.work }, { src: ctx.toolsVol, dst: P.tools, ro: true }], env: CASE_ENV,
      cmd: ['python3', `${P.tools}/selftest/hostile.py`, name, nonce, NETS.run.gateway, String(CANARY_PORT)],
      hostEnv: process.env,
    });
    const manifest = settingsManifest(argv, { role: 'case' });
    tel.write('settings', { digest: settingsDigest(manifest), manifest }, meta);
    const t0 = Date.now();
    watch = watchTraces(cfg, { sinceMs: t0, onOverflow: () => dk.kill(cname) });
    // The docker client's environment is built from process.env the way every run builds it, and is
    // then given the canaries outright too, as a runner's own docker client would hold its tokens.
    const started = await dk.d(argv, { env: { ...dockerEnvFrom(process.env), ...canaries }, keepStdout: true, logStdout: false, cap: 4096, deadline: Date.now() + 120_000 });
    const id = started.stdout.toString().trim();
    if (started.exit !== 0 || !/^[0-9a-f]{64}$/.test(id)) throw new HarnessError(`the case container did not start (exit ${started.exit})`);
    const w = await dk.d(['wait', id], { keepStdout: true, logStdout: false, cap: 64, deadline: Date.now() + CASE_MS, onTimeout: () => dk.d(['kill', id], { deadline: Date.now() + 30_000 }) });
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

    const lines = await stopNetlog(dk, netlog);
    ev.netlogLines = lines.filter((o) => o.kind === 'stopped');
    netlog = null;
    writeNetlog(tel, lines, { subject, roles });
    const mine = lines.filter((o) => o.from === NETS.run.target).map(fromNetlog).filter(Boolean);
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
    tel.write('case_evidence', { case: name, limits_hit: limits, canary_hits: ev.canaryHits, inspect: { runtime: ev.inspect.runtime, mismatches: ev.inspect.mismatches.map((m) => String(m).slice(0, 200)).slice(0, 20), canary_in_env: ev.inspect.canaryInEnv }, telemetry_has_nonce: ev.telemetryHasNonce, pids_limit: ev.pidsLimit }, meta);
    const v = evaluateCase(name, ev);
    tel.write('bypass_result', { case: name, ...v }, meta);
    return { case: name, ...v, ...extra };
  } catch (e) {
    const v = { blocked: false, logged: false, pass: false, evidence: [], detail: `harness: ${String(e && e.message).slice(0, 580)}` };
    tel.write('bypass_result', { case: name, ...v }, meta);
    return { case: name, ...v, ...extra };
  } finally {
    if (watch) watch.stop();
    for (const [k, val] of Object.entries(savedEnv)) { if (val === undefined) delete process.env[k]; else process.env[k] = val; }
    if (canary) canary.close();
    if (netlog) await dk.kill(netlog);
    await dk.sweep(name);
  }
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
  tel.write('run_start', { kind: 'selftest', lane: o.lane, node: process.version, platform: `${platform()}/${arch()}`, runtime: RUNTIME, gvisor_release: cfg.release });
  let ok = false;
  try {
    const images = loadImages(o.images);
    const v = await dk.d(['version', '--format', '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'], { keepStdout: true, logStdout: false, deadline: Date.now() + 60_000 });
    if (v.exit !== 0) throw Object.assign(new HarnessError('the Docker daemon is not available'), { reason: 'runtime_unavailable' });
    checkDockerVersion(v.stdout.toString().trim().split(' ')[0]);
    await dk.image(images.python, 'python');
    await dk.image(images.node22, 'node22');
    const pf = await preflight(dk, { cfg, arch: arch(), image: images.python, cmd: ['python3', '-c', 'import os; print(os.getuid(), os.getgid())'], expect: '65534 65534', tel, labels: dk.labels(), readLog, needHostLog: true, strict: true });
    if (!pf.ok) {
      results.skipped = { reason: pf.reason, detail: pf.detail };
      say(`selftest: skipped (${pf.reason}): ${pf.detail}`);
    } else {
      const ctx = { dk, tel, cfg, images, out, readLog, toolsVol: await toolsVolume(dk, images) };
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
