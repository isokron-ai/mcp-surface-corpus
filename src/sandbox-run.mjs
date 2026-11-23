// The host side of a sandbox run, shared by the corpus driver (bin/run-shard.mjs) and the sandbox
// self test (bin/sandbox-selftest.mjs):
//   - preflight(): nothing runs unless gVisor is really there. The daemon must have the runsc runtime
//     with exactly the flags gvisor.json gives, net-guard.sh's resolv.conf files must be in place, a
//     smoke container must run under runsc as 65534, and runsc must have written its syscall trace.
//     Any of these missing is a `skip` record with the reason, and the caller stops: there is no
//     fallback to runc.
//   - the network logger at .2 of a sandbox network, and its lines as telemetry;
//   - the syscall trace of one container, summarised and then removed;
//   - the host firewall's drops for the sandbox range in a time window.
import { existsSync, readFileSync, readdirSync, rmSync, statSync, statfsSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { HarnessError, helperRunArgs, sandboxRunArgs } from './docker.mjs';
import { RUNTIME, runscFlags, runtimeArgs, runtimeAvailable, traceLogPath } from './runsc.mjs';
import { NETS, SANDBOX_RANGE, firewallCounts, firewallProblems, groupDrops, parseKernelLog, readHostLog, resolvConf } from './sandbox-net.mjs';
import { spawnSync } from 'node:child_process';
import { settingsDigest, settingsManifest } from './sandbox-env.mjs';
import { summarizeTraceFile } from './trace-summary.mjs';
import { fromDrop, fromNetlog } from './telemetry.mjs';
import { P } from './targets.mjs';

/** The JSON objects among the lines of a buffer; other lines are ignored. */
export function jsonLines(buf) {
  const out = [];
  for (const l of String(buf).split('\n')) {
    if (!l.startsWith('{')) continue;
    try { const o = JSON.parse(l); if (o && typeof o === 'object' && !Array.isArray(o)) out.push(o); } catch { /* not ours */ }
  }
  return out;
}

/** Whether the daemon has runsc, and with which flags, against the ones gvisor.json gives. */
export async function runtimeStatus(dk, cfg, hostArch) {
  const json = await dk.runtimes();
  const available = runtimeAvailable(json);
  const flagsExpected = runscFlags(cfg, hostArch);
  const flagsDaemon = available ? runtimeArgs(json) : [];
  const same = JSON.stringify([...flagsDaemon].sort()) === JSON.stringify([...flagsExpected].sort());
  return { available, name: RUNTIME, release: cfg.release, flags_expected: flagsExpected, flags_daemon: flagsDaemon, flags_match: available && same };
}

/**
 * null when the daemon's runsc is the one install-runsc.sh put in place: the runtime's path is
 * <install_dir>/current/runsc and that binary says it is the pinned release. Else what is wrong.
 */
export function installProblem(cfg, runtimesJson, run = spawnSync) {
  let path = null;
  try { path = JSON.parse(String(runtimesJson))[RUNTIME].path; } catch { /* reported below */ }
  const want = `${cfg.install_dir}/current/runsc`;
  if (path !== want) return `the daemon's runsc is ${String(path).slice(0, 80)}, not ${want}`;
  const r = run(want, ['--version'], { encoding: 'utf8', timeout: 30_000 });
  const first = r.status === 0 ? String(r.stdout).split('\n')[0] : '';
  if (!new RegExp(`release-${cfg.release.replace('.', '\\.')}(?:\\b|$)`).test(first)) return `runsc --version does not say release-${cfg.release}`;
  return null;
}

/** null when the resolv.conf of a sandbox network is the one net-guard.sh writes, else what is wrong. */
export function resolvProblem(net, read = (f) => readFileSync(f, 'utf8')) {
  const f = NETS[net].resolv;
  let text;
  try { text = read(f); } catch { return `${f} is missing (scripts/net-guard.sh writes it)`; }
  return text === resolvConf(net) ? null : `${f} is not the one net-guard.sh writes`;
}

/** One container's `docker inspect` object, or null. */
export async function inspectOne(dk, id) {
  const r = await dk.d(['inspect', id], { keepStdout: true, logStdout: false, cap: 4 * 1024 * 1024, deadline: Date.now() + 30_000 });
  if (r.exit !== 0) return null;
  try { const j = JSON.parse(r.stdout.toString('utf8')); return Array.isArray(j) && j[0] && typeof j[0] === 'object' ? j[0] : null; } catch { return null; }
}

/**
 * The summary of the syscall trace runsc wrote for one container, after which the raw trace is
 * removed (it holds whatever the target did; the summary is what is kept). null when there is none.
 */
export async function takeTrace(cfg, id, { waitMs = 5000, remove = true } = {}) {
  let path;
  try { path = traceLogPath(cfg, id); } catch { return null; }
  const until = Date.now() + waitMs;
  while (!existsSync(path) && Date.now() < until) await sleep(100);
  if (!existsSync(path)) return null;
  // runsc may still be writing the last lines as the sandbox ends: wait until the size holds still.
  let size = -1;
  for (let i = 0; i < 20 && Date.now() < until; i++) {
    const s = statSync(path).size;
    if (s === size) break;
    size = s; await sleep(150);
  }
  const summary = await summarizeTraceFile(path, cfg);
  if (remove) { try { rmSync(path, { force: true }); } catch { /* the log folder is the runner's; best effort */ } }
  return summary;
}

/**
 * Removes the traces runsc wrote since a time (milliseconds) that nobody summarised: the helpers'
 * (our own code). Returns how many were removed.
 */
export function sweepTraces(cfg, sinceMs) {
  let n = 0;
  let names = [];
  try { names = readdirSync(cfg.log_dir); } catch { return 0; }
  for (const f of names) {
    if (!/^[0-9a-f]{64}\.[a-z-]{1,20}\.log$/.test(f)) continue;
    const p = join(cfg.log_dir, f);
    try { if (statSync(p).mtimeMs >= sinceMs - 1000) { rmSync(p, { force: true }); n++; } } catch { /* gone already */ }
  }
  return n;
}

const TRACE_FILE = /^[0-9a-f]{64}\.[a-z-]{1,20}\.log$/;

/**
 * Watches the traces runsc writes from `sinceMs` on (one target, or one self test case, at a time)
 * and calls onOverflow once, with the file and its size, when one passes trace_max_mb or the trace
 * filesystem has less than that left. The caller stops the containers and records `trace_overflow`.
 * Returns { stop(), overflow() }: overflow() is null or { file, bytes, free }.
 */
export function watchTraces(cfg, { sinceMs, onOverflow, intervalMs = 1000, statfs = statfsSync } = {}) {
  const max = cfg.trace_max_mb * 1024 * 1024;
  let hit = null;
  const check = () => {
    if (hit) return;
    let free = Infinity;
    try { const s = statfs(cfg.log_dir); free = Number(s.bavail) * Number(s.bsize); } catch { /* no filesystem to ask */ }
    let names = [];
    try { names = readdirSync(cfg.log_dir); } catch { return; }
    for (const f of names) {
      if (!TRACE_FILE.test(f)) continue;
      let st; try { st = statSync(join(cfg.log_dir, f)); } catch { continue; }
      if (st.mtimeMs < sinceMs - 1000) continue;
      if (st.size > max || free < max) { hit = { file: f, bytes: st.size, free: Number.isFinite(free) ? free : null }; break; }
    }
    if (hit) Promise.resolve().then(() => onOverflow(hit)).catch(() => {});
  };
  const timer = setInterval(check, intervalMs);
  timer.unref?.();
  return { stop: () => { clearInterval(timer); check(); }, overflow: () => hit, check };
}

/** null when the trace folder is its own filesystem of about trace_fs_mb (install-runsc.sh), else why not. */
export function traceFsProblem(cfg, { statfs = statfsSync } = {}) {
  let s;
  try { s = statfs(cfg.log_dir); } catch { return `${cfg.log_dir} cannot be read`; }
  const total = Number(s.blocks) * Number(s.bsize);
  if (!(total > 0) || total > cfg.trace_fs_mb * 1024 * 1024 * 1.05) return `${cfg.log_dir} is not a filesystem of its own of ${cfg.trace_fs_mb} MB (run scripts/install-runsc.sh)`;
  return null;
}

/** null when there is room to run one more target: the output folder and the trace filesystem, else why not. */
export function diskProblem(cfg, outDir, { minOutBytes = 2 * 1024 ** 3, statfs = statfsSync } = {}) {
  const free = (p) => { try { const s = statfs(p); return Number(s.bavail) * Number(s.bsize); } catch { return null; } };
  const out = free(outDir);
  if (out === null || out < minOutBytes) return `less than ${Math.round(minOutBytes / 1024 ** 3)} GB free for the results`;
  const tr = free(cfg.log_dir);
  if (tr === null || tr < cfg.trace_max_mb * 1024 * 1024) return 'the trace filesystem has less room than one trace may take';
  return null;
}

async function smoke(dk, { cfg, image, cmd, expect, tel, labels, deadlineMs, traceWaitMs }) {
  const name = dk.name(null, 'smoke');
  const argv = sandboxRunArgs({ name, image, network: 'none', labels, detach: true, env: { HOME: '/tmp', SURFACE_SANDBOX: '1' }, cmd });
  const meta = { role: 'smoke' };
  const manifest = settingsManifest(argv, { role: 'smoke' });
  tel.write('settings', { digest: settingsDigest(manifest), manifest }, meta);
  const t0 = Date.now();
  try {
    const r = await dk.d(argv, { keepStdout: true, logStdout: false, cap: 4096, deadline: Date.now() + deadlineMs });
    const id = r.stdout.toString().trim();
    if (r.exit !== 0 || !/^[0-9a-f]{64}$/.test(id)) return { ok: false, reason: 'runtime_unavailable', detail: `a container under runsc did not start (exit ${r.exit})` };
    const w = await dk.d(['wait', id], { keepStdout: true, logStdout: false, cap: 64, deadline: Date.now() + deadlineMs, onTimeout: () => dk.kill(name) });
    const ins = await inspectOne(dk, id);
    const out = await dk.d(['logs', id], { keepStdout: true, logStdout: false, cap: 4096 });
    const exit = ins && ins.State && Number.isInteger(ins.State.ExitCode) ? ins.State.ExitCode : null;
    const runtime = String((ins && ins.HostConfig && ins.HostConfig.Runtime) || 'unknown').slice(0, 20);
    tel.write('container', { runtime, exit, signal: null, timed_out: !!w.timed_out, oom_killed: ins && ins.State ? !!ins.State.OOMKilled : null, ms: Date.now() - t0 }, meta);
    if (runtime !== RUNTIME) return { ok: false, reason: 'runtime_unavailable', detail: `the smoke container did not run under runsc (runtime ${runtime})` };
    if (exit !== 0 || out.stdout.toString().trim() !== expect) return { ok: false, reason: 'runtime_unavailable', detail: `the smoke container under runsc did not run as ${expect} (exit ${exit})` };
    const trace = await takeTrace(cfg, id, { waitMs: traceWaitMs });
    if (!trace || !(trace.syscalls > 0)) return { ok: false, reason: 'trace_unavailable', detail: `runsc wrote no syscall trace for the smoke container (expected in ${cfg.log_dir})` };
    tel.tryWrite('trace_summary', { summary: trace }, { source: 'runsc', role: 'smoke' });
    return { ok: true };
  } finally {
    await dk.kill(name);
  }
}

/**
 * Checks the sandbox before anything runs in it, and records what it found (`runtime`, the smoke
 * container's `settings`, `container` and `trace_summary`). { ok, reason, detail, hostLog }: when ok
 * is false a `skip` record with the reason is written and the caller must not run anything. An
 * unreadable kernel log stops the run only when needHostLog is set (the self test and the corpus's
 * ci lane need the drops as evidence; the local lane records the skip and goes on).
 */
export async function preflight(dk, { cfg, arch, image, cmd, expect, tel, labels = {}, readResolv, readLog = readHostLog, needHostLog = true, strict = false, statfs = statfsSync, run = spawnSync, deadlineMs = 180_000, traceWaitMs = 5000 }) {
  const skip = (reason, detail) => tel.write('skip', { reason, detail: String(detail).slice(0, 300) });
  const fail = (reason, detail) => { skip(reason, detail); return { ok: false, reason, detail, hostLog: null }; };
  const rt = await runtimeStatus(dk, cfg, arch);
  const runtimeRecord = (s) => tel.write('runtime', { ...rt, smoke: s });
  if (!rt.available) { runtimeRecord('not_run'); return fail('runtime_unavailable', 'the Docker daemon has no runsc runtime (scripts/install-runsc.sh registers it)'); }
  if (!rt.flags_match) { runtimeRecord('not_run'); return fail('sandbox_setup_missing', 'runsc is registered with other flags than gvisor.json gives (run scripts/install-runsc.sh)'); }
  for (const net of Object.keys(NETS)) {
    const p = resolvProblem(net, readResolv);
    if (p) { runtimeRecord('not_run'); return fail('sandbox_setup_missing', p); }
  }
  // strict (the self test and the corpus's ci lane): the host as install-runsc.sh and net-guard.sh
  // left it, checked live: the pinned runsc in its place, the trace filesystem, the firewall rules.
  if (strict) {
    const p = installProblem(cfg, await dk.runtimes(), run) ?? traceFsProblem(cfg, { statfs });
    if (p) { runtimeRecord('not_run'); return fail('sandbox_setup_missing', p); }
    const fw = firewallProblems(run);
    tel.write('firewall', { live: fw.length === 0, problems: fw.map((x) => String(x).slice(0, 200)).slice(0, 20) });
    if (fw.length) { runtimeRecord('not_run'); return fail('sandbox_setup_missing', `the firewall is not the one net-guard.sh makes: ${fw.join('; ')}`); }
  }
  const sm = await smoke(dk, { cfg, image, cmd, expect, tel, labels, deadlineMs, traceWaitMs });
  runtimeRecord(sm.ok ? 'ok' : 'failed');
  if (!sm.ok) return fail(sm.reason, sm.detail);
  const log = readLog(Math.floor(Date.now() / 1000) - 60);
  if (!log.ok) {
    const detail = 'the kernel log (the host firewall\'s drops) cannot be read: neither journalctl nor sudo -n journalctl worked';
    if (needHostLog) return fail('host_log_unavailable', detail);
    skip('host_log_unavailable', detail);
    return { ok: true, reason: null, detail: null, hostLog: false };
  }
  return { ok: true, reason: null, detail: null, hostLog: true };
}

/** Which role an address of a sandbox network has (for telemetry); `target` names the .3/.4 container's role. */
export function rolesOn(net, { target = null } = {}) {
  const n = NETS[net];
  if (net === 'run') return { [n.netlog]: 'netlog', [n.target]: target ?? 'server', [n.probe]: 'probe' };
  return { [n.netlog]: 'netlog', [n.proxy]: 'proxy', [n.target]: target ?? 'install' };
}

/** Starts the network logger at .2 of a sandbox network (under gVisor) and waits until it listens. */
export async function startNetlogOn(dk, { net, network, image, toolsVol, labels, target, deadlineMs = 30_000 }) {
  const ip = NETS[net].netlog;
  const name = dk.name(target, 'netlog');
  // Root in the container only to bind ports below 1024: every other capability is dropped.
  await dk.must(dk.d(helperRunArgs({ name, image, network, ip, user: '0:0', capAdd: ['NET_BIND_SERVICE'], detach: true, labels, memory: '256m', mounts: [{ src: toolsVol, dst: P.tools, ro: true }], cmd: ['node', `${P.tools}/sandbox/netlog.mjs`, ip] }), { deadline: Date.now() + deadlineMs }), 'network logger');
  const until = Date.now() + deadlineMs;
  for (;;) {
    const r = await dk.d(['logs', name], { keepStdout: true, logStdout: false, cap: 64 * 1024, deadline: Date.now() + 10_000 });
    const first = jsonLines(r.stdout).find((o) => o.kind === 'listening');
    if (first) {
      if (!first.dns || !first.dns.udp || !first.dns.tcp) throw new HarnessError('the network logger could not take DNS (port 53)');
      return name;
    }
    if (Date.now() >= until) throw new HarnessError('the network logger did not start');
    await sleep(250);
  }
}

/** Stops the network logger (it prints its counts on SIGTERM) and returns its lines. */
export async function stopNetlog(dk, name) {
  await dk.d(['stop', '-t', '3', name], { deadline: Date.now() + 30_000 });
  const r = await dk.d(['logs', name], { keepStdout: true, logStdout: false, cap: 32 * 1024 * 1024, deadline: Date.now() + 60_000 });
  return jsonLines(r.stdout);
}

/** The logger's lines as `dns_query` and `connection` records. { records, invalid, stopped }. */
export function writeNetlog(tel, lines, { subject = null, roles = {} } = {}) {
  let records = 0; let invalid = 0;
  for (const o of lines) {
    const rec = fromNetlog(o);
    if (!rec) continue;
    if (tel.tryWrite(rec[0], rec[1], { source: 'netlog', subject, role: roles[o.from] ?? null })) records++; else invalid++;
  }
  return { records, invalid, stopped: lines.find((o) => o.kind === 'stopped') ?? null };
}

const ip4 = (s) => (typeof s === 'string' && /^(?:\d{1,3}\.){3}\d{1,3}$/.test(s) ? s.split('.').reduce((n, o) => n * 256 + Number(o), 0) : null);
const inRange = (ip, cidr) => {
  const [base, bits] = cidr.split('/'); const m = 2 ** (32 - Number(bits)); const n = ip4(ip);
  return n !== null && Math.floor(n / m) === Math.floor(ip4(base) / m);
};

/** Our drops (to or from the sandbox range, or any IPv6) between since and until, grouped. */
export function hostDropsFor(text, { since, until = Infinity, range = SANDBOX_RANGE, cap = 200 } = {}) {
  const drops = parseKernelLog(text, { since }).filter((d) => (d.ts === null || d.ts <= until) && (d.family === 6 || inRange(d.src, range) || inRange(d.dst, range)));
  return groupDrops(drops, cap);
}

/** Grouped drops as `host_drop` records. Returns how many were written. */
export function writeDrops(tel, groups, { subject = null, roles = {} } = {}) {
  let n = 0;
  for (const g of groups) {
    const [type, f] = fromDrop(g);
    if (tel.tryWrite(type, f, { source: 'host', subject, role: roles[g.src] ?? null })) n++; // a line the schema refuses is left out and counted
  }
  return n;
}

/**
 * Where a log or a limit cut the evidence of one target or case short: the firewall dropped more
 * than it logged (its LOG rules are rate limited), the network logger stopped printing, the trace
 * summary was cut to fit. `fw0` and `fw1` are firewallCounts() before and after.
 */
export function limitsHit({ fw0, fw1, netlogLines = [], trace = null }) {
  const out = [];
  if (!fw0 || !fw1) out.push('the firewall counters could not be read');
  else {
    for (const [chain, c1] of Object.entries(fw1)) {
      const c0 = fw0[chain] || { logged: 0, dropped: 0 };
      const unlogged = (c1.dropped - c0.dropped) - (c1.logged - c0.logged);
      if (unlogged > 0) out.push(`firewall ${chain}: ${unlogged} drop(s) not logged (rate limit)`);
    }
  }
  for (const l of netlogLines) if (l && l.kind === 'stopped' && Number(l.dropped) > 0) out.push(`network logger: ${Number(l.dropped)} line(s) not printed (line limit)`);
  if (trace && trace.shrunk) out.push('trace summary: lists cut to fit a record');
  return out;
}

export { firewallCounts };
