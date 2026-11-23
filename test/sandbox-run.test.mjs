import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Docker } from '../src/docker.mjs';
import { loadRunscConfig, runscFlags } from '../src/runsc.mjs';
import { NETS, resolvConf } from '../src/sandbox-net.mjs';
import { Telemetry, readTelemetry } from '../src/telemetry.mjs';
import { fakeHostRun } from './helpers.mjs';
import { preflight, installProblem, limitsHit, runtimeStatus, takeTrace, sweepTraces, startNetlogOn, stopNetlog, writeNetlog, hostDropsFor, rolesOn, resolvProblem, watchTraces, traceFsProblem, diskProblem } from '../src/sandbox-run.mjs';

const IMG = `docker.io/library/python:3.13-slim-bookworm@sha256:${'a'.repeat(64)}`;
const ID = 'c'.repeat(64);
const dir = () => mkdtempSync(join(tmpdir(), 'isk-run-'));
const cfgIn = (d) => ({ ...loadRunscConfig(), log_dir: d });
const TRACE = [
  'I1121 10:00:00.000001       1 strace.go:567] [   1:   1] python3 E openat(AT_FDCWD /work, 0x7f "/etc/passwd", O_RDONLY|O_CLOEXEC, 0o0)',
  'I1121 10:00:00.000002       1 strace.go:605] [   1:   1] python3 X openat(AT_FDCWD /work, 0x7f "/etc/passwd", O_RDONLY|O_CLOEXEC, 0o0) = 3 (0x3) (5µs)',
].join('\n');

/** A Docker session that answers from a script instead of a daemon, and records what it was asked. */
class FakeDocker extends Docker {
  constructor(script) { super({ runId: 'r1' }); this.script = script; this.calls = []; }
  d(argv) {
    this.calls.push(argv);
    const r = this.script(argv) ?? { exit: 0, stdout: '' };
    return Promise.resolve({ exit: r.exit ?? 0, signal: null, timed_out: !!r.timed_out, stdout: Buffer.from(r.stdout ?? ''), stdout_bytes: String(r.stdout ?? '').length, stdout_truncated: false, ms: 1 });
  }
}

const daemonWith = (flags, path = '/usr/local/lib/isokron-gvisor/current/runsc') => JSON.stringify({ 'io.containerd.runc.v2': { path: 'runc' }, ...(flags ? { runsc: { path, runtimeArgs: flags } } : {}) });
const inspect = (over = {}) => JSON.stringify([{ Id: ID, HostConfig: { Runtime: 'runsc', ...(over.HostConfig || {}) }, State: { ExitCode: 0, OOMKilled: false }, Config: { User: '65534:65534', Env: [] }, Mounts: [] }]);

function smokeScript({ flags, runtime = 'runsc', out = '65534 65534\n', trace = TRACE, logDir }) {
  return (argv) => {
    if (argv[0] === 'info') return { stdout: daemonWith(flags) };
    if (argv[0] === 'run') { if (trace !== null) writeFileSync(join(logDir, `${ID}.boot.log`), trace); return { stdout: `${ID}\n` }; }
    if (argv[0] === 'wait') return { stdout: '0\n' };
    if (argv[0] === 'inspect') return { stdout: inspect({ HostConfig: { Runtime: runtime } }) };
    if (argv[0] === 'logs') return { stdout: out };
    return null;
  };
}

function setup({ flags = 'expected', resolv = true, runtime, out, trace, hostLog = true } = {}) {
  const d = dir();
  const cfg = cfgIn(d);
  const want = runscFlags(cfg, 'x86_64');
  const dk = new FakeDocker(smokeScript({ flags: flags === 'expected' ? want : flags, runtime, out, trace, logDir: d }));
  const tel = new Telemetry(join(d, 't.jsonl'), { run: 'r-test1' });
  const readResolv = (f) => { if (!resolv) throw new Error('missing'); return resolvConf(f.endsWith('run.conf') ? 'run' : 'install'); };
  const readLog = () => (hostLog ? { ok: true, text: '', via: 'journalctl' } : { ok: false, text: '', via: null });
  return { d, cfg, dk, tel, opts: { cfg, arch: 'x86_64', image: IMG, cmd: ['python3', '-c', 'x'], expect: '65534 65534', tel, labels: dk.labels(), readResolv, readLog, needHostLog: true, traceWaitMs: 0 } };
}
const records = (d) => readTelemetry(join(d, 't.jsonl')).records;

test('runtime status: the daemon must have runsc with exactly the flags gvisor.json gives', async () => {
  const cfg = loadRunscConfig();
  const want = runscFlags(cfg, 'x86_64');
  const ok = await runtimeStatus(new FakeDocker(() => ({ stdout: daemonWith([...want].reverse()) })), cfg, 'x86_64');
  assert.equal(ok.available, true);
  assert.equal(ok.flags_match, true, 'order does not matter');
  const none = await runtimeStatus(new FakeDocker(() => ({ stdout: daemonWith(null) })), cfg, 'x86_64');
  assert.equal(none.available, false);
  assert.equal(none.flags_match, false);
  const other = await runtimeStatus(new FakeDocker(() => ({ stdout: daemonWith(['--network=host']) })), cfg, 'x86_64');
  assert.equal(other.available, true);
  assert.equal(other.flags_match, false);
  const down = await runtimeStatus(new FakeDocker(() => ({ exit: 1, stdout: '' })), cfg, 'x86_64');
  assert.equal(down.available, false);
});

test('preflight passes only with runsc, its flags, our resolv.conf, a smoke container under runsc as 65534, and its trace', async () => {
  const s = setup();
  const r = await preflight(s.dk, s.opts);
  assert.equal(r.ok, true, r.detail);
  const recs = records(s.d);
  assert.deepEqual(recs.map((x) => x.type), ['settings', 'container', 'trace_summary', 'runtime']);
  assert.equal(recs[0].manifest.runtime, 'runsc');
  assert.equal(recs[0].role, 'smoke');
  assert.equal(recs[1].runtime, 'runsc');
  assert.equal(recs[2].source, 'runsc');
  assert.ok(recs[2].summary.syscalls >= 1);
  assert.equal(recs[3].available, true);
  assert.equal(recs[3].flags_match, true);
  assert.equal(recs[3].smoke, 'ok', 'the runtime record carries the smoke container\'s result');
  assert.ok(!existsSync(join(s.d, `${ID}.boot.log`)), 'the raw trace is removed once summarised');
  const run = s.dk.calls.find((a) => a[0] === 'run');
  assert.equal(run[run.indexOf('--runtime') + 1], 'runsc');
  assert.ok(s.dk.calls.some((a) => a[0] === 'rm'), 'the smoke container is removed');
});

const skipOf = (d) => records(d).filter((x) => x.type === 'skip');
for (const [what, o, reason, re] of [
  ['no runsc runtime', { flags: null }, 'runtime_unavailable', /no runsc runtime/],
  ['runsc with other flags', { flags: ['--network=host'] }, 'sandbox_setup_missing', /other flags/],
  ['no resolv.conf from net-guard.sh', { resolv: false }, 'sandbox_setup_missing', /net-guard/],
  ['a container that did not run under runsc', { runtime: 'runc' }, 'runtime_unavailable', /did not run under runsc \(runtime runc\)/],
  ['a container that did not run as 65534', { out: '0 0\n' }, 'runtime_unavailable', /65534/],
  ['no syscall trace', { trace: null }, 'trace_unavailable', /trace/],
  ['an empty syscall trace', { trace: 'I1121 10:00:00.000001 1 x.go:1] nothing\n' }, 'trace_unavailable', /trace/],
  ['no host firewall log', { hostLog: false }, 'host_log_unavailable', /kernel log/],
]) {
  test(`preflight fails closed on ${what}: a skip record with the reason, never a runc fallback`, async () => {
    const s = setup(o);
    const r = await preflight(s.dk, s.opts);
    assert.equal(r.ok, false);
    assert.equal(r.reason, reason);
    assert.match(r.detail, re);
    const skips = skipOf(s.d);
    assert.equal(skips.length, 1);
    assert.equal(skips[0].reason, reason);
    for (const a of s.dk.calls.filter((x) => x[0] === 'run')) assert.equal(a[a.indexOf('--runtime') + 1], 'runsc');
  });
}

test('without needHostLog an unreadable kernel log is recorded and the run goes on', async () => {
  const s = setup({ hostLog: false });
  const r = await preflight(s.dk, { ...s.opts, needHostLog: false });
  assert.equal(r.ok, true);
  assert.equal(r.hostLog, false);
  assert.equal(skipOf(s.d)[0].reason, 'host_log_unavailable');
});

test('resolvProblem: our file, exactly', () => {
  assert.equal(resolvProblem('run', () => resolvConf('run')), null);
  assert.match(resolvProblem('run', () => 'nameserver 8.8.8.8\n'), /not the one net-guard\.sh writes/);
  assert.match(resolvProblem('install', () => { throw new Error('ENOENT'); }), /missing/);
});

test('takeTrace: summarises and removes the trace; null when runsc wrote none', async () => {
  const d = dir();
  const cfg = cfgIn(d);
  writeFileSync(join(d, `${ID}.boot.log`), TRACE);
  const s = await takeTrace(cfg, ID, { waitMs: 0 });
  assert.equal(s.syscalls, 1);
  assert.ok(!existsSync(join(d, `${ID}.boot.log`)));
  assert.equal(await takeTrace(cfg, 'e'.repeat(64), { waitMs: 0 }), null);
  assert.equal(await takeTrace(cfg, 'not-an-id', { waitMs: 0 }), null);
});

test('the network logger: started at .2 of its network under runsc, waited for, its lines become telemetry by role', async () => {
  const listening = JSON.stringify({ kind: 'listening', own: NETS.run.netlog, dns: { udp: 53, tcp: 53 }, tcp: 29, udp: 3, failed: [] });
  const lines = [
    listening,
    JSON.stringify({ t: 'x', kind: 'dns', from: NETS.run.target, proto: 'udp', qname: 'dns.google', qtype: 'A', answer: 'sinkhole' }),
    JSON.stringify({ t: 'x', kind: 'conn', from: NETS.run.target, proto: 'tcp', port: 443, bytes: 517, sni: 'dns.google' }),
    JSON.stringify({ t: 'x', kind: 'conn', from: NETS.run.probe, proto: 'tcp', port: 80, bytes: 0 }),
    'not json',
    JSON.stringify({ kind: 'stopped', lines: 3, dropped: 0 }),
  ].join('\n');
  const dk = new FakeDocker((a) => (a[0] === 'logs' ? { stdout: lines } : null));
  const name = await startNetlogOn(dk, { net: 'run', network: 'surface-r1-s001-run', image: IMG, toolsVol: 'surface-r1-tools', labels: dk.labels('s001'), target: 's001' });
  const run = dk.calls.find((a) => a[0] === 'run');
  assert.equal(run[run.indexOf('--ip') + 1], NETS.run.netlog);
  assert.equal(run[run.indexOf('--runtime') + 1], 'runsc');
  assert.deepEqual(run.filter((x, i) => run[i - 1] === '--cap-add'), ['NET_BIND_SERVICE']);
  assert.deepEqual(run.slice(-2), ['/opt/surface/sandbox/netlog.mjs', NETS.run.netlog]);
  const got = await stopNetlog(dk, name);
  assert.ok(dk.calls.some((a) => a[0] === 'stop'));
  const d = dir();
  const tel = new Telemetry(join(d, 't.jsonl'), { run: 'r-test1' });
  const n = writeNetlog(tel, got, { subject: 's001', roles: rolesOn('run', { target: 'server' }) });
  assert.equal(n.records, 3);
  assert.equal(n.stopped.dropped, 0);
  const recs = records(d);
  assert.deepEqual(recs.map((r) => [r.type, r.role, r.source]), [['dns_query', 'server', 'netlog'], ['connection', 'server', 'netlog'], ['connection', 'probe', 'netlog']]);
  assert.equal(recs[1].sni, 'dns.google');
});

test('the network logger that never says it is listening is a setup failure', async () => {
  const dk = new FakeDocker((a) => (a[0] === 'logs' ? { stdout: '' } : null));
  await assert.rejects(startNetlogOn(dk, { net: 'run', network: 'n', image: IMG, toolsVol: 'surface-r1-tools', labels: {}, target: 's001', deadlineMs: 300 }), /network logger/);
  const dk2 = new FakeDocker((a) => (a[0] === 'logs' ? { stdout: JSON.stringify({ kind: 'listening', dns: { udp: null, tcp: 53 }, failed: ['udp/53'] }) } : null));
  await assert.rejects(startNetlogOn(dk2, { net: 'run', network: 'n', image: IMG, toolsVol: 'surface-r1-tools', labels: {}, target: 's001', deadlineMs: 300 }), /DNS/);
});

test('host drops: only ours (the sandbox range, or IPv6) inside the time window, grouped', () => {
  const text = [
    '1763719200.100000 h kernel: isk-sbx-fwd: IN=br-1 OUT=eth0 SRC=10.213.53.3 DST=1.1.1.1 PROTO=TCP SPT=1 DPT=443',
    '1763719200.200000 h kernel: isk-sbx-fwd: IN=br-1 OUT=eth0 SRC=10.213.53.3 DST=1.1.1.1 PROTO=TCP SPT=2 DPT=443',
    '1763719200.300000 h kernel: isk-sbx-in: IN=docker0 OUT= SRC=172.17.0.2 DST=172.17.0.1 PROTO=TCP SPT=3 DPT=22',
    '1763719200.400000 h kernel: isk-sbx-in6: IN=br-1 OUT= SRC=fe80:0000:0000:0000:0000:0000:0000:0003 DST=ff02:0000:0000:0000:0000:0000:0000:0002 PROTO=ICMPv6 TYPE=133',
    '1763719300.000000 h kernel: isk-sbx-fwd: IN=br-1 OUT=eth0 SRC=10.213.53.3 DST=8.8.8.8 PROTO=UDP SPT=1 DPT=53',
  ].join('\n');
  const g = hostDropsFor(text, { since: 1763719200, until: 1763719250 });
  assert.deepEqual(g.map((x) => [x.chain, x.dst, x.n]), [['forward', '1.1.1.1', 2], ['input6', 'ff02:0000:0000:0000:0000:0000:0000:0002', 1]]);
  assert.equal(rolesOn('install')[NETS.install.proxy], 'proxy');
  assert.equal(rolesOn('install')[NETS.install.target], 'install');
  assert.equal(rolesOn('run', { target: 'case' })[NETS.run.target], 'case');
});

test('sweepTraces: removes the run\'s leftover traces (helpers\' too), nothing older and nothing else', () => {
  const d = dir();
  const cfg = cfgIn(d);
  const old = join(d, `${'1'.repeat(64)}.boot.log`);
  const fresh = join(d, `${'2'.repeat(64)}.boot.log`);
  const other = join(d, 'notes.txt');
  for (const f of [old, fresh, other]) writeFileSync(f, 'x');
  utimesSync(old, new Date(Date.now() - 3600_000), new Date(Date.now() - 3600_000));
  assert.equal(sweepTraces(cfg, Date.now() - 60_000), 1);
  assert.deepEqual([existsSync(old), existsSync(fresh), existsSync(other)], [true, false, true]);
  assert.equal(sweepTraces({ ...cfg, log_dir: join(d, 'missing') }, 0), 0);
});

test('a trace that grows past its limit, or a trace filesystem running short, stops the containers', async () => {
  const d = mkdtempSync(join(tmpdir(), 'tw-'));
  const cfg = { ...loadRunscConfig(), log_dir: d, trace_max_mb: 1 / 1024 }; // 1 KiB, for the test
  const roomy = () => ({ bsize: 4096, blocks: 1e6, bavail: 1e6 });
  const hits = [];
  const w = watchTraces(cfg, { sinceMs: Date.now(), intervalMs: 20, statfs: roomy, onOverflow: (h) => hits.push(h) });
  const f = join(d, `${'a'.repeat(64)}.boot.log`);
  writeFileSync(f, 'x'.repeat(100));
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(w.overflow(), null, 'under the limit');
  writeFileSync(f, 'x'.repeat(4096));
  await new Promise((r) => setTimeout(r, 80));
  w.stop();
  assert.equal(hits.length, 1);
  assert.deepEqual([w.overflow().file, w.overflow().bytes], [`${'a'.repeat(64)}.boot.log`, 4096]);
  const full = watchTraces(cfg, { sinceMs: Date.now() - 5000, intervalMs: 1000, statfs: () => ({ bsize: 4096, blocks: 1e6, bavail: 0 }), onOverflow: () => {} });
  full.stop();
  assert.ok(full.overflow(), 'a trace filesystem with no room left counts as an overflow');
});

test('the trace folder must be its own filesystem of the pinned size, and a target needs room to run', () => {
  const cfg = loadRunscConfig();
  const own = () => ({ bsize: 4096, blocks: cfg.trace_fs_mb * 256, bavail: cfg.trace_fs_mb * 256 });
  const rootFs = () => ({ bsize: 4096, blocks: 20 * 1024 * 256 * 10, bavail: 1e7 });
  assert.equal(traceFsProblem(cfg, { statfs: own }), null);
  assert.match(traceFsProblem(cfg, { statfs: rootFs }), /not a filesystem of its own/);
  assert.match(traceFsProblem(cfg, { statfs: () => { throw new Error('no'); } }), /cannot be read/);
  assert.equal(diskProblem(cfg, '/out', { statfs: (p) => (p === '/out' ? { bsize: 4096, bavail: 1e7 } : own()) }), null);
  assert.match(diskProblem(cfg, '/out', { statfs: (p) => (p === '/out' ? { bsize: 4096, bavail: 10 } : own()) }), /GB free for the results/);
  assert.match(diskProblem(cfg, '/out', { statfs: (p) => (p === '/out' ? { bsize: 4096, bavail: 1e7 } : { bsize: 4096, bavail: 1 }) }), /trace filesystem has less room/);
});

test('the strict preflight checks the host live: the pinned runsc in its place, the trace filesystem, the firewall', async () => {
  const own = (cfg) => () => ({ bsize: 4096, blocks: cfg.trace_fs_mb * 256, bavail: cfg.trace_fs_mb * 256 });
  const s = setup();
  const r = await preflight(s.dk, { ...s.opts, strict: true, statfs: own(s.cfg), run: fakeHostRun(s.cfg) });
  assert.equal(r.ok, true, r.detail);
  assert.deepEqual(records(s.d).filter((x) => x.type === 'firewall').map((x) => [x.live, x.problems]), [[true, []]]);
  const no = async (o) => { const t = setup(); const x = await preflight(t.dk, { ...t.opts, strict: true, statfs: own(t.cfg), run: fakeHostRun(t.cfg), ...o(t.cfg) }); assert.equal(x.ok, false); assert.equal(x.reason, 'sandbox_setup_missing'); return x.detail; };
  assert.match(await no((cfg) => ({ run: fakeHostRun(cfg, { drop: { 'iptables INPUT': ['-A INPUT -i br-+ -j ISK-SBX-IN'] } }) })), /firewall is not the one net-guard.sh makes/);
  assert.match(await no((cfg) => ({ run: fakeHostRun(cfg, { version: 'release-20250101.0' }) })), /does not say release-/);
  assert.match(await no(() => ({ statfs: () => ({ bsize: 4096, blocks: 1e9, bavail: 1e9 }) })), /not a filesystem of its own/);
  const cfg = loadRunscConfig();
  assert.match(installProblem(cfg, daemonWith(['x'], '/usr/bin/runsc'), fakeHostRun(cfg)), /not \/usr\/local\/lib\/isokron-gvisor\/current\/runsc/);
  assert.equal(installProblem(cfg, daemonWith(['x']), fakeHostRun(cfg)), null);
});

test('limits that cut evidence short are reported: firewall rate limit, logger line limit, a trace cut to fit', () => {
  const fw0 = { 'ISK-SBX': { logged: 10, dropped: 10 }, 'ISK-SBX-IN': { logged: 5, dropped: 5 } };
  assert.deepEqual(limitsHit({ fw0, fw1: { 'ISK-SBX': { logged: 12, dropped: 12 }, 'ISK-SBX-IN': { logged: 5, dropped: 5 } } }), []);
  assert.deepEqual(limitsHit({ fw0, fw1: { 'ISK-SBX': { logged: 210, dropped: 900 }, 'ISK-SBX-IN': { logged: 5, dropped: 5 } } }), ['firewall ISK-SBX: 690 drop(s) not logged (rate limit)']);
  assert.deepEqual(limitsHit({ fw0: null, fw1: null }), ['the firewall counters could not be read']);
  assert.deepEqual(limitsHit({ fw0, fw1: fw0, netlogLines: [{ kind: 'stopped', lines: 20000, dropped: 7 }], trace: { shrunk: true } }), ['network logger: 7 line(s) not printed (line limit)', 'trace summary: lists cut to fit a record']);
});
