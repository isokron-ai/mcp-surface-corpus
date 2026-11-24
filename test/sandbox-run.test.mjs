import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, realpathSync, symlinkSync, utimesSync, writeFileSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Docker } from '../src/docker.mjs';
import { loadRunscConfig, runscFlags } from '../src/runsc.mjs';
import { NETS, resolvConf } from '../src/sandbox-net.mjs';
import { Telemetry, readTelemetry } from '../src/telemetry.mjs';
import { fakeHostRun } from './helpers.mjs';
import { preflight, installProblem, dockerFsProblem, workReadCmd, WORK_READ_SCRIPT, limitsHit, runtimeStatus, takeTrace, sweepTraces, startNetlogOn, stopNetlog, writeNetlog, hostDropsFor, rolesOn, resolvProblem, watchTraces, traceFsProblem, diskProblem, imageHoles, PROXY_LOG_CAP } from '../src/sandbox-run.mjs';

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

test('R-SBX-02 a trace that grows past its limit, or a trace filesystem running short, stops the containers', async () => {
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

test('R-SBX-02 the trace folder must be its own filesystem of the pinned size, and a target needs room to run', () => {
  const cfg = loadRunscConfig();
  const own = () => ({ bsize: 4096, blocks: cfg.trace_fs_mb * 256, bavail: cfg.trace_fs_mb * 256 });
  const rootFs = () => ({ bsize: 4096, blocks: 20 * 1024 * 256 * 10, bavail: 1e7 });
  assert.equal(traceFsProblem(cfg, { statfs: own }), null);
  assert.match(traceFsProblem(cfg, { statfs: rootFs }), /not a filesystem of its own/);
  assert.match(traceFsProblem(cfg, { statfs: () => { throw new Error('no'); } }), /cannot be read/);
  const roomy = (p) => (p === '/out' || p === cfg.docker_root ? { bsize: 4096, bavail: 1e7 } : own());
  assert.equal(diskProblem(cfg, '/out', { statfs: roomy }), null);
  assert.match(diskProblem(cfg, '/out', { statfs: (p) => (p === '/out' ? { bsize: 4096, bavail: 10 } : roomy(p)) }), /GB free for the results/);
  assert.match(diskProblem(cfg, '/out', { statfs: (p) => (p === cfg.log_dir ? { bsize: 4096, bavail: 1 } : roomy(p)) }), /trace filesystem has less room/);
});

test('R-SBX-05 the strict preflight checks the host live: the pinned runsc in its place, the trace filesystem, the firewall', async () => {
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

test('R-SBX-04 limits that cut evidence short are reported: firewall rate limit, logger line limit, a trace cut to fit', () => {
  const fw0 = { 'ISK-SBX': { logged: 10, dropped: 10 }, 'ISK-SBX-IN': { logged: 5, dropped: 5 } };
  assert.deepEqual(limitsHit({ fw0, fw1: { 'ISK-SBX': { logged: 12, dropped: 12 }, 'ISK-SBX-IN': { logged: 5, dropped: 5 } } }), []);
  assert.deepEqual(limitsHit({ fw0, fw1: { 'ISK-SBX': { logged: 210, dropped: 900 }, 'ISK-SBX-IN': { logged: 5, dropped: 5 } } }), ['firewall ISK-SBX: 690 drop(s) not logged (rate limit)']);
  assert.deepEqual(limitsHit({ fw0: null, fw1: null }), ['the firewall counters could not be read']);
  assert.deepEqual(limitsHit({ fw0, fw1: fw0, netlogLines: [{ kind: 'stopped', lines: 20000, dropped: 7 }], trace: { shrunk: true } }), ['network logger: 7 line(s) not printed (line limit)', 'trace summary: lists cut to fit a record']);
});

test('R-SBX-23 the strict preflight refuses a Docker volumes folder that is not its own ext4 of the pinned size, from install-runsc.sh\'s image', async () => {
  const cfg = loadRunscConfig();
  assert.equal(dockerFsProblem(cfg, fakeHostRun(cfg)), null);
  for (const [v, why] of [[{ mounted: false }, /volumes folder \/var\/lib\/isokron-docker\/volumes is not a filesystem of its own of 6144 MB/], [{ fstype: 'tmpfs' }, /not a filesystem of its own/], [{ sectors: 70 * 1024 * 1024 * 2 }, /not a filesystem of its own/], [{ backing: '/tmp/other.img' }, /not a filesystem of its own/]]) {
    assert.match(String(dockerFsProblem(cfg, fakeHostRun(cfg, { fs: { volumes: v } }))), why, JSON.stringify(v));
  }
  const own = (c) => () => ({ bsize: 4096, blocks: c.trace_fs_mb * 256, bavail: c.trace_fs_mb * 256 });
  const t = setup();
  const x = await preflight(t.dk, { ...t.opts, strict: true, statfs: own(t.cfg), run: fakeHostRun(t.cfg, { fs: { volumes: { mounted: false } } }) });
  assert.deepEqual([x.ok, x.reason], [false, 'sandbox_setup_missing']);
  assert.match(x.detail, /Docker volumes folder \/var\/lib\/isokron-docker\/volumes is not a filesystem of its own/);
});

test('R-SBX-25 the strict preflight refuses Docker data off its own capped filesystem: data-root, overlay2, a reservation with holes, the inode count', () => {
  const cfg = loadRunscConfig();
  const why = (fs) => String(dockerFsProblem(cfg, fakeHostRun(cfg, { fs })));
  assert.match(why({ info: '/var/lib/docker overlay2 local' }), /does not keep its data on \/var\/lib\/isokron-docker/, 'the default data-root');
  assert.match(why({ info: `${cfg.docker_root} overlayfs local` }), /with overlay2/, 'containerd\'s image store keeps images off the data-root');
  assert.match(why({ data: { mounted: false } }), /Docker data-root \/var\/lib\/isokron-docker is not a filesystem of its own of 20480 MB/);
  assert.match(why({ data: { blocks: 1024 } }), /docker-fs\.img has holes/, 'a discard or a trim gave its blocks back');
  assert.match(why({ volumes: { blocks: 2048 } }), /volume-fs\.img has holes/);
  assert.match(why({ data: { sopts: 'rw,discard' } }), /mounted with discard/, 'seen on GitHub: online discard handed 512 MB of the reservation back');
  assert.equal(why({ data: { sopts: 'rw,nodiscard' } }), 'null', 'nodiscard is fine');
  assert.match(why({ volumes: { inodes: 19529728 } }), /it has 19529728 inodes/);
  assert.match(why({ data: { inodes: 1000 } }), /it has 1000 inodes/);
});

test('R-SBX-26 the strict preflight refuses a daemon whose containers keep their output without the pinned limits', () => {
  const cfg = loadRunscConfig();
  const why = (fs) => String(dockerFsProblem(cfg, fakeHostRun(cfg, { fs })));
  assert.match(why({ info: `${cfg.docker_root} overlay2 json-file` }), /the local log driver/);
  assert.match(why({ daemonJson: JSON.stringify({ 'log-driver': 'local' }) }), /log limits are not the pinned ones/);
  assert.match(why({ daemonJson: JSON.stringify({ 'log-driver': 'local', 'log-opts': { 'max-size': '1g', 'max-file': '2' } }) }), /log limits are not the pinned ones/);
  assert.match(why({ daemonJson: 'not json' }), /log limits are not the pinned ones/);
});

test('R-SBX-24 the work readout refuses a link anywhere in the path, the last part or a folder above it, and reads a plain file', { skip: process.platform !== 'linux' && 'needs GNU realpath -e (runs on the Linux CI)' }, () => {
  const d = realpathSync(dir());
  const script = WORK_READ_SCRIPT.replace('/work/*', `${d}/*`);
  const read = (p) => spawnSync('sh', ['-c', script, 'sh', p, '100'], { encoding: 'utf8' });
  mkdirSync(join(d, 'lock')); mkdirSync(join(d, 'real'));
  writeFileSync(join(d, 'lock', 'plain.txt'), 'plain\n');
  writeFileSync(join(d, 'real', 'package-lock.json'), '{}\n');
  symlinkSync('/etc/passwd', join(d, 'lock', 'freeze.txt'));
  symlinkSync(join(d, 'real'), join(d, 'pkg'));
  assert.deepEqual([read(join(d, 'lock', 'plain.txt')).status, read(join(d, 'lock', 'plain.txt')).stdout], [0, 'plain\n']);
  assert.equal(read(join(d, 'lock', 'freeze.txt')).status, 3, 'the last part is a link');
  assert.equal(read(join(d, 'pkg', 'package-lock.json')).status, 3, 'a folder above it is a link');
  assert.equal(read(join(d, 'lock', 'none.txt')).status, 4);
  assert.equal(read(join(d, 'lock')).status, 4, 'not a regular file');
  assert.equal(read('/etc/hostname').status, 3, 'never outside the work folder');
});

test('R-SBX-24 the corpus reads lock files with the same readout, and only through a helper with the work volume read-only', () => {
  const cmd = workReadCmd('/work/lock/freeze.txt', 16);
  assert.deepEqual(cmd, ['sh', '-c', WORK_READ_SCRIPT, 'sh', '/work/lock/freeze.txt', '16']);
  assert.match(WORK_READ_SCRIPT, /realpath -e -- "\$1"/);
  assert.match(WORK_READ_SCRIPT, /\[ "\$r" = "\$1" \] \|\| exit 3/);
  const shard = readFileSync(new URL('../bin/run-shard.mjs', import.meta.url), 'utf8');
  assert.match(shard, /mounts: \[\{ src: work, dst: P\.work, ro: true \}\], cmd: workReadCmd\(lk\.path, 16 \* 1024 \* 1024\) \}/);
  assert.ok(!/test ! -L/.test(shard), 'the old check (the last part only) is gone');
});

test('R-SBX-28 a proxy that left lines out is a limit hit, like the network logger', () => {
  const fw = { 'ISK-SBX': { logged: 1, dropped: 1 } };
  assert.deepEqual(limitsHit({ fw0: fw, fw1: fw, proxyLines: [{ kind: 'stopped', lines: 20000, dropped: 512 }] }), ['egress proxy: 512 line(s) not printed (line limit)']);
  assert.deepEqual(limitsHit({ fw0: fw, fw1: fw, proxyLines: [{ kind: 'stopped', lines: 3, dropped: 0 }] }), []);
});

test('R-SBX-29 a target needs room on Docker\'s data filesystem too', () => {
  const cfg = loadRunscConfig();
  const st = (dockerFree) => (p) => (p === cfg.docker_root ? { bsize: 4096, bavail: dockerFree } : { bsize: 4096, bavail: 1e7 });
  assert.equal(diskProblem(cfg, '/out', { statfs: st(1e7) }), null);
  assert.match(diskProblem(cfg, '/out', { statfs: st(1000) }), /less than 3 GB free on Docker's data filesystem \(\/var\/lib\/isokron-docker\)/);
  assert.match(diskProblem(cfg, '/out', { statfs: (p) => { if (p === cfg.docker_root) throw new Error('no'); return { bsize: 4096, bavail: 1e7 }; } }), /Docker's data filesystem/);
});

test('R-SBX-32 the strict preflight refuses a trace filesystem whose image has holes', async () => {
  const cfg = loadRunscConfig();
  const own = () => ({ bsize: 4096, blocks: cfg.trace_fs_mb * 256, bavail: cfg.trace_fs_mb * 256 });
  assert.equal(traceFsProblem(cfg, { statfs: own, run: fakeHostRun(cfg) }), null);
  assert.match(traceFsProblem(cfg, { statfs: own, run: fakeHostRun(cfg, { fs: { trace: { blocks: 100 } } }) }), /trace-fs\.img has holes \(stat: 100 512 2147483648\)/);
  assert.equal(traceFsProblem(cfg, { statfs: own }), null, 'without run (not strict), the size only');
  assert.match(String(imageHoles('/x.img', () => ({ status: 1, stdout: '' }))), /has holes \(stat: unreadable\)/);
  const t = setup();
  const x = await preflight(t.dk, { ...t.opts, strict: true, statfs: own, run: fakeHostRun(t.cfg, { fs: { trace: { blocks: 100 } } }) });
  assert.deepEqual([x.ok, x.reason], [false, 'sandbox_setup_missing']);
  assert.match(x.detail, /trace-fs\.img has holes/);
});

test('R-SBX-33 Docker lists no volume lost+found: the folder mkfs makes in the volumes filesystem is removed, and the preflight checks it', () => {
  const cfg = loadRunscConfig();
  assert.match(String(dockerFsProblem(cfg, fakeHostRun(cfg, { fs: { volumeList: 'lost+found\n' } }))), /Docker lists a volume lost\+found/, 'seen on GitHub: mcp-check\'s sweep found 1 volume left after every run');
  assert.equal(dockerFsProblem(cfg, fakeHostRun(cfg, { fs: { volumeList: 'surface-x-work\n' } })), null);
  const sh = readFileSync(new URL('../scripts/install-runsc.sh', import.meta.url), 'utf8');
  assert.ok(sh.indexOf('rmdir "$volumes_dir/lost+found"') > sh.indexOf('mount -o loop,nosuid,nodev,nodiscard "$install_dir/volume-fs.img" "$volumes_dir"'), 'removed once mounted');
  assert.match(sh, /rmdir "\$docker_root\/lost\+found"/);
});

test('R-SBX-34 the harness reads all of a full proxy log: MAX_LINES refusals of the longest host names and the stopped line fit its read cap, and a cut read is a limit hit', async () => {
  const { makeProxy, cappedLog, MAX_LINES } = await import('../sandbox/egress-proxy.mjs');
  // Exactly what the proxy prints: its own timestamp, then the refusal makeProxy logs for a CONNECT.
  const lines = [];
  const capped = cappedLog((o) => lines.push(`${JSON.stringify({ t: new Date().toISOString(), ...o })}\n`));
  const host = `${'a'.repeat(63)}.${'b'.repeat(63)}.${'c'.repeat(63)}.${'d'.repeat(61)}`; // 253 characters, the longest a DNS name may be
  assert.equal(host.length, 253);
  for (let i = 0; i < MAX_LINES + 100; i++) capped.log({ host, port: 443, allowed: false, error: 'host not on the allowlist' });
  lines.push(`${JSON.stringify({ t: new Date().toISOString(), kind: 'stopped', ...capped.stats() })}\n`);
  const bytes = Buffer.byteLength(lines.join(''));
  assert.ok(bytes > 4 * 1024 * 1024, `${bytes} bytes: the old 4 MiB cap cut the stopped line off`);
  assert.ok(bytes < PROXY_LOG_CAP, `${bytes} bytes fit the read cap (${PROXY_LOG_CAP})`);
  assert.equal(PROXY_LOG_CAP, 16 * 1024 * 1024, 'one container log file');
  assert.match(lines[lines.length - 1], /"kind":"stopped","lines":20000,"dropped":100/);
  assert.ok(typeof makeProxy === 'function');
  const fw = { 'ISK-SBX': { logged: 1, dropped: 1 } };
  assert.deepEqual(limitsHit({ fw0: fw, fw1: fw, proxyTruncated: true }), [`egress proxy: its log was cut at ${PROXY_LOG_CAP} bytes when read`]);
  for (const f of ['../bin/run-shard.mjs', '../bin/sandbox-selftest.mjs']) {
    const src = readFileSync(new URL(f, import.meta.url), 'utf8');
    assert.match(src, /\['logs', proxy\], \{ keepStdout: true, logStdout: false, cap: PROXY_LOG_CAP/, `${f}: the proxy's log read with PROXY_LOG_CAP`);
    assert.ok(!/\['logs', proxy\][^\n]*cap: 4 \* 1024 \* 1024/.test(src), `${f}: not 4 MiB`);
    assert.match(src, /stdout_truncated/, `${f}: a cut read is noted`);
  }
});
