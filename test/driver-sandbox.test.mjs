// The corpus driver (bin/run-shard.mjs) against a scripted Docker daemon: no daemon, no network.
// What is checked here is the wiring of the sandbox: nothing runs unless gVisor is there, every
// container but the egress proxy names runsc, the fixed addresses and resolv.conf files, and what
// reaches the run telemetry.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { arch, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fakeFetch, tarGz } from './helpers.mjs';
import { Docker } from '../src/docker.mjs';
import { loadRunscConfig, runscFlags } from '../src/runsc.mjs';
import { NETS, resolvConf } from '../src/sandbox-net.mjs';
import { readTelemetry } from '../src/telemetry.mjs';

process.env.SURFACE_PROBE_MS = '6000';
const D = await import('../bin/run-shard.mjs');
const SHA = 'c'.repeat(40);
const IMAGE = `docker.io/library/node:24-bookworm-slim@sha256:${'d'.repeat(64)}`;
const TRACE = [
  'I1121 10:00:00.000001       1 strace.go:567] [   1:   1] node E openat(AT_FDCWD /work, 0x7f "/etc/passwd", O_RDONLY|O_CLOEXEC, 0o0)',
  'I1121 10:00:00.000002       1 strace.go:605] [   1:   1] node X openat(AT_FDCWD /work, 0x7f "/etc/passwd", O_RDONLY|O_CLOEXEC, 0o0) = 3 (0x3) (5µs)',
].join('\n');
const NETLOG = [
  { kind: 'listening', dns: { udp: true, tcp: true }, tcp: [80, 443], udp: [123] },
  { kind: 'dns', from: '10.213.53.3', proto: 'udp', qname: 'registry.npmjs.org', qtype: 'A', answer: 'sinkhole' },
  { kind: 'conn', from: '10.213.53.3', proto: 'tcp', port: 443, bytes: 0 },
  { kind: 'stopped', dns: 1, conns: 1 },
].map((o) => JSON.stringify(o)).join('\n');
const PROXY = [
  { t: '2026-11-21T10:00:00.000Z', listening: 8080, hosts: ['registry.npmjs.org'] },
  { t: '2026-11-21T10:00:01.000Z', host: 'registry.npmjs.org', port: 443, allowed: true, up: 100, down: 2000, ms: 30 },
  { t: '2026-11-21T10:00:02.000Z', host: 'evil.example', port: 443, allowed: false, error: 'not on the allowlist' },
].map((o) => JSON.stringify(o)).join('\n');
const val = (a, flag) => (a.indexOf(flag) < 0 ? null : a[a.indexOf(flag) + 1]);

/** A Docker session that answers from a script instead of a daemon, and records what it was asked. */
class FakeDocker extends Docker {
  constructor(o, script) { super(o); this.script = script; this.calls = []; }
  d(argv) {
    this.calls.push(argv);
    const r = this.script(argv) ?? {};
    const out = Buffer.from(r.stdout ?? '');
    return Promise.resolve({ exit: r.exit ?? 0, signal: null, timed_out: false, stdout: out, stdout_bytes: out.length, stdout_truncated: false, ms: 1 });
  }
}

/** The daemon: every runsc container leaves a trace in logDir, as runsc would. */
function daemon({ logDir, flags, noTrace = null }) {
  const nets = new Map();
  const box = new Map();
  let n = 0;
  return (argv) => {
    const [c0, c1] = argv;
    if (c0 === 'version') return { stdout: '27.3.1 linux/amd64\n' };
    if (c0 === 'info') return { stdout: argv[2] === '{{.NCPU}}' ? '4\n' : JSON.stringify({ runc: { path: 'runc' }, ...(flags ? { runsc: { path: '/usr/local/bin/runsc', runtimeArgs: flags } } : {}) }) };
    if (c0 === 'image') return { stdout: `sha256:${'e'.repeat(64)}\n` };
    if (c0 === 'volume' && c1 === 'inspect') return { exit: 1 };
    if (c0 === 'network' && c1 === 'create') { nets.set(argv[argv.length - 1], { internal: argv.includes('--internal'), subnet: val(argv, '--subnet') ?? '172.18.0.0/16' }); return {}; }
    if (c0 === 'network' && c1 === 'inspect') { const x = nets.get(argv[argv.length - 1]); return { stdout: `${x.internal} false ${x.subnet}\n` }; }
    if (c0 === 'run') {
      const id = (++n).toString(16).padStart(64, '0');
      const name = val(argv, '--name');
      const cmd = argv.join(' ');
      const what = /netlog\.mjs/.test(cmd) ? 'netlog' : /egress-proxy\.mjs/.test(cmd) ? 'proxy' : name.includes('-smoke') ? 'smoke' : val(argv, '--ip') === NETS.run.target ? 'server' : 'other';
      box.set(name, { id, what }); box.set(id, { id, what });
      if (val(argv, '--runtime') === 'runsc' && what !== noTrace) writeFileSync(join(logDir, `${id}.boot.log`), TRACE);
      if (val(argv, '--cidfile')) writeFileSync(val(argv, '--cidfile'), `${id}`);
      if (argv.includes('--detach')) return { stdout: `${id}\n` };
      if (/npm-entry\.mjs/.test(cmd)) return { stdout: JSON.stringify({ script: '/work/pkg/node_modules/n/index.js', version: '1.2.3' }) };
      if (/test -f/.test(cmd)) return { stdout: '{"lockfileVersion":3,"packages":{}}' };
      if (/probe\.mjs/.test(cmd)) return { stdout: JSON.stringify({ format: 'isokron-surface-probe/1', mode: 'http', error: 'no answer', lists: {}, transcript: [], transport: {} }) };
      return {};
    }
    if (c0 === 'logs') {
      const x = box.get(argv[1]) ?? { what: 'none' };
      return { stdout: x.what === 'netlog' ? NETLOG : x.what === 'proxy' ? PROXY : x.what === 'smoke' ? '65534 65534\n' : 'what the server printed\n' };
    }
    if (c0 === 'wait') return { stdout: '0\n' };
    if (c0 === 'inspect') {
      const x = box.get(argv[1]);
      return x ? { stdout: JSON.stringify([{ Id: x.id, HostConfig: { Runtime: 'runsc' }, State: { Running: x.what === 'server', ExitCode: 0, OOMKilled: false }, Config: { User: '65534:65534', Env: [] }, Mounts: [] }]) } : { exit: 1 };
    }
    return {};
  };
}

/** bsdtar (macOS) has no --owner/--group/--mode: a stand-in that drops them, for the tools volume only. */
function gnuTarOnPath(d) {
  if (/GNU tar/.test(spawnSync('tar', ['--version'], { encoding: 'utf8' }).stdout || '')) return process.env.PATH;
  const bin = join(d, 'bin'); mkdirSync(bin);
  writeFileSync(join(bin, 'tar'), '#!/bin/sh\nfor a in "$@"; do shift; case "$a" in --owner=*|--group=*|--mode=*) ;; *) set -- "$@" "$a" ;; esac; done\nexec /usr/bin/tar "$@"\n');
  chmodSync(join(bin, 'tar'), 0o755);
  return `${bin}:${process.env.PATH}`;
}

function setup({ flags = 'expected', hostLog = true, lane = 'local', noTrace = null, hostLogFailsAfter = Infinity } = {}) {
  const d = mkdtempSync(join(tmpdir(), 'surface-sbx-'));
  const logDir = join(d, 'runsc'); mkdirSync(logDir);
  const cfg = { ...loadRunscConfig(), log_dir: logDir };
  const want = runscFlags(cfg, arch());
  const box = { dk: null, probes: [], logReads: 0 };
  const makeDocker = (o) => (box.dk = new FakeDocker(o, daemon({ logDir, flags: flags === 'expected' ? want : flags, noTrace })));
  // The stdio probe starts `docker run --interactive`; here it writes the cidfile and the trace as docker and runsc would.
  const probe = async (argv) => {
    box.probes.push(argv);
    const id = `${'9'.repeat(60)}${String(box.probes.length).padStart(4, '0')}`;
    writeFileSync(val(argv, '--cidfile'), id);
    writeFileSync(join(logDir, `${id}.boot.log`), TRACE);
    const isNull = argv.some((x) => x.endsWith('null-server.mjs'));
    return { format: 'isokron-surface-probe/1', mode: 'stdio', lists: isNull ? { 'tools/list': { ok: true, items: [] } } : {}, timing: { initialize_ms: isNull ? 42 : null }, transport: { exit: isNull ? null : 1, signal: isNull ? 'SIGTERM' : null }, error: isNull ? null : 'the server exited (exit 1, signal null)', transcript: [], stderr: '', stderr_bytes: 0 };
  };
  const readResolv = (f) => resolvConf(f.endsWith('run.conf') ? 'run' : 'install');
  const readLog = () => {
    box.logReads++;
    if (!hostLog || box.logReads > hostLogFailsAfter) return { ok: false, text: '', via: null };
    return { ok: true, text: `${(Date.now() / 1000).toFixed(6)} runner kernel: isk-sbx-fwd: IN=br-1 OUT=eth0 SRC=10.213.53.3 DST=1.1.1.1 LEN=60 PROTO=TCP SPT=40000 DPT=443\n`, via: 'journalctl' };
  };
  const list = { format: 'isokron-surface-targets/1', defaults: { timeout_s: 120 }, targets: [
    { id: 's001', repo: 'o/n', commit: SHA, launch: { kind: 'npm', package: 'n', version: '1.2.3' } },
    { id: 's002', repo: 'o/n', commit: SHA, launch: { kind: 'docker', image: IMAGE, transport: 'http', http: { port: 8123, path: '/mcp' } } },
  ] };
  writeFileSync(join(d, 'targets.json'), JSON.stringify(list));
  const fetchFn = fakeFetch({ archives: { '*': tarGz({ 'README.md': '# n\n' }, { commit: SHA }) } });
  return { d, cfg, logDir, box, lane, out: join(d, 'out'), path: gnuTarOnPath(d), opts: { fetchFn, makeDocker, probe, runscConfig: cfg, readResolv, readLog, traceWaitMs: 0 } };
}

async function runMain(s) {
  const lines = [];
  const write = process.stdout.write.bind(process.stdout);
  const path = process.env.PATH;
  process.stdout.write = (x, ...r) => { if (typeof x === 'string' && /^run finished/.test(x)) { lines.push(x.trim()); return true; } return write(x, ...r); };
  process.env.PATH = s.path;
  let rc;
  try { rc = await D.main(['--targets', join(s.d, 'targets.json'), '--out', s.out, '--lane', s.lane], s.opts); } finally { process.stdout.write = write; process.env.PATH = path; }
  const tel = readTelemetry(join(s.out, '_shard', 'telemetry.jsonl'));
  const shard = JSON.parse(readFileSync(join(s.out, '_shard', 'shard.json'), 'utf8'));
  return { rc, lines, tel, shard, by: (type, f = () => true) => tel.records.filter((r) => r.type === type && f(r)) };
}

for (const [what, flags, reason] of [['no runsc runtime', null, 'runtime_unavailable'], ['runsc with other flags', ['--network=host'], 'sandbox_setup_missing']]) {
  test(`${what}: the shard starts no container of any runtime, records the skip and reports a harness error`, async () => {
    const s = setup({ flags });
    const r = await runMain(s);
    assert.equal(r.rc, 1);
    assert.deepEqual(r.lines, ['run finished, exit 125']);
    assert.deepEqual(s.box.dk.calls.filter((a) => a[0] === 'run'), [], 'nothing falls back to runc');
    assert.deepEqual(s.box.probes, []);
    assert.deepEqual(r.tel.bad, []);
    assert.deepEqual(r.tel.records.map((x) => x.type), ['run_start', 'runtime', 'skip', 'run_end']);
    assert.equal(r.by('run_start')[0].kind, 'corpus');
    assert.equal(r.by('runtime')[0].smoke, 'not_run');
    assert.equal(r.by('skip')[0].reason, reason);
    assert.equal(r.by('run_end')[0].ok, false);
    assert.match(r.shard.harness_error, new RegExp(reason));
    assert.deepEqual([r.shard.sandbox.ok, r.shard.sandbox.reason, r.shard.sandbox.runtime], [false, reason, 'runsc']);
    assert.equal(readFileSync(join(s.out, '_shard', 'rows.jsonl'), 'utf8'), '');
  });
}

test('a shard in the sandbox: runsc for every container but the egress proxy, fixed addresses, our resolv.conf, and the run telemetry', async () => {
  const s = setup();
  const r = await runMain(s);
  assert.equal(r.rc, 0);
  assert.deepEqual(r.lines, ['run finished, exit 0', 'run finished, exit 0']);
  const runs = s.box.dk.calls.filter((a) => a[0] === 'run');
  assert.ok(runs.every((a) => a.includes('--runtime')), 'every container names its runtime');
  const notRunsc = runs.filter((a) => val(a, '--runtime') !== 'runsc');
  assert.equal(notRunsc.length, 1);
  assert.equal(val(notRunsc[0], '--runtime'), 'runc');
  assert.ok(notRunsc[0].some((x) => x.endsWith('/sandbox/egress-proxy.mjs')), 'the one runc container is the egress proxy');
  assert.equal(val(notRunsc[0], '--user'), '65534:65534');
  assert.ok(s.box.probes.length === 2 && s.box.probes.every((a) => a[0] === 'docker' && val(a, '--runtime') === 'runsc'));

  // Install: the target's container at .4 of the install network, the proxy at .3, the logger at .2.
  const install = runs.filter((a) => val(a, '--ip') === NETS.install.target);
  assert.equal(install.length, 2, 'npm install and the entry helper');
  for (const a of install) {
    assert.equal(val(a, '--user'), '65534:65534');
    assert.ok(a.includes(`type=bind,src=${NETS.install.resolv},dst=/etc/resolv.conf,readonly`));
    assert.ok(a.includes(`HTTPS_PROXY=http://${NETS.install.proxy}:8080`));
    assert.ok(!a.join(' ').includes('egress:'), 'no name for the proxy: every name resolves to the logger');
    assert.ok(val(a, '--cidfile').startsWith(join(s.out, '_shard')));
  }
  const connect = s.box.dk.calls.find((a) => a[0] === 'network' && a[1] === 'connect');
  assert.deepEqual(connect.slice(0, 4), ['network', 'connect', '--ip', NETS.install.proxy]);
  assert.ok(runs.some((a) => a.join(' ').includes('chown -R 65534:65534 /work')));
  const netlogs = runs.filter((a) => a.some((x) => x.endsWith('/sandbox/netlog.mjs')));
  assert.deepEqual(netlogs.map((a) => val(a, '--ip')).sort(), [NETS.run.netlog, NETS.run.netlog, NETS.run.netlog, NETS.install.netlog].sort(), 'a logger for the baseline, each target\'s run network, and the install network');
  const created = s.box.dk.calls.filter((a) => a[0] === 'network' && a[1] === 'create');
  assert.equal(created.filter((a) => val(a, '--subnet') === NETS.run.subnet).length, 3);
  assert.ok(created.filter((a) => val(a, '--subnet')).every((a) => a.includes('--internal')));

  // Run: stdio and http servers at .3 of the run network with its resolv.conf; the http probe at .4.
  for (const a of [...s.box.probes, ...runs.filter((x) => val(x, '--ip') === NETS.run.target)]) {
    assert.equal(val(a, '--ip'), NETS.run.target);
    assert.ok(a.includes(`type=bind,src=${NETS.run.resolv},dst=/etc/resolv.conf,readonly`));
    assert.ok(!a.includes('--network-alias'));
    assert.notEqual(val(a, '--network'), 'none');
  }
  const probe = runs.find((a) => a.some((x) => x.endsWith('/sandbox/probe.mjs')));
  assert.deepEqual([val(probe, '--ip'), val(probe, '--add-host'), probe[probe.length - 1]], [NETS.run.probe, `server:${NETS.run.target}`, 'http://server:8123/mcp']);

  // Telemetry: every record valid, every container that ran target code recorded with its settings and trace.
  assert.deepEqual(r.tel.bad, []);
  assert.deepEqual([r.by('run_start')[0].kind, r.by('runtime')[0].smoke, r.by('runtime')[0].flags_match], ['corpus', 'ok', true]);
  const roles = (type, subject) => r.by(type, (x) => x.subject === subject).map((x) => x.role).sort();
  assert.deepEqual(roles('settings', null), ['baseline', 'smoke']);
  assert.deepEqual(roles('settings', 's001'), ['install', 'install', 'proxy', 'server']);
  assert.deepEqual(roles('settings', 's002'), ['server']);
  for (const type of ['container', 'trace_summary']) {
    assert.deepEqual(roles(type, null), ['baseline', 'smoke']);
    assert.deepEqual(roles(type, 's001'), ['install', 'install', 'server']);
    assert.deepEqual(roles(type, 's002'), ['server']);
  }
  assert.ok(r.by('container').every((x) => x.runtime === 'runsc'));
  assert.ok(r.by('trace_summary').every((x) => x.source === 'runsc' && x.summary.syscalls > 0));
  const settings = r.by('settings', (x) => x.subject === 's001' && x.role === 'install')[0];
  assert.deepEqual([settings.manifest.runtime, settings.manifest.user, settings.manifest.ip, settings.manifest.read_only], ['runsc', '65534:65534', NETS.install.target, true]);
  assert.deepEqual(r.by('egress').map((x) => [x.subject, x.source, x.role, x.host, x.allowed]), [['s001', 'proxy', 'proxy', 'registry.npmjs.org', true], ['s001', 'proxy', 'proxy', 'evil.example', false]]);
  assert.equal(r.by('dns_query').length, 4, 'the baseline\'s, s001\'s install and run, s002\'s run network loggers');
  assert.ok(r.by('dns_query').every((x) => x.source === 'netlog' && x.qname === 'registry.npmjs.org'));
  assert.equal(r.by('connection').length, 4);
  assert.ok(r.by('host_drop', (x) => x.subject === 's001' && x.dst === '1.1.1.1').length === 1);
  assert.deepEqual(r.by('skip'), []);
  const end = r.by('run_end')[0];
  assert.deepEqual([end.ok, end.records, end.skipped], [true, r.tel.records.length, 0]);
  assert.deepEqual(r.tel.records.map((x) => x.seq), r.tel.records.map((_, i) => i));

  // Kept: the record still has the proxy's lines. Gone: raw traces, cidfiles.
  assert.equal(JSON.parse(readFileSync(join(s.out, 's001', 'record.json'), 'utf8')).install.egress_refused, 1);
  assert.deepEqual(readdirSync(s.logDir), [], 'raw traces are summarised or swept');
  assert.equal(existsSync(join(s.out, '_shard', 'cid')), false);
  assert.deepEqual([r.shard.sandbox.ok, r.shard.sandbox.runtime, r.shard.sandbox.gvisor_release, r.shard.sandbox.host_log, r.shard.sandbox.telemetry], [true, 'runsc', s.cfg.release, true, 'telemetry.jsonl']);
  assert.equal(r.shard.baseline_initialize_ms, 42);
});

test('a kernel log the driver cannot read is a skip, not a stop: the shard runs, with no host_drop records', async () => {
  const s = setup({ hostLog: false });
  const r = await runMain(s);
  assert.equal(r.rc, 0);
  assert.deepEqual(r.by('skip').map((x) => x.reason), ['host_log_unavailable']);
  assert.deepEqual(r.by('host_drop'), []);
  assert.equal(s.box.logReads, 1, 'asked once, at the start');
  assert.equal(r.shard.sandbox.host_log, false);
  assert.equal(r.by('run_end')[0].ok, true);
});

test('the ci lane fails closed: a kernel log it cannot read stops the shard before any target runs', async () => {
  const s = setup({ hostLog: false, lane: 'ci' });
  const r = await runMain(s);
  assert.equal(r.rc, 1);
  assert.deepEqual(r.lines, ['run finished, exit 125']);
  assert.deepEqual(r.by('skip').map((x) => x.reason), ['host_log_unavailable']);
  assert.match(r.shard.harness_error, /host_log_unavailable/);
  assert.equal(readFileSync(join(s.out, '_shard', 'rows.jsonl'), 'utf8'), '');
});

test('the ci lane fails closed: a target with no syscall trace, or no firewall log, is a harness error and its row is left out', async () => {
  const s = setup({ lane: 'ci', noTrace: 'server' });
  const r = await runMain(s);
  assert.equal(r.rc, 1);
  const rows = readFileSync(join(s.out, '_shard', 'rows.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l).id);
  assert.deepEqual(rows, ['s001'], 's002 ran its http server without a trace: no row');
  const rec2 = JSON.parse(readFileSync(join(s.out, 's002', 'record.json'), 'utf8'));
  assert.deepEqual([rec2.public_exit, rec2.excluded], [125, 'sandbox evidence missing']);
  assert.match(rec2.errors.find((e) => e.step === 'evidence').error, /syscall trace \(server\)/);
  assert.equal(r.shard.results.s002, 125);

  const h = setup({ lane: 'ci', hostLogFailsAfter: 1 });
  const rh = await runMain(h);
  assert.equal(rh.rc, 1);
  assert.equal(readFileSync(join(h.out, '_shard', 'rows.jsonl'), 'utf8'), '', 'no target row without the firewall log');
  assert.match(JSON.parse(readFileSync(join(h.out, 's001', 'record.json'), 'utf8')).errors.find((e) => e.step === 'evidence').error, /host firewall log/);
});
