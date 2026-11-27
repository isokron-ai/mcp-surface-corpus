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
import { fakeFetch, fakeHostRun, tarGz } from './helpers.mjs';
import { Docker } from '../src/docker.mjs';
import { loadRunscConfig, runscFlags } from '../src/runsc.mjs';
import { NETS, resolvConf } from '../src/sandbox-net.mjs';
import { Telemetry, readTelemetry } from '../src/telemetry.mjs';

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
// The other registries' names resolve to a public address in these tests (crates.io, NuGet, GitHub release assets, PyPI).
const PUBLIC_HOSTS = ['index.crates.io', 'static.crates.io', 'api.nuget.org', 'globalcdn.nuget.org', 'github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com', 'pypi.org', 'files.pythonhosted.org'];
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
function daemon({ logDir, flags, noTrace = null, runscPath = '/usr/local/lib/isokron-gvisor/current/runsc' }) {
  const nets = new Map();
  const box = new Map();
  let n = 0;
  return (argv) => {
    const [c0, c1] = argv;
    if (c0 === 'version') return { stdout: '27.3.1 linux/amd64\n' };
    if (c0 === 'info') return { stdout: argv[2] === '{{.NCPU}}' ? '4\n' : JSON.stringify({ runc: { path: 'runc' }, ...(flags ? { runsc: { path: runscPath, runtimeArgs: flags } } : {}) }) };
    if (c0 === 'image') return { stdout: `sha256:${'e'.repeat(64)}\n` };
    if (c0 === 'volume' && c1 === 'inspect') return { exit: 1 };
    if (c0 === 'network' && c1 === 'create') { nets.set(argv[argv.length - 1], { internal: argv.includes('--internal'), subnet: val(argv, '--subnet') ?? '172.18.0.0/16' }); return {}; }
    if (c0 === 'network' && c1 === 'inspect') { const x = nets.get(argv[argv.length - 1]); return { stdout: `${x.internal} false ${x.subnet}\n` }; }
    if (c0 === 'start') return {};
    if (c0 === 'run' || c0 === 'create') {
      const id = (++n).toString(16).padStart(64, '0');
      const name = val(argv, '--name');
      const cmd = argv.join(' ');
      const what = /netlog\.mjs/.test(cmd) ? 'netlog' : /egress-proxy\.mjs/.test(cmd) ? 'proxy' : name.includes('-smoke') ? 'smoke' : val(argv, '--ip') === NETS.run.target ? 'server' : 'other';
      box.set(name, { id, what }); box.set(id, { id, what });
      if (val(argv, '--runtime') === 'runsc' && what !== noTrace) writeFileSync(join(logDir, `${id}.boot.log`), TRACE);
      if (val(argv, '--cidfile')) writeFileSync(val(argv, '--cidfile'), `${id}`);
      if (argv.includes('--detach') || c0 === 'create') return { stdout: `${id}\n` };
      if (/npm-entry\.mjs/.test(cmd)) return { stdout: JSON.stringify({ script: '/work/pkg/node_modules/n/index.js', version: '1.2.3' }) };
      if (/cargo-entry\.mjs/.test(cmd)) return { stdout: JSON.stringify({ script: '/work/pkg/bin/crate-mcp', version: '0.4.1', bins: 1 }) };
      if (/nuget-entry\.mjs/.test(cmd)) return { stdout: JSON.stringify({ script: '/work/pkg/.store/p.mcp/1.0.0/p.mcp/1.0.0/tools/net9.0/any/P.Mcp.dll', runner: 'dotnet', command: 'p-mcp', version: '1.0.0', tfm: 'net9.0', rid: 'any' }) };
      if (/mcpb-fetch\.mjs/.test(cmd)) return { stdout: JSON.stringify({ ok: true, bytes: 1000, sha256: 'a'.repeat(64), files: 3, dirs: 1, links_skipped: 0, unpacked: 2000 }) };
      if (/realpath -e/.test(cmd)) return { stdout: '{"lockfileVersion":3,"packages":{}}' };
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

function setup({ flags = 'expected', hostLog = true, lane = 'local', noTrace = null, hostLogFailsAfter = Infinity, targets = null } = {}) {
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
  const list = { format: 'isokron-surface-targets/1', defaults: { timeout_s: 120 }, targets: targets ?? [
    { id: 's001', repo: 'o/n', commit: SHA, launch: { kind: 'npm', package: 'n', version: '1.2.3' } },
    { id: 's002', repo: 'o/n', commit: SHA, launch: { kind: 'docker', image: IMAGE, transport: 'http', http: { port: 8123, path: '/mcp' } } },
  ] };
  writeFileSync(join(d, 'targets.json'), JSON.stringify(list));
  const fetchFn = fakeFetch({ archives: { '*': tarGz({ 'README.md': '# n\n' }, { commit: SHA }) } });
  // The trace folder as install-runsc.sh mounts it: its own filesystem of trace_fs_mb, mostly free.
  const statfs = (p) => (p === logDir ? { bsize: 4096, blocks: cfg.trace_fs_mb * 256, bavail: cfg.trace_fs_mb * 256 - 10 } : { bsize: 4096, blocks: 1e9, bavail: 1e9 });
  return { d, cfg, logDir, box, lane, out: join(d, 'out'), path: gnuTarOnPath(d), opts: { fetchFn, makeDocker, probe, runscConfig: cfg, readResolv, readLog, traceWaitMs: 0, statfs, hostRun: fakeHostRun(cfg), resolveHost: async (h) => (h === 'registry.npmjs.org' ? [{ address: '104.16.1.34', family: 4 }, { address: '10.0.0.9', family: 4 }] : PUBLIC_HOSTS.includes(h) ? [{ address: '140.82.112.3', family: 4 }] : []) } };
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

test('R-SBX-07 a shard in the sandbox: runsc for every container, the egress proxy too, fixed addresses, our resolv.conf, and the run telemetry', async () => {
  const s = setup();
  const r = await runMain(s);
  assert.equal(r.rc, 0);
  assert.deepEqual(r.lines, ['run finished, exit 0', 'run finished, exit 0']);
  const runs = s.box.dk.calls.filter((a) => a[0] === 'run' || a[0] === 'create');
  assert.ok(runs.every((a) => val(a, '--runtime') === 'runsc'), 'every container runs under gVisor');
  // The egress proxy: created, given its install-network address, then started; registry names as
  // fixed host entries the host resolved, public addresses only.
  const proxy = runs.find((a) => a.some((x) => x.endsWith('/sandbox/egress-proxy.mjs')));
  assert.equal(proxy[0], 'create');
  assert.equal(val(proxy, '--user'), '65534:65534');
  assert.deepEqual(proxy.filter((x, i) => proxy[i - 1] === '--add-host'), ['registry.npmjs.org:104.16.1.34']);
  const pName = val(proxy, '--name');
  const seq = s.box.dk.calls.map((a) => a.join(' ')).filter((l) => l.includes(pName) && /^(create|network connect|start)/.test(l)).map((l) => l.split(' ')[0]);
  assert.deepEqual(seq, ['create', 'network', 'start']);
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

test('R-SBX-03 the ci lane fails closed: a kernel log it cannot read stops the shard before any target runs', async () => {
  const s = setup({ hostLog: false, lane: 'ci' });
  const r = await runMain(s);
  assert.equal(r.rc, 1);
  assert.deepEqual(r.lines, ['run finished, exit 125']);
  assert.deepEqual(r.by('skip').map((x) => x.reason), ['host_log_unavailable']);
  assert.match(r.shard.harness_error, /host_log_unavailable/);
  assert.equal(readFileSync(join(s.out, '_shard', 'rows.jsonl'), 'utf8'), '');
});

test('R-SBX-03 the ci lane fails closed: a target with no syscall trace, or no firewall log, is a harness error and its row is left out', async () => {
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

test('R-SBX-11 the ci lane fails closed when the schema refuses a trace summary: that target counts as missing its trace', async () => {
  const s = setup({ lane: 'ci' });
  const orig = Telemetry.prototype.tryWrite;
  // The schema refusing s002's server trace, as a summary too big or malformed would be refused.
  Telemetry.prototype.tryWrite = function (type, fields, meta = {}) {
    if (type === 'trace_summary' && meta.subject === 's002') { this.dropped++; return null; }
    return orig.call(this, type, fields, meta);
  };
  let r;
  try { r = await runMain(s); } finally { Telemetry.prototype.tryWrite = orig; }
  assert.equal(r.rc, 1);
  const rows = readFileSync(join(s.out, '_shard', 'rows.jsonl'), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l).id);
  assert.deepEqual(rows, ['s001'], 's002 has no row');
  const rec2 = JSON.parse(readFileSync(join(s.out, 's002', 'record.json'), 'utf8'));
  assert.deepEqual([rec2.public_exit, rec2.excluded], [125, 'sandbox evidence missing']);
  assert.match(rec2.errors.find((e) => e.step === 'evidence').error, /a syscall trace record \(server\)/);
  assert.ok(r.by('run_end')[0].telemetry_dropped >= 1);
});

test('R-SBX-22 a native build runs in the build image with every hardening an install gets; the server runs in the slim image', async () => {
  const s = setup({ targets: [
    { id: 's001', repo: 'o/n', commit: SHA, launch: { kind: 'npm', package: 'n', version: '1.2.3', install_scripts: true } },
    { id: 's002', repo: 'o/n', commit: SHA, launch: { kind: 'npm', package: 'n', version: '1.2.3' } },
  ] });
  const r = await runMain(s);
  assert.equal(r.rc, 0);
  const images = D.loadImages(new URL('../images.json', import.meta.url).pathname);
  const runs = s.box.dk.calls.filter((a) => a[0] === 'run' || a[0] === 'create');
  const installs = runs.filter((a) => val(a, '--ip') === NETS.install.target);
  const imageOf = (a) => a.find((x) => /@sha256:[0-9a-f]{64}$/.test(x));
  const subject = (a) => (val(a, '--name') || '').match(/-(s00\d)-/)?.[1];
  const built = installs.filter((a) => subject(a) === 's001');
  const plain = installs.filter((a) => subject(a) === 's002');
  assert.equal(built.length, 2, 'npm install and the entry helper');
  assert.equal(plain.length, 2);
  for (const a of built) assert.equal(imageOf(a), images['node24-build']);
  for (const a of plain) assert.equal(imageOf(a), images.node24);
  // The same hardening as any install: gVisor, user 65534, no capabilities, a read-only root with
  // only the work volume writable, the install network (internal, proxy-only), our resolv.conf.
  const flags = (a) => ({
    runtime: val(a, '--runtime'), user: val(a, '--user'), capDrop: val(a, '--cap-drop'), readOnly: a.includes('--read-only'),
    noNewPriv: a.includes('no-new-privileges') || a.some((x) => /no-new-privileges/.test(x)), ip: val(a, '--ip'),
    resolv: a.includes(`type=bind,src=${NETS.install.resolv},dst=/etc/resolv.conf,readonly`), proxy: a.includes(`HTTPS_PROXY=http://${NETS.install.proxy}:8080`),
    rwMounts: a.filter((x) => /^type=volume,/.test(x) && !/,readonly/.test(x)).map((x) => x.replace(/^.*dst=([^,]+).*$/, '$1')),
  });
  assert.deepEqual(flags(built[0]), flags(plain[0]), 'the build container is hardened exactly like an install container');
  assert.deepEqual([flags(built[0]).runtime, flags(built[0]).user, flags(built[0]).capDrop, flags(built[0]).readOnly, flags(built[0]).rwMounts], ['runsc', '65534:65534', 'ALL', true, ['/work']]);
  assert.ok(built[0].includes('npm_config_nodedir=/usr/local') && built[0].includes('npm_config_build_from_source=true'));
  assert.ok(!plain[0].some((x) => x.startsWith('npm_config_nodedir=')));
  assert.ok(!built[0].includes('--ignore-scripts') && plain[0].includes('--ignore-scripts'));
  // Only the registry, as for any npm install.
  const proxies = runs.filter((a) => a.some((x) => x.endsWith('/sandbox/egress-proxy.mjs')));
  for (const p of proxies) assert.deepEqual(p.slice(p.findIndex((x) => x.endsWith('/sandbox/egress-proxy.mjs')) + 2), ['registry.npmjs.org']);
  // The servers run in the slim image.
  const servers = s.box.probes.filter((a) => /-s00[12]-/.test(val(a, '--name') || ''));
  assert.ok(servers.length >= 2);
  for (const a of servers) assert.equal(imageOf(a), images.node24);
  // Traced and recorded like any install.
  assert.deepEqual(r.by('settings', (x) => x.subject === 's001').map((x) => x.role).sort(), ['install', 'install', 'proxy', 'server']);
  assert.deepEqual(r.by('trace_summary', (x) => x.subject === 's001').map((x) => x.role).sort(), ['install', 'install', 'server']);
  const st = r.by('settings', (x) => x.subject === 's001' && x.role === 'install')[0];
  assert.deepEqual([st.manifest.runtime, st.manifest.user, st.manifest.read_only], ['runsc', '65534:65534', true]);
  assert.equal(JSON.parse(readFileSync(join(s.out, 's001', 'record.json'), 'utf8')).install.image, images['node24-build']);
});

/** The hardening of one container's `docker run` arguments, as R-SBX-22 reads it. */
const hardening = (a) => ({
  runtime: val(a, '--runtime'), user: val(a, '--user'), capDrop: val(a, '--cap-drop'), readOnly: a.includes('--read-only'),
  noNewPriv: a.some((x) => /no-new-privileges/.test(x)), ip: val(a, '--ip'), memory: val(a, '--memory'), pids: val(a, '--pids-limit'),
  resolv: a.includes(`type=bind,src=${NETS.install.resolv},dst=/etc/resolv.conf,readonly`), proxy: a.includes(`HTTPS_PROXY=http://${NETS.install.proxy}:8080`),
  rwMounts: a.filter((x) => /^type=volume,/.test(x) && !/,readonly/.test(x)).map((x) => x.replace(/^.*dst=([^,]+).*$/, '$1')),
});

test('R-SBX-35 a crate builds in the pinned Rust image and a .NET tool installs in the pinned SDK image, every step hardened like any install, the helper steps in our node image, the proxy open to crates.io or NuGet only', async () => {
  const s = setup({ targets: [
    { id: 's001', repo: 'o/n', commit: SHA, launch: { kind: 'cargo', crate: 'crate-mcp', version: 'latest', args: ['--stdio'] } },
    { id: 's002', repo: 'o/n', commit: SHA, launch: { kind: 'nuget', package: 'P.Mcp', version: '1.0.0' } },
    { id: 's003', repo: 'o/n', commit: SHA, launch: { kind: 'npm', package: 'n', version: '1.2.3' } },
  ] });
  const r = await runMain(s);
  assert.equal(r.rc, 0);
  const images = D.loadImages(new URL('../images.json', import.meta.url).pathname);
  const runs = s.box.dk.calls.filter((a) => a[0] === 'run' || a[0] === 'create');
  const imageOf = (a) => a.find((x) => /@sha256:[0-9a-f]{64}$/.test(x));
  const subject = (a) => (val(a, '--name') || '').match(/-(s00\d)-/)?.[1];
  const installs = (id) => runs.filter((a) => val(a, '--ip') === NETS.install.target && subject(a) === id);
  const crate = installs('s001'); const tool = installs('s002'); const npm = installs('s003');
  assert.deepEqual(crate.map(imageOf), [images['rust-build'], images.node24, images['rust-build']], 'build, entry helper, clean');
  assert.deepEqual(tool.map(imageOf), [images['dotnet-sdk'], images['dotnet-sdk'], images.node24, images['dotnet-sdk']], 'config, install, entry helper, clean');
  for (const a of [...crate, ...tool]) assert.deepEqual(hardening(a), hardening(npm[0]), 'hardened exactly like an npm install container');
  assert.deepEqual([hardening(crate[0]).runtime, hardening(crate[0]).user, hardening(crate[0]).capDrop, hardening(crate[0]).readOnly, hardening(crate[0]).rwMounts], ['runsc', '65534:65534', 'ALL', true, ['/work']]);
  const cmdOf = (a) => a.slice(a.indexOf(imageOf(a)) + 1);
  assert.deepEqual(cmdOf(crate[0]), ['cargo', 'install', '--locked', '--root', '/work/pkg', '--', 'crate-mcp']);
  assert.ok(crate[0].includes('CARGO_HOME=/work/cargo-home') && crate[0].includes('CARGO_TARGET_DIR=/work/target'));
  assert.deepEqual(cmdOf(crate[2]), ['rm', '-rf', '/work/target', '/work/cargo-home'], 'the build output is gone before the server starts');
  assert.deepEqual(cmdOf(tool[1]), ['dotnet', 'tool', 'install', 'P.Mcp', '--tool-path', '/work/pkg', '--configfile', '/work/nuget.config', '--allow-roll-forward', '--version', '1.0.0']);
  assert.ok(tool[1].includes('NUGET_CERT_REVOCATION_MODE=offline') && tool[1].includes('NUGET_PACKAGES=/work/nuget'));
  // The proxy of each: its registry's hosts only.
  const proxies = runs.filter((a) => a.some((x) => x.endsWith('/sandbox/egress-proxy.mjs')));
  const hostsOf = (id) => proxies.filter((p) => subject(p) === id).map((p) => p.slice(p.findIndex((x) => x.endsWith('/sandbox/egress-proxy.mjs')) + 2));
  assert.deepEqual(hostsOf('s001'), [['index.crates.io', 'static.crates.io']]);
  assert.deepEqual(hostsOf('s002'), [['api.nuget.org', 'globalcdn.nuget.org']]);
  // The servers: the crate's binary in the Rust image; the tool's entry point on the SDK image's runtime, rolled forward.
  const server = (id) => s.box.probes.find((a) => new RegExp(`-${id}-s`).test(val(a, '--name') || ''));
  assert.equal(imageOf(server('s001')), images['rust-build']);
  assert.deepEqual(cmdOf(server('s001')), ['/work/pkg/bin/crate-mcp', '--stdio']);
  assert.equal(imageOf(server('s002')), images['dotnet-sdk']);
  assert.deepEqual(cmdOf(server('s002')), ['dotnet', '/work/pkg/.store/p.mcp/1.0.0/p.mcp/1.0.0/tools/net9.0/any/P.Mcp.dll']);
  assert.ok(server('s002').includes('DOTNET_ROLL_FORWARD=Major') && !server('s001').some((x) => x.startsWith('DOTNET_')));
  for (const id of ['s001', 's002']) {
    const a = server(id);
    assert.deepEqual([val(a, '--runtime'), val(a, '--user'), val(a, '--cap-drop'), a.includes('--read-only'), val(a, '--ip')], ['runsc', '65534:65534', 'ALL', true, NETS.run.target]);
    assert.ok(a.includes('type=volume,src=surface-' + s.box.dk.runId + `-${id}-work,dst=/work,readonly`) || a.some((x) => /dst=\/work,readonly$/.test(x)), 'the work volume is read-only for the server');
  }
  // Recorded: which image each step ran in, and the version the entry helper read.
  const rec = JSON.parse(readFileSync(join(s.out, 's001', 'record.json'), 'utf8'));
  assert.deepEqual(rec.install.steps.map((x) => [x.name, x.image ?? null]), [['install', null], ['entry', 'node24'], ['clean', null]]);
  assert.equal(rec.install.resolved_version, '0.4.1');
  assert.deepEqual(r.by('trace_summary', (x) => x.subject === 's001').map((x) => x.role).sort(), ['install', 'install', 'install', 'server']);
});

test('R-SBX-36 an MCP bundle is fetched and unpacked by our helper behind a proxy open to GitHub release assets only; it runs from the read-only volume in its runtime image, a uv bundle installs its dependencies through PyPI only', async () => {
  const url = 'https://github.com/o/n/releases/download/v1.0.0/n.mcpb';
  const sha = 'a'.repeat(64);
  const s = setup({ targets: [
    { id: 's001', repo: 'o/n', commit: SHA, launch: { kind: 'mcpb', url, sha256: sha, runtime: 'node', args: ['/work/pkg/server/index.js'], workdir: '.' } },
    { id: 's002', repo: 'o/n', commit: SHA, launch: { kind: 'mcpb', url, sha256: sha, runtime: 'python', args: ['/work/pkg/server/main.py'], pythonpath: ['server/lib'] } },
    { id: 's003', repo: 'o/n', commit: SHA, launch: { kind: 'mcpb', url, sha256: sha, runtime: 'binary', entry: 'server/n-linux' } },
    { id: 's004', repo: 'o/n', commit: SHA, launch: { kind: 'mcpb', url, sha256: sha, runtime: 'uv', console: 'n-mcp', extras: ['mcp'] } },
    { id: 's005', repo: 'o/n', commit: SHA, launch: { kind: 'npm', package: 'n', version: '1.2.3' } },
  ] });
  const r = await runMain(s);
  assert.equal(r.rc, 0);
  const images = D.loadImages(new URL('../images.json', import.meta.url).pathname);
  const runs = s.box.dk.calls.filter((a) => a[0] === 'run' || a[0] === 'create');
  const imageOf = (a) => a.find((x) => /@sha256:[0-9a-f]{64}$/.test(x));
  const cmdOf = (a) => a.slice(a.indexOf(imageOf(a)) + 1);
  const subject = (a) => (val(a, '--name') || '').match(/-(s00\d)-/)?.[1];
  const installs = (id) => runs.filter((a) => val(a, '--ip') === NETS.install.target && subject(a) === id);
  const npm = installs('s005');
  for (const id of ['s001', 's002', 's003', 's004']) {
    const f = installs(id)[0];
    assert.equal(imageOf(f), images.node24, `${id}: the fetch runs in our node image`);
    assert.deepEqual(cmdOf(f).slice(0, 5), ['node', '/opt/surface/sandbox/mcpb-fetch.mjs', url, sha, '/work/pkg']);
    for (const a of installs(id)) assert.deepEqual(hardening(a), hardening(npm[0]), `${id}: hardened like any install`);
  }
  assert.deepEqual(cmdOf(installs('s003')[0]).slice(5), ['--exec', 'server/n-linux']);
  assert.deepEqual(installs('s004').map(imageOf), [images.node24, images.python, images.python, images.python, images.python]);
  assert.deepEqual(cmdOf(installs('s004')[2]), ['python', '-I', '/opt/surface/sandbox/pyproject-reqs.py', '/work/pkg', '/work/lock/requirements.txt', 'mcp']);
  const proxies = runs.filter((a) => a.some((x) => x.endsWith('/sandbox/egress-proxy.mjs')));
  const hostsOf = (id) => proxies.filter((p) => subject(p) === id).map((p) => p.slice(p.findIndex((x) => x.endsWith('/sandbox/egress-proxy.mjs')) + 2));
  const gh = ['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com'];
  for (const id of ['s001', 's002', 's003']) assert.deepEqual(hostsOf(id), [gh]);
  assert.deepEqual(hostsOf('s004'), [[...gh, 'pypi.org', 'files.pythonhosted.org']]);
  const server = (id) => s.box.probes.find((a) => new RegExp(`-${id}-s`).test(val(a, '--name') || ''));
  assert.deepEqual([imageOf(server('s001')), cmdOf(server('s001')), val(server('s001'), '--workdir')], [images.node24, ['node', '/work/pkg/server/index.js'], '/work/pkg']);
  assert.deepEqual([imageOf(server('s002')), cmdOf(server('s002'))], [images.python, ['python', '/work/pkg/server/main.py']]);
  assert.ok(server('s002').includes('PYTHONPATH=/work/pkg/server/lib'));
  assert.deepEqual([imageOf(server('s003')), cmdOf(server('s003'))], [images['node24-build'], ['/work/pkg/server/n-linux']]);
  assert.deepEqual([imageOf(server('s004')), cmdOf(server('s004'))], [images.python, ['/work/venv/bin/n-mcp']]);
  for (const id of ['s001', 's002', 's003', 's004']) {
    const a = server(id);
    assert.deepEqual([val(a, '--runtime'), val(a, '--user'), val(a, '--cap-drop'), a.includes('--read-only'), val(a, '--ip')], ['runsc', '65534:65534', 'ALL', true, NETS.run.target]);
    assert.ok(a.some((x) => /dst=\/work,readonly$/.test(x)), `${id}: the bundle is read-only for the server`);
  }
  const rec = JSON.parse(readFileSync(join(s.out, 's001', 'record.json'), 'utf8'));
  assert.deepEqual(rec.install.steps[0].result, { ok: true, bytes: 1000, sha256: sha, files: 3, dirs: 1, links_skipped: 0, unpacked: 2000 }, 'the fetch answer is kept');
});

test('R-SBX-37 a launch plan\'s own server settings (a runtime roll-forward, a bundle\'s PYTHONPATH) sit on top of a target\'s env, never under it', async () => {
  // runEnv sits on top of the target's env: a target env name cannot replace PYTHONPATH or DOTNET_ROLL_FORWARD (and the
  // list validator refuses PYTHONPATH as a target env name anyway).
  const url = 'https://github.com/o/n/releases/download/v1.0.0/n.mcpb';
  const s = setup({ targets: [
    { id: 's001', repo: 'o/n', commit: SHA, launch: { kind: 'nuget', package: 'P.Mcp', version: '1.0.0', env: { DOTNET_ROLL_FORWARD: 'Disable' } } },
    { id: 's002', repo: 'o/n', commit: SHA, launch: { kind: 'mcpb', url, sha256: 'b'.repeat(64), runtime: 'python', args: ['/work/pkg/m.py'], pythonpath: ['.'] } },
  ] });
  const r = await runMain(s);
  assert.equal(r.rc, 0);
  const server = (id) => s.box.probes.filter((a) => new RegExp(`-${id}-s`).test(val(a, '--name') || ''));
  for (const a of server('s001')) { assert.ok(a.includes('DOTNET_ROLL_FORWARD=Major')); assert.ok(!a.includes('DOTNET_ROLL_FORWARD=Disable')); }
  assert.ok(server('s002')[0].includes('PYTHONPATH=/work/pkg'));
});

test('R-SBX-56 a caller\'s source reader goes into the tools volume as reader/, and the static step runs it on the subject\'s repository and commit; the shard records its id', async () => {
  const s = setup({ targets: [{ id: 's001', repo: 'o/n', commit: SHA, subdir: 'packages/server', launch: { kind: 'npm', package: 'n', version: '1.2.3' } }] });
  const dir = join(s.d, 'reader'); mkdirSync(dir);
  writeFileSync(join(dir, 'static-read.cjs'), 'module.exports = { readFiles: async () => ({}) };\n');
  const id = 'f'.repeat(64);
  const r = await runMain({ ...s, opts: { ...s.opts, reader: { dir, id, entry: 'static-read.cjs' } } });
  assert.equal(r.rc, 0);
  const runs = s.box.dk.calls.filter((a) => a[0] === 'run');
  const put = runs.find((a) => a.join(' ').includes('mkdir -p /opt/surface/reader && tar -x -f - --no-same-owner -C /opt/surface/reader'));
  assert.ok(put, 'the reader folder is unpacked into the tools volume');
  const stat = runs.find((a) => a.includes('/opt/surface/sandbox/static.mjs'));
  assert.deepEqual(stat.slice(stat.indexOf('/opt/surface/sandbox/static.mjs') + 1), ['--subdir', 'packages/server', '--reader', '/opt/surface/reader/static-read.cjs', '--repo', 'o/n', '--sha', SHA]);
  assert.ok(stat.some((x) => /^type=volume,src=[^,]+,dst=\/opt\/surface,readonly$/.test(x)), 'the tools volume, the reader in it, is read-only in the static step');
  assert.equal(r.shard.reader.id, id);
  assert.match(r.shard.reader.tar_sha256, /^[0-9a-f]{64}$/);
  // without the option, the static step is as before
  const s2 = setup();
  const r2 = await runMain(s2);
  assert.equal(r2.rc, 0);
  const stat2 = s2.box.dk.calls.filter((a) => a[0] === 'run').find((a) => a.includes('/opt/surface/sandbox/static.mjs'));
  assert.ok(!stat2.includes('--reader'));
  assert.equal(r2.shard.reader, null);
  // a reader option that does not hold its entry file is refused
  assert.throws(() => D.readerOption({ dir, id, entry: 'other.cjs' }), /reader option/);
  assert.throws(() => D.readerOption({ dir, id: 'x', entry: 'static-read.cjs' }), /reader option/);
  assert.equal(D.readerOption(null), null);
});
