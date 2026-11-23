import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadRunscConfig, validateRunscConfig, runscFlags, tracedSyscalls, syscallFamily, traceLogPath, debugLogPattern, runtimeAvailable, runtimeArgs, normArch, RunscConfigError, RUNTIME, FAMILIES } from '../src/runsc.mjs';

const cfg = loadRunscConfig();
const clone = () => JSON.parse(JSON.stringify(cfg));
const broken = (edit) => { const c = clone(); edit(c); return () => validateRunscConfig(c); };

test('gvisor.json pins one release, a sha512 per architecture, and the release\'s own bundle urls', () => {
  assert.match(cfg.release, /^\d{8}\.\d+$/);
  assert.equal(cfg.runtime, 'runsc');
  assert.equal(RUNTIME, 'runsc');
  for (const a of ['x86_64', 'aarch64']) {
    assert.match(cfg.bundles[a].sha512, /^[0-9a-f]{128}$/);
    assert.equal(cfg.bundles[a].url, `https://storage.googleapis.com/gvisor/releases/release/${cfg.release}/${a}/gvisor.tar.bz2`);
  }
  assert.notEqual(cfg.bundles.x86_64.sha512, cfg.bundles.aarch64.sha512);
});

test('the runtime flags: gVisor\'s own network stack, no raw sockets, the trace of every family, one log per container', () => {
  const f = runscFlags(cfg, 'x86_64');
  assert.deepEqual(f.slice(0, 5), ['--network=sandbox', '--net-raw=false', '--debug-command=boot', '--debug-log-format=text', '--strace']);
  const sys = f.find((x) => x.startsWith('--strace-syscalls=')).split('=')[1].split(',');
  for (const n of ['openat', 'execve', 'clone', 'socket', 'connect', 'sendto', 'mount', 'ptrace']) assert.ok(sys.includes(n), n);
  assert.ok(f.includes(`--strace-log-size=${cfg.strace.log_size}`));
  assert.equal(f.at(-1), '--debug-log=/var/log/isokron-runsc/%ID%.%COMMAND%.log');
  assert.equal(debugLogPattern(cfg), '/var/log/isokron-runsc/%ID%.%COMMAND%.log');
  assert.ok(!f.some((x) => /^--(debug|strace)$/.test(x) && x === '--debug'), 'no full debug log, only the trace');
  assert.ok(!f.some((x) => /--network=host|--net-raw=true|--TESTONLY/.test(x)));
  assert.deepEqual(runscFlags(cfg, 'amd64'), f, 'amd64 is x86_64');
});

test('on arm64 the calls it does not have are left out of the trace list', () => {
  const x = tracedSyscalls(cfg, 'x86_64'); const a = tracedSyscalls(cfg, 'aarch64');
  for (const n of cfg.strace.amd64_only) { assert.ok(x.includes(n), n); assert.ok(!a.includes(n), n); }
  assert.equal(x.length - a.length, cfg.strace.amd64_only.length);
  assert.equal(normArch('arm64'), 'aarch64');
  assert.throws(() => normArch('riscv64'), RunscConfigError);
});

test('each traced call is in exactly one family', () => {
  assert.equal(syscallFamily(cfg, 'openat'), 'file');
  assert.equal(syscallFamily(cfg, 'clone3'), 'process');
  assert.equal(syscallFamily(cfg, 'connect'), 'network');
  assert.equal(syscallFamily(cfg, 'mount'), 'privileged');
  assert.equal(syscallFamily(cfg, 'read'), 'other');
  const all = FAMILIES.flatMap((f) => cfg.strace.families[f]);
  assert.equal(new Set(all).size, all.length);
});

test('a config that would weaken the sandbox or blur the install is refused', () => {
  assert.throws(broken((c) => { c.flags['net-raw'] = 'true'; }), /net-raw/);
  assert.throws(broken((c) => { c.flags.network = 'host'; }), /network/);
  assert.throws(broken((c) => { c.flags.strace = 'true'; }), /strace block/);
  assert.throws(broken((c) => { c.flags.debug = 'true'; }), /strace block/);
  assert.throws(broken((c) => { c.flags['x y'] = '1'; }), /not plain/);
  assert.throws(broken((c) => { c.flags.platform = 'a b'; }), /not plain/);
  assert.throws(broken((c) => { c.bundles.x86_64.sha512 = 'abc'; }), /sha512/);
  assert.throws(broken((c) => { c.bundles.aarch64.url = 'https://example.com/gvisor.tar.bz2'; }), /url/);
  assert.throws(broken((c) => { c.release = 'latest'; }), /release/);
  assert.throws(broken((c) => { c.runtime = 'runc'; }), /runtime/);
  assert.throws(broken((c) => { c.log_dir = '/var/log/../tmp'; }), /log_dir/);
  assert.throws(broken((c) => { c.strace.families.file.push('connect'); }), /two families/);
  assert.throws(broken((c) => { c.strace.families.extra = ['read']; }), /unknown syscall family/);
  assert.throws(broken((c) => { c.strace.families.network = []; }), /empty/);
  assert.throws(broken((c) => { c.strace.amd64_only.push('read'); }), /amd64_only/);
  assert.throws(broken((c) => { c.strace.log_size = 1e6; }), /log_size/);
  assert.throws(broken((c) => { c.summary.credential.push('('); }), /credential/);
  assert.throws(() => validateRunscConfig(null), /not an object/);
});

test('the trace log of a container is named by its full id only', () => {
  const id = 'a'.repeat(64);
  assert.equal(traceLogPath(cfg, id), `/var/log/isokron-runsc/${id}.boot.log`);
  for (const bad of ['../../etc/passwd', 'a'.repeat(63), `${'a'.repeat(64)}/x`, 'A'.repeat(64)]) assert.throws(() => traceLogPath(cfg, bad), /container id/);
});

test('whether the daemon has the runtime: read from its runtimes, never assumed', () => {
  const j = JSON.stringify({ 'io.containerd.runc.v2': { path: 'runc' }, runc: { path: 'runc' }, runsc: { path: '/usr/local/lib/isokron-gvisor/20261116.0/runsc', runtimeArgs: ['--network=sandbox', '--net-raw=false'] } });
  assert.equal(runtimeAvailable(j), true);
  assert.deepEqual(runtimeArgs(j), ['--network=sandbox', '--net-raw=false']);
  assert.equal(runtimeAvailable(JSON.stringify({ runc: { path: 'runc' } })), false);
  for (const bad of ['', 'null', 'not json', '[]', '"runsc"']) assert.equal(runtimeAvailable(bad), false, bad);
  assert.deepEqual(runtimeArgs('{"runsc":{"path":"x"}}'), []);
});

test('the install script and the summary read the same file', () => {
  const sh = readFileSync(new URL('../scripts/install-runsc.sh', import.meta.url), 'utf8');
  assert.match(sh, /gvisor\.json|runsc-plan\.mjs/);
});
