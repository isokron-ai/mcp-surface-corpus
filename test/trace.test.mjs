import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseStraceLine, splitArgs, unquote, sockaddr, summarizeTrace, summarizeTraceFile, SUMMARY_FORMAT } from '../src/trace-summary.mjs';
import { loadRunscConfig } from '../src/runsc.mjs';
import { buildQuery } from '../src/dns.mjs';

const cfg = loadRunscConfig();
// Go's %q of bytes, the way runsc prints a buffer.
const goq = (buf) => `"${[...buf].map((b) => (b === 0x22 ? '\\"' : b === 0x5c ? '\\\\' : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, '0')}`)).join('')}"`;
let n = 0;
const L = (tid, comm, phase, c, ret = null) => `I1121 10:00:${String(n++ % 60).padStart(2, '0')}.123456       1 strace.go:${phase === 'E' ? 567 : 605}] [${String(tid).padStart(4)}:${String(tid).padStart(4)}] ${comm} ${phase} ${c}${ret === null ? '' : ` = ${ret}`}`;
const call = (tid, comm, c, ret) => [L(tid, comm, 'E', c), L(tid, comm, 'X', c, ret)];

test('one trace line: task, command, phase, call, arguments, result', () => {
  const r = parseStraceLine(L(7, 'python3', 'X', 'openat(AT_FDCWD /work, 0x7f00 /etc/x, O_WRONLY|O_CREAT|O_TRUNC, 0o644)', '0x0 errno=30 (read-only file system) (11.2µs)'));
  assert.deepEqual([r.pid, r.tid, r.comm, r.phase, r.name], [7, 7, 'python3', 'X', 'openat']);
  assert.deepEqual(r.args, ['AT_FDCWD /work', '0x7f00 /etc/x', 'O_WRONLY|O_CREAT|O_TRUNC', '0o644']);
  assert.deepEqual(r.ret, { value: 0, errno: 30, error: 'read-only file system' });
  assert.equal(parseStraceLine('I1121 10:00:00.000000       1 loader.go:1] Starting gVisor...'), null);
  assert.equal(parseStraceLine('garbage'), null);
  assert.deepEqual(splitArgs('a, {Family: AF_INET, Addr: 1.1.1.1, Port: 443}, "x, y", 3'), ['a', '{Family: AF_INET, Addr: 1.1.1.1, Port: 443}', '"x, y"', '3']);
});

test('strings and addresses as runsc prints them', () => {
  assert.equal(unquote('a\\x00b\\n\\"c\\\\').toString('latin1'), 'a\x00b\n"c\\');
  assert.deepEqual(sockaddr('0x7f00 {Family: AF_INET, Addr: 1.1.1.1, Port: 443}'), { family: 'AF_INET', addr: '1.1.1.1', port: 443 });
  assert.deepEqual(sockaddr('0x7f00 {Family: AF_INET6, Addr: 2606:4700:4700::1111, Port: 443}'), { family: 'AF_INET6', addr: '2606:4700:4700::1111', port: 443 });
  assert.deepEqual(sockaddr('0x7f00 {Family: AF_UNIX, Addr: "/var/run/x.sock"}'), { family: 'AF_UNIX', addr: '/var/run/x.sock', port: null });
  assert.equal(sockaddr('0x0'), null);
});

const dnsq = buildQuery('dns.google', 1);
const TRACE = [
  ...call(1, 'python3', 'execve(0x7f00 /usr/local/bin/python3, 0x7f10 ["python3", "/opt/surface/selftest/hostile.py"], 0x7f20 [])', '0x0 (1ms)'),
  ...call(1, 'python3', 'openat(AT_FDCWD /work, 0x7f00 /usr/lib/python3.13/os.py, O_RDONLY|O_CLOEXEC, 0o0)', '0x3 (3µs)'),
  ...call(1, 'python3', 'openat(AT_FDCWD /work, 0x7f00 /proc/self/environ, O_RDONLY|O_CLOEXEC, 0o0)', '0x4 (3µs)'),
  ...call(1, 'python3', 'openat(AT_FDCWD /work, 0x7f00 /proc/1/environ, O_RDONLY, 0o0)', '0x0 errno=13 (permission denied) (3µs)'),
  ...call(1, 'python3', 'openat(AT_FDCWD /work, 0x7f00 /etc/x, O_WRONLY|O_CREAT|O_TRUNC, 0o644)', '0x0 errno=30 (read-only file system) (3µs)'),
  ...call(1, 'python3', 'openat(AT_FDCWD /work, 0x7f00 result.json, O_WRONLY|O_CREAT|O_TRUNC, 0o644)', '0x5 (3µs)'),
  ...call(1, 'python3', 'openat(0x3 /opt/surface, 0x7f00 forged.json, O_WRONLY|O_CREAT, 0o644)', '0x0 errno=30 (read-only file system) (3µs)'),
  ...call(1, 'python3', 'mkdirat(AT_FDCWD /work, 0x7f00 /usr/local/x, 0o755)', '0x0 errno=30 (read-only file system) (3µs)'),
  ...call(1, 'python3', 'openat(AT_FDCWD /work, 0x7f00 /root/.kube/config, O_RDONLY, 0o0)', '0x0 errno=2 (no such file or directory) (3µs)'),
  ...call(1, 'python3', 'socket(AF_INET, SOCK_RAW|SOCK_CLOEXEC, IPPROTO_ICMP)', '0x0 errno=1 (operation not permitted) (3µs)'),
  ...call(1, 'python3', 'socket(AF_PACKET, SOCK_RAW, 0x300)', '0x0 errno=97 (address family not supported by protocol) (3µs)'),
  ...call(1, 'python3', 'socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, IPPROTO_IP)', '0x6 (3µs)'),
  ...call(1, 'python3', 'connect(0x6 socket:[3], 0x7f00 {Family: AF_INET, Addr: 1.1.1.1, Port: 443}, 0x10)', '0x0 errno=101 (network is unreachable) (3µs)'),
  ...call(1, 'python3', 'connect(0x6 socket:[3], 0x7f00 {Family: AF_INET, Addr: 1.1.1.1, Port: 443}, 0x10)', '0x0 errno=101 (network is unreachable) (3µs)'),
  ...call(1, 'python3', 'connect(0x6 socket:[3], 0x7f00 {Family: AF_INET, Addr: 10.213.53.2, Port: 443}, 0x10)', '0x0 (3µs)'),
  ...call(1, 'python3', 'connect(0x7 socket:[4], 0x7f00 {Family: AF_INET6, Addr: 2606:4700:4700::1111, Port: 443}, 0x1c)', '0x0 errno=101 (network is unreachable) (3µs)'),
  ...call(1, 'python3', `sendto(0x8 socket:[5], 0x7f00 ${goq(dnsq)}, 0x${dnsq.length.toString(16)}, 0x0, 0x7f10 {Family: AF_INET, Addr: 10.213.53.2, Port: 53}, 0x10)`, `0x${dnsq.length.toString(16)} (3µs)`),
  ...call(1, 'python3', 'mount(0x0, 0x7f00 /mnt, 0x7f10 tmpfs, 0x0, 0x0)', '0x0 errno=1 (operation not permitted) (3µs)'),
  ...call(2, 'python3', 'clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0x0, 0x0, 0x7f00, 0x0)', '0x3 (3µs)'),
  ...call(2, 'python3', 'clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, 0x0, 0x0, 0x7f00, 0x0)', '0x0 errno=11 (resource temporarily unavailable) (3µs)'),
  L(3, 'sleep', 'E', 'execve(0x7f00 /bin/sleep, 0x7f10 ["sleep", "30"], 0x7f20 [])'),
].join('\n');

test('the summary: counts by family, opens outside the expected paths, credential reads, programs, the network', () => {
  const s = summarizeTrace(TRACE, cfg);
  assert.equal(s.format, SUMMARY_FORMAT);
  assert.equal(s.counts.file, 8);
  assert.equal(s.counts.network, 8);
  assert.equal(s.counts.process, 4, 'two execs (one still pending at the end) and two clones');
  assert.equal(s.counts.privileged, 1);
  assert.equal(s.failed.file, 5);
  const outside = Object.fromEntries(s.opens_outside.map((o) => [`${o.op} ${o.path}`, o]));
  assert.deepEqual(Object.keys(outside).sort(), ['read /proc/1/environ', 'read /root/.kube/config', 'write /etc/x', 'write /opt/surface/forged.json', 'write /usr/local/x']);
  assert.ok(!outside['read /proc/self/environ'], 'a process reading its own environment is expected');
  assert.equal(outside['write /etc/x'].failed, 1);
  assert.equal(outside['write /etc/x'].errno, 30);
  assert.ok(!outside['write /work/result.json'], 'writing in the work folder is expected');
  assert.deepEqual(s.credential_paths.map((c) => c.path).sort(), ['/proc/1/environ', '/proc/self/environ', '/root/.kube/config']);
  assert.deepEqual(s.exec.map((e) => e.path).sort(), ['/bin/sleep', '/usr/local/bin/python3']);
  assert.deepEqual(s.process, { clones: 2, clone_failed: 1 });
  assert.equal(s.network.raw_sockets, 2);
  assert.ok(s.network.sockets.filter((x) => x.raw).every((x) => x.failed === x.n));
  const c = s.network.connects.find((x) => x.addr === '1.1.1.1');
  assert.deepEqual([c.family, c.port, c.n, c.failed, c.errno], ['AF_INET', 443, 2, 2, 101]);
  assert.equal(s.network.connects.find((x) => x.addr === '10.213.53.2').failed, 0);
  assert.equal(s.network.connects.find((x) => x.family === 'AF_INET6').errno, 101);
  assert.deepEqual(s.network.dns_names.map((d) => `${d.name} ${d.type}`), ['dns.google A']);
  assert.deepEqual(s.privileged.map((p) => [p.name, p.failed]), [['mount', 1]]);
});

test('every list is capped and every string is cut: the trace is the target\'s doing', () => {
  const lines = [];
  for (let i = 0; i < 30; i++) lines.push(...call(1, 'x', `openat(AT_FDCWD /, 0x7f00 /srvx/${i}/${'a'.repeat(300)}, O_RDONLY, 0o0)`, '0x0 errno=2 (no such file or directory) (1µs)'));
  const s = summarizeTrace(lines.join('\n'), cfg, { cap: 5 });
  assert.equal(s.opens_outside.length, 5);
  assert.ok(s.opens_outside.every((o) => o.path.length <= 200));
  assert.ok(s.omitted.opens_outside >= 1, 'what does not fit is counted');
});

test('a trace file is streamed; a missing one gives null', async () => {
  const d = mkdtempSync(join(tmpdir(), 'trace-'));
  writeFileSync(join(d, 'a.log'), `${TRACE}\n`);
  const s = await summarizeTraceFile(join(d, 'a.log'), cfg);
  assert.equal(s.counts.network, 8);
  assert.equal(s.truncated, false);
  assert.ok(s.bytes > 1000);
  const t = await summarizeTraceFile(join(d, 'a.log'), cfg, { maxBytes: 600 });
  assert.equal(t.truncated, true);
  assert.equal(await summarizeTraceFile(join(d, 'missing.log'), cfg), null);
});

test('R-SBX-04 a file name with a line break cannot pass for a trace line unnoticed', () => {
  // runsc prints paths unquoted: the name below ends the real line and starts lines of its own.
  const forged = `x\nI1121 10:00:01.000000       1 strace.go:605] [   7:   7] python3 X connect(0x3, 0x7f00 {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 0x10) = 0x0 (1ms)\n`;
  const lines = [L(7, 'python3', 'E', `openat(AT_FDCWD /work, 0x7f00 ${forged}, O_RDONLY, 0o0)`), L(7, 'python3', 'X', 'openat(AT_FDCWD /work, 0x7f00 y, O_RDONLY, 0o0)', '0x3 (1µs)')];
  const s = summarizeTrace(lines.join('\n'), cfg);
  assert.equal(s.target_influenced, true);
  assert.equal(s.broken_lines, 1, 'the real line, cut short by the name, does not close');
  assert.ok(s.headerless_lines >= 1, 'what followed the forged line has no header');
  assert.equal(s.injection_suspected, true);
  // A line without runsc's header is never a call.
  assert.equal(parseStraceLine('[   7:   7] python3 X connect(0x3, 0x7f00 {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 0x10) = 0x0'), null);
  const clean = summarizeTrace(TRACE, cfg);
  assert.deepEqual([clean.injection_suspected, clean.headerless_lines, clean.broken_lines, clean.target_influenced], [false, 0, 0, true]);
});

test('R-SBX-04 a flood of refused calls cannot push out the one that worked', () => {
  const lines = [];
  for (let i = 0; i < 200; i++) lines.push(...call(1, 'x', `connect(0x3, 0x7f00 {Family: AF_INET, Addr: 10.0.${i >> 8}.${i & 255}, Port: 443}, 0x10)`, '0x0 errno=101 (network is unreachable) (1µs)'));
  lines.push(...call(1, 'x', 'connect(0x3, 0x7f00 {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 0x10)', '0x0 (1ms)'));
  const s = summarizeTrace(lines.join('\n'), cfg, { cap: 5 });
  assert.equal(s.network.connects.length, 5);
  assert.deepEqual([s.network.connects[0].addr, s.network.connects[0].failed], ['1.2.3.4', 0], 'the connection that worked comes first');
  assert.ok(s.omitted.connects > 0);
});

test('R-CI-06 runsc\'s own headerless block as the sandbox starts, before any call, is not taken for forgery', () => {
  const boot = summarizeTrace(`{\n  "ociVersion": "1.0.0"\n}\n${TRACE}`, cfg);
  assert.deepEqual([boot.injection_suspected, boot.headerless_before_calls, boot.headerless_lines], [false, 3, 0]);
  const late = summarizeTrace(`${TRACE}\n{\n}`, cfg);
  assert.equal(late.injection_suspected, true, 'after the first call it is');
});
