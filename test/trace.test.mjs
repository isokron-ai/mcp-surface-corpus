import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseStraceLine, splitArgs, unquote, sockaddr, summarizeTrace, summarizeTraceFile, SUMMARY_FORMAT } from '../src/trace-summary.mjs';
import { loadRunscConfig } from '../src/runsc.mjs';
import { traceProblems } from '../src/selftest.mjs';
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

// runsc's boot timing table as a GitHub runner's trace had it (26 Nov 2026, gVisor 20261116.0): one
// log message, a header line, rows without headers, an end line (gVisor pkg/timing Timer.Log).
const TIMING = readFileSync(new URL('./runsc-boot-timing.txt', import.meta.url), 'utf8').split('\n').filter(Boolean);
const TIMING_ROWS = TIMING.length - 1; // all but the header line have no header
const BOOT = [
  'I1126 03:36:11.432654       1 cli.go:282] **************** gVisor ****************',
  'I1126 03:36:11.450739       1 loader.go:1562] Process should have started...',
  'I1126 03:36:11.450808       1 timing.go:551] Timer for runsc boot: Ended.',
];
const TL = TRACE.split('\n'); // the trace above, by line
const FIRST = call(1, 'docker-init', 'clone(CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|0x11, 0x0, 0x0, 0x4bf650, 0x0)', '2 (0x2) (3.262534ms)');

test('R-CI-09 runsc\'s boot timing table is runsc\'s whether it comes before or after the target\'s first calls', () => {
  // runsc starts the kernel, then logs the table: on a busy runner the target's first calls come first.
  const usual = summarizeTrace([...BOOT, ...TIMING, ...FIRST, ...TL].join('\n'), cfg);
  const late = summarizeTrace([...BOOT, ...FIRST, ...TIMING, ...TL].join('\n'), cfg);
  const mid = summarizeTrace([...BOOT, ...FIRST, ...TL.slice(0, 6), ...TIMING, '', ...TL.slice(6)].join('\n'), cfg);
  for (const [s, where] of [[usual, 'before_calls'], [late, 'after_calls'], [mid, 'after_calls']]) {
    assert.deepEqual([s.injection_suspected, s.headerless_lines, s.headerless_before_calls, s.broken_lines, s.runsc_timing_block], [false, 0, 0, 0, where], where);
    assert.deepEqual(s.counts, usual.counts, 'the table holds no calls');
  }
  assert.deepEqual(traceProblems(late), [], 'a trace with the table after the first call can carry a verdict');
  // Without the table's header line its rows are lines like any other: after a call, flagged (the 26 Nov failure).
  const rowsOnly = summarizeTrace([...BOOT, ...FIRST, ...TIMING.slice(1), ...TL].join('\n'), cfg);
  assert.deepEqual([rowsOnly.injection_suspected, rowsOnly.headerless_lines, rowsOnly.runsc_timing_block], [true, TIMING_ROWS, null]);
});

test('R-CI-09 only one whole timing table in runsc\'s form is passed over: every change to it is still flagged', () => {
  const at = (block, extra = []) => summarizeTrace([...BOOT, ...FIRST, ...block, ...extra, ...TL].join('\n'), cfg);
  const flagged = (s, why) => { assert.equal(s.injection_suspected, true, why); assert.ok(s.headerless_lines > 0, why); assert.ok(traceProblems(s).length > 0, why); };
  // Mutations of the form: each part of it is load-bearing.
  const head = TIMING[0]; const rows = TIMING.slice(1, -1); const end = TIMING[TIMING.length - 1];
  flagged(at([head.replace('timing.go:', 'strace.go:'), ...rows, end]), 'a header line from another file');
  flagged(at([head.replace(/^I/, 'W'), ...rows, end]), 'another log level');
  flagged(at([`${head} `, ...rows, end]), 'anything after the header');
  flagged(at([head, ...rows, `${end})`]), 'anything after the end line (the rest of a forged call line)');
  flagged(at([head, ...rows]), 'no end line');
  flagged(at([head, ...rows.slice(0, 5), 'x', ...rows.slice(5), end]), 'a line that is not a row');
  flagged(at([head, ...rows.slice(0, 5), rows[5].replace('\t', ' '), ...rows.slice(6), end]), 'a row without its tab');
  flagged(at([head, ...Array(1001).fill(rows[0]), end]), 'more rows than any boot has');
  // A second table, whichever comes first: only one is runsc's.
  const twice = at(TIMING, TIMING);
  flagged(twice, 'a second table');
  assert.equal(twice.headerless_lines, TIMING_ROWS, 'the second table\'s rows are counted');
  flagged(summarizeTrace([...BOOT, ...TIMING, ...FIRST, ...TIMING, ...TL].join('\n'), cfg), 'a second table after the first call');
  // A runsc line inside a table ends it: the table never hides one of runsc's lines, and that call is still read.
  const split = at([head, ...rows.slice(0, 3), ...call(1, 'python3', 'connect(0x3, 0x7f00 {Family: AF_INET, Addr: 1.2.3.4, Port: 443}, 0x10)', '0x0 (1ms)'), ...rows.slice(3), end]);
  flagged(split, 'a call inside the table');
  assert.ok(split.network.connects.some((c) => c.addr === '1.2.3.4' && c.failed === 0), 'the call is not hidden');
});

test('R-CI-09 a timing table forged through a file name is flagged', () => {
  // A name that closes the real line, then a whole table: the rest of the real line follows it.
  const name = `x)\n${TIMING.join('\n')}\n`;
  const forged = [L(7, 'python3', 'E', `unlink(0x7f00 ${name})`), L(7, 'python3', 'X', `unlink(0x7f00 ${name})`, '0x0 (1µs)')];
  for (const order of [[...BOOT, ...TIMING, ...FIRST, ...forged, ...TL], [...BOOT, ...FIRST, ...forged, ...TIMING, ...TL]]) {
    const s = summarizeTrace(order.join('\n'), cfg);
    assert.equal(s.injection_suspected, true);
    assert.ok(s.headerless_lines >= TIMING_ROWS, 'the forged table, or runsc\'s after it, counts');
  }
});

test('R-CASE-19 the trace summary lists the links a target made, and where they point', () => {
  const lines = [
    L(7, 'python3', 'X', 'symlinkat(0x7f00 /etc, AT_FDCWD /work, 0x7f01 /work/links-1/l01)', '0 (0x0) (3µs)'),
    L(7, 'python3', 'X', 'symlinkat(0x7f00 /var/run/docker.sock, 0x3 /work/links-1, 0x7f01 l09)', '0 (0x0) (3µs)'),
    L(7, 'python3', 'X', 'symlink(0x7f00 /work/..,0x7f01 /tmp/isk-up-1)'.replace(',0x', ', 0x'), '0 (0x0) (3µs)'),
    L(7, 'python3', 'X', 'linkat(AT_FDCWD /work, 0x7f00 /etc/passwd, AT_FDCWD /work, 0x7f01 /work/bomb/hard, 0x0)', '-1 errno=18 (cross-device link) (2µs)'),
  ];
  const s = summarizeTrace(lines.join('\n'), cfg);
  const got = s.links.map((l) => [l.kind, l.target, l.path, l.failed]).sort();
  assert.deepEqual(got, [['hard', '/etc/passwd', '/work/bomb/hard', 1], ['symlink', '/etc', '/work/links-1/l01', 0], ['symlink', '/var/run/docker.sock', '/work/links-1/l09', 0], ['symlink', '/work/..', '/tmp/isk-up-1', 0]].sort());
  assert.equal(s.omitted.links, 0);
  assert.equal(s.opens_outside.length, 0, 'a link made in the work folder is not a write outside it');
});
