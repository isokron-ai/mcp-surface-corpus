import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CASES, CANARY_PORT, evaluateCase } from '../src/selftest.mjs';
import { NETS } from '../src/sandbox-net.mjs';

const GW = NETS.run.gateway;
const fail = (o) => ({ n: 1, failed: 1, errno: 101, ...o });
const ok = (o) => ({ n: 1, failed: 0, errno: null, ...o });
const conn = (addr, port, o = {}) => fail({ family: 'AF_INET', addr, port, ...o });
const trace = (o = {}) => ({
  format: 'isokron-trace-summary/1', opens_outside: [], credential_paths: [], exec: [], privileged: [],
  process: { clones: 0, clone_failed: 0 },
  ...o,
  network: { sockets: [], raw_sockets: 0, connects: [], sends: [], binds: [], dns_names: [], ...(o.network || {}) },
});
const base = (o = {}) => ({ inspect: { runtime: 'runsc', mismatches: [], canaryInEnv: false }, container: { exit: 0, timed_out: false, oom_killed: false }, canaryHits: 0, dns: [], conns: [], drops: [], telemetryHasNonce: false, output: { bytes: 10 }, outputRecorded: true, report: null, ...o });

/** For every case, evidence of an attempt that was blocked and logged. */
const GOOD = {
  'direct-ip': () => base({ trace: trace({ network: { connects: [conn('1.1.1.1', 443), conn('8.8.8.8', 53), conn('140.82.112.3', 443)], sends: [conn('8.8.8.8', 53)] } }) }),
  'doh-ip': () => base({
    trace: trace({ network: { connects: [conn('1.1.1.1', 443, { n: 2, failed: 2 }), conn('8.8.8.8', 443), conn('9.9.9.9', 443), ok({ family: 'AF_INET', addr: NETS.run.netlog, port: 443 })] } }),
    dns: [{ qname: 'dns.google', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: NETS.run.target }],
    conns: [{ proto: 'tcp', port: 443, bytes: 517, sni: 'dns.google', from: NETS.run.target }],
  }),
  'raw-socket': () => base({ trace: trace({ network: { raw_sockets: 3, sockets: [fail({ family: 'AF_INET', type: 'SOCK_RAW', protocol: 'IPPROTO_TCP', raw: true, errno: 1 }), fail({ family: 'AF_INET', type: 'SOCK_RAW', protocol: 'IPPROTO_RAW', raw: true, errno: 1 }), fail({ family: 'AF_PACKET', type: 'SOCK_RAW', protocol: '0x300', raw: true, errno: 1 })] } }) }),
  ipv6: () => base({ trace: trace({ network: { connects: [fail({ family: 'AF_INET6', addr: '2606:4700:4700::1111', port: 443 }), fail({ family: 'AF_INET6', addr: 'fe80::1', port: 443, errno: 4 })], sends: [fail({ family: 'AF_INET6', addr: '2001:4860:4860::8888', port: 53 })] } }) }),
  icmp: () => base({
    trace: trace({ network: { sockets: [ok({ family: 'AF_INET', type: 'SOCK_DGRAM', protocol: 'IPPROTO_ICMP', n: 2 }), fail({ family: 'AF_INET', type: 'SOCK_RAW', protocol: 'IPPROTO_ICMP', raw: true, n: 2, failed: 2, errno: 1 })], sends: [conn('1.1.1.1', 0), ok({ family: 'AF_INET', addr: GW, port: 0 })] } }),
    drops: [{ chain: 'input', family: 4, proto: 'ICMP', src: NETS.run.target, dst: GW, dpt: null, icmp_type: 8, n: 1 }],
  }),
  'docker-host': () => base({
    trace: trace({ network: { connects: [ok({ family: 'AF_INET', addr: NETS.run.netlog, port: 2375 }), conn(GW, 2375, { errno: 4 }), conn(GW, 2376, { errno: 4 }), conn(GW, CANARY_PORT, { errno: 4 }), fail({ family: 'AF_UNIX', addr: '/var/run/docker.sock', port: null, errno: 2 })] } }),
    dns: [{ qname: 'host.docker.internal', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: NETS.run.target }],
    conns: [{ proto: 'tcp', port: 2375, bytes: 60, http: { method: 'GET', host: 'host.docker.internal', path: '/version' } }],
    drops: [{ chain: 'input', family: 4, proto: 'TCP', src: NETS.run.target, dst: GW, dpt: 2375, n: 3 }, { chain: 'input', family: 4, proto: 'TCP', src: NETS.run.target, dst: GW, dpt: CANARY_PORT, n: 3 }],
  }),
  metadata: () => base({
    trace: trace({ network: { connects: [conn('169.254.169.254', 80, { n: 2, failed: 2 }), conn('168.63.129.16', 80)] } }),
    dns: [{ qname: 'metadata.google.internal', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: NETS.run.target }],
    conns: [{ proto: 'tcp', port: 80, bytes: 90, http: { method: 'GET', host: 'metadata.google.internal', path: '/computeMetadata/v1/' } }],
  }),
  'env-token': () => base({ trace: trace({ credential_paths: [ok({ path: '/proc/self/environ', op: 'read' }), ok({ path: '/proc/1/environ', op: 'read' })] }), report: { case: 'env-token', result: { canary_in_env: 0, token_names: [], files: [{ ok: true, canary: 0 }] } } }),
  'write-outside': () => base({ trace: trace({ opens_outside: ['/etc/isk-1', '/usr/local/isk-1', '/opt/surface/forged-1.json', '/isk-1', '/proc/sys/kernel/hostname'].map((path) => fail({ path, op: 'write', call: 'openat', errno: 30 })), privileged: [fail({ name: 'mount', errno: 1 })] }) }),
  'fork-bomb': () => base({ trace: trace({ process: { clones: 512, clone_failed: 3 } }), report: { result: { bomb: { forked: 509, error: 'EAGAIN' } } } }),
  'output-forgery': () => base({ trace: trace({ opens_outside: [fail({ path: '/opt/surface/telemetry.jsonl', op: 'write', errno: 30 })] }), output: { bytes: 700 } }),
};

test('every case of the hostile target has a verdict, and the two lists agree', () => {
  assert.deepEqual(Object.keys(GOOD).sort(), [...CASES].sort());
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  const block = /CASES = \{([\s\S]*?)\n\}/.exec(py)[1];
  assert.deepEqual([...block.matchAll(/"([a-z0-9-]+)":/g)].map((m) => m[1]).sort(), [...CASES].sort());
  assert.throws(() => evaluateCase('nope', {}), /no such self test case/);
});

test('blocked and logged: every case passes on the evidence of a working sandbox', () => {
  for (const c of CASES) {
    const v = evaluateCase(c, GOOD[c]());
    assert.deepEqual([c, v.blocked, v.logged, v.pass], [c, true, true, true], `${c}: ${v.detail}\n${v.evidence.join('\n')}`);
    assert.ok(v.evidence.length >= 2 && v.evidence.every((e) => typeof e === 'string' && e.length <= 200));
  }
});

test('nothing tried proves nothing: an empty trace fails every case', () => {
  for (const c of CASES) {
    const v = evaluateCase(c, base({ trace: trace(), output: { bytes: 0 }, outputRecorded: false }));
    assert.equal(v.pass, false, c);
  }
});

test('not the declared sandbox, or no trace: never a pass', () => {
  for (const c of CASES) {
    assert.equal(evaluateCase(c, { ...GOOD[c](), inspect: { runtime: 'runc', mismatches: [] } }).blocked, false, `${c} under runc`);
    assert.equal(evaluateCase(c, { ...GOOD[c](), inspect: { runtime: 'runsc', mismatches: ['the root filesystem is not read-only'] } }).pass, false, `${c} with other settings`);
    assert.equal(evaluateCase(c, { ...GOOD[c](), inspect: null }).pass, false, `${c} without inspect`);
    const v = evaluateCase(c, { ...GOOD[c](), trace: null });
    assert.equal(v.logged, false, `${c} without a trace`);
    assert.match(v.detail, /no syscall trace/);
  }
});

test('got through: a connection, a socket, a write, a reply, a token, a forged line', () => {
  const g = (c, f) => { const ev = GOOD[c](); f(ev); return evaluateCase(c, ev); };
  assert.equal(g('direct-ip', (ev) => { ev.trace.network.connects[0] = ok({ family: 'AF_INET', addr: '1.1.1.1', port: 443 }); }).blocked, false);
  assert.equal(g('direct-ip', (ev) => { ev.trace.network.connects[0].errno = 115; }).blocked, false, '"in progress" is not a refusal');
  assert.equal(g('doh-ip', (ev) => { ev.report = { result: { attempts: [{ ok: true, tls: true, received: 120 }] } }; }).blocked, false, 'the target says it got an answer');
  assert.equal(g('doh-ip', (ev) => { ev.dns[0].answer = 'empty'; }).blocked, false, 'the name did not go to the sinkhole');
  assert.equal(g('doh-ip', (ev) => { ev.conns = []; }).logged, false);
  assert.equal(g('raw-socket', (ev) => { ev.trace.network.sockets[2] = ok({ family: 'AF_PACKET', type: 'SOCK_RAW', protocol: '0x300', raw: true }); }).blocked, false);
  assert.equal(g('ipv6', (ev) => { ev.trace.network.connects[0] = ok({ family: 'AF_INET6', addr: '2606:4700:4700::1111', port: 443 }); }).blocked, false);
  assert.equal(g('icmp', (ev) => { ev.drops = []; }).pass, false, 'an echo to the host that left the container must show up as a drop');
  assert.equal(g('icmp', (ev) => { ev.report = { result: { attempts: [{ ok: true, sent: true, received: 24 }] } }; }).blocked, false);
  assert.equal(g('docker-host', (ev) => { ev.canaryHits = 1; }).blocked, false, 'the host listener was reached');
  assert.equal(g('docker-host', (ev) => { ev.trace.network.connects[4] = ok({ family: 'AF_UNIX', addr: '/var/run/docker.sock', port: null }); }).blocked, false, 'the Docker socket was there');
  assert.equal(g('docker-host', (ev) => { ev.drops = []; }).logged, false);
  assert.equal(g('metadata', (ev) => { ev.trace.network.connects[1] = ok({ family: 'AF_INET', addr: '168.63.129.16', port: 80 }); }).blocked, false);
  assert.equal(g('metadata', (ev) => { ev.report = { result: { attempts: [{ ok: true, connected: true, received: 300 }] } }; }).blocked, false);
  assert.equal(g('env-token', (ev) => { ev.inspect.canaryInEnv = true; }).blocked, false);
  assert.equal(g('env-token', (ev) => { ev.report.result.token_names = ['GITHUB_TOKEN']; }).blocked, false, 'the target says it saw a token name');
  assert.equal(g('env-token', (ev) => { ev.trace.credential_paths = []; }).logged, false);
  assert.equal(g('write-outside', (ev) => { ev.trace.opens_outside[0] = ok({ path: '/etc/isk-1', op: 'write' }); }).blocked, false);
  assert.equal(g('write-outside', (ev) => { ev.trace.privileged = [ok({ name: 'mount' })]; }).blocked, false);
  assert.equal(g('write-outside', (ev) => { ev.report = { result: { attempts: [{ path: '/etc/isk-1', ok: true, written: true }] } }; }).blocked, false);
  assert.equal(g('write-outside', (ev) => { ev.report = { result: { inside: [{ path: '/work/inside-1', ok: true, written: true }] } }; }).blocked, true, 'writing in the work folder is allowed');
  assert.equal(g('fork-bomb', (ev) => { ev.trace.process = { clones: 1500, clone_failed: 0 }; }).blocked, false);
  assert.equal(g('fork-bomb', (ev) => { ev.report.result.bomb.forked = 1500; }).blocked, false);
  assert.equal(g('output-forgery', (ev) => { ev.telemetryHasNonce = true; }).blocked, false);
  assert.equal(g('output-forgery', (ev) => { ev.outputRecorded = false; }).logged, false);
});

test('the target\'s report cannot make a case pass', () => {
  for (const c of CASES) {
    const v = evaluateCase(c, base({ trace: trace(), report: { case: c, result: { attempts: [{ ok: false, error: 'ENETUNREACH' }], blocked: true, logged: true, pass: true } } }));
    assert.equal(v.pass, false, c);
  }
});
