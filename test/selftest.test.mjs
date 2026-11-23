import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { CASES, evaluateCase } from '../src/selftest.mjs';
import { GOOD, base, trace, ok } from './selftest-fixtures.mjs';

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

test('an outside address counts as blocked only on a definite refusal, never on a cut-short call', () => {
  const g = (c, f) => { const ev = GOOD[c](); f(ev); return evaluateCase(c, ev); };
  for (const errno of [4, 512, 110]) {
    assert.equal(g('direct-ip', (ev) => { ev.trace.network.connects[0].errno = errno; }).blocked, false, `direct-ip errno ${errno}`);
    assert.equal(g('metadata', (ev) => { ev.trace.network.connects[1].errno = errno; }).blocked, false, `metadata errno ${errno}`);
    assert.equal(g('ipv6', (ev) => { ev.trace.network.connects[1].errno = errno; }).blocked, false, `ipv6 errno ${errno}`);
    assert.equal(g('doh-ip', (ev) => { ev.trace.network.connects[2].errno = errno; }).blocked, false, `doh-ip errno ${errno}`);
  }
  for (const errno of [1, 13, 101, 111, 113]) assert.equal(g('direct-ip', (ev) => { for (const e of ev.trace.network.connects) e.errno = errno; }).blocked, true, `errno ${errno} is a refusal`);
  assert.equal(g('docker-host', () => {}).blocked, true, 'the host address: a timeout plus the drop log and the listener decide');
});

test('a trace a target may have shaped, or one cut short, cannot carry a verdict', () => {
  for (const c of CASES) {
    for (const bad of [{ injection_suspected: true, headerless_lines: 2, broken_lines: 1 }, { truncated: true }, { omitted_ok: { connects: 1 } }]) {
      const ev = GOOD[c]();
      Object.assign(ev.trace, bad);
      const v = evaluateCase(c, ev);
      assert.equal(v.pass, false, `${c} ${JSON.stringify(bad)}`);
      assert.equal(v.blocked, false);
    }
  }
});
