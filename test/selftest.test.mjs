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

test('R-SBX-08 an outside address counts as blocked only on a definite refusal, never on a cut-short call', () => {
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

test('R-SBX-04 a trace a target may have shaped, or one cut short, cannot carry a verdict', () => {
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

/**
 * One regression test per hostile case (REGRESSIONS.md R-CASE-*): on a working sandbox's evidence the
 * case is blocked and logged, and on evidence that the attempt got through it is not.
 */
function caseTest(name, c, gotThrough) {
  test(name, () => {
    const good = evaluateCase(c, GOOD[c]());
    assert.deepEqual([good.blocked, good.logged, good.pass], [true, true, true], good.detail);
    const ev = GOOD[c]();
    gotThrough(ev);
    const bad = evaluateCase(c, ev);
    assert.equal(bad.pass, false, `${c} must fail when the attempt got through`);
  });
}
caseTest('R-CASE-01 direct-ip: a connection to an outside address by IP is refused and traced', 'direct-ip', (ev) => { ev.trace.network.connects[0] = ok({ family: 'AF_INET', addr: '1.1.1.1', port: 443 }); });
caseTest('R-CASE-02 doh-ip: DNS over HTTPS by address or by name reaches no resolver, and is logged', 'doh-ip', (ev) => { ev.dns[0].answer = 'empty'; });
caseTest('R-CASE-03 raw-socket: no raw or packet socket opens', 'raw-socket', (ev) => { ev.trace.network.sockets[2] = ok({ family: 'AF_PACKET', type: 'SOCK_RAW', protocol: '0x300', raw: true }); });
caseTest('R-CASE-04 ipv6: nothing gets out over IPv6', 'ipv6', (ev) => { ev.trace.network.connects[0] = ok({ family: 'AF_INET6', addr: '2606:4700:4700::1111', port: 443 }); });
caseTest('R-CASE-05 icmp: no echo leaves the sandbox network, and one to the host is dropped and logged', 'icmp', (ev) => { ev.drops = []; });
caseTest('R-CASE-06 docker-host: the host, its Docker API and its sockets are out of reach', 'docker-host', (ev) => { ev.canaryHits = 1; });
caseTest('R-CASE-07 metadata: no cloud metadata or host agent address answers', 'metadata', (ev) => { ev.trace.network.connects[1] = ok({ family: 'AF_INET', addr: '168.63.129.16', port: 80 }); });
caseTest('R-CASE-08 env-token: no runner or Actions token reaches the target', 'env-token', (ev) => { ev.inspect.canaryInEnv = true; });
caseTest('R-CASE-09 write-outside: nothing is written outside the work folder and /tmp', 'write-outside', (ev) => { ev.trace.opens_outside[0] = ok({ path: '/etc/isk-1', op: 'write' }); });
caseTest('R-CASE-10 fork-bomb: the process limit refuses forks below the limit', 'fork-bomb', (ev) => { ev.trace.process = { clones: 1500, clone_failed: 0 }; });
caseTest('R-CASE-11 output-forgery: forged results and telemetry stay target output', 'output-forgery', (ev) => { ev.telemetryHasNonce = true; });

// The install network (node24-build image, HTTPS_PROXY to the egress proxy that allows the registry on 443 only).
const allow = (host, port) => ({ host, port, allowed: true, up: 10, down: 10, ms: 5 });
caseTest('R-CASE-12 install-proxy-host: the proxy refuses a CONNECT to a host not on its allowlist, and plain HTTP, and logs each', 'install-proxy-host', (ev) => { ev.egress[0] = allow('example.com', 443); });
caseTest('R-CASE-13 install-proxy-ip: the proxy refuses a CONNECT to an IP literal and logs it', 'install-proxy-ip', (ev) => { ev.egress.push(allow('1.1.1.1', 443)); });
caseTest('R-CASE-14 install-proxy-port: the proxy refuses a CONNECT to a port other than 443, even to the registry, and logs it', 'install-proxy-port', (ev) => { ev.report = { result: { attempts: [{ to: 'CONNECT registry.npmjs.org:22', ok: true, tunnel: true, received: 39 }] } }; });
caseTest('R-CASE-15 install-direct: nothing on the install network gets out around the proxy, by address or by name', 'install-direct', (ev) => { ev.trace.network.connects[2] = ok({ family: 'AF_INET', addr: '104.16.1.34', port: 443 }); });
caseTest('R-CASE-16 install-metadata: no metadata or host agent address answers on the install network, directly or through the proxy', 'install-metadata', (ev) => { ev.trace.network.connects[1] = ok({ family: 'AF_INET', addr: '168.63.129.16', port: 80 }); });
caseTest('R-CASE-17 install-host: the host, its Docker API and its sockets are out of reach from the install network', 'install-host', (ev) => { ev.canaryHits = 1; });

test('R-CASE-12 R-CASE-13 R-CASE-14 the proxy cases need the proxy\'s own log: a dead proxy, or one that logged nothing, is no pass', () => {
  const g = (c, f) => { const ev = GOOD[c](); f(ev); return evaluateCase(c, ev); };
  for (const c of ['install-proxy-host', 'install-proxy-ip', 'install-proxy-port']) {
    assert.match(g(c, (ev) => { ev.egress = []; }).detail, /^not logged: the proxy logged 0 refusal/, `${c}: no proxy log`);
    assert.match(g(c, (ev) => { ev.trace.network.connects = []; }).detail, /^nothing was tried: no traced connection reached the proxy/, `${c}: never reached the proxy`);
    assert.match(g(c, (ev) => { ev.egress.push(allow('evil.example', 443)); }).detail, /^got through: the proxy let evil\.example:443 through/, `${c}: anything let through`);
    assert.equal(g(c, (ev) => { ev.egress.push(allow('registry.npmjs.org', 443)); }).pass, true, `${c}: the registry on 443 is what the proxy is for`);
  }
  assert.equal(g('install-proxy-host', (ev) => { ev.egress = ev.egress.filter((e) => e.error !== 'plain HTTP refused'); }).pass, false, 'plain HTTP must be refused and logged too');
  assert.equal(g('install-metadata', (ev) => { ev.egress = []; }).logged, false, 'the metadata request through the proxy must be logged');
  assert.equal(g('install-direct', (ev) => { ev.dns = []; }).logged, false, 'the registry name must reach the logger');
  assert.match(g('install-direct', (ev) => { ev.dns[0].answer = 'empty'; }).detail, /^got through: registry\.npmjs\.org got a real answer/);
  assert.match(g('install-host', (ev) => { ev.drops = []; }).detail, /blocked|reach|host/);
  assert.equal(g('install-host', (ev) => { ev.drops = []; }).logged, false);
});

test('R-SBX-10 a case says which way it failed: got through, nothing tried, or no definite refusal', () => {
  const g = (c, f) => { const ev = GOOD[c](); f(ev); return evaluateCase(c, ev); };
  for (const c of ['direct-ip', 'metadata', 'doh-ip']) {
    assert.match(g(c, (ev) => { ev.trace.network.connects[0] = ok({ family: 'AF_INET', addr: ev.trace.network.connects[0].addr, port: 443 }); }).detail, /^got through: 1 traced connection/, `${c} reply`);
    assert.match(g(c, (ev) => { for (const e of ev.trace.network.connects) e.errno = 4; }).detail, /^no definite refusal: /, `${c} cut short`);
    assert.match(g(c, (ev) => { ev.trace.network.connects = []; ev.trace.network.sends = []; }).detail, /^nothing was tried: /, `${c} nothing`);
  }
  assert.match(g('ipv6', (ev) => { for (const e of [...ev.trace.network.connects, ...ev.trace.network.sends]) e.errno = 110; }).detail, /^no definite refusal: /);
  assert.match(g('doh-ip', (ev) => { ev.dns[0].answer = 'empty'; }).detail, /^got through: dns\.google got a real answer/);
  assert.match(g('write-outside', (ev) => { ev.trace.opens_outside[1] = ok({ path: '/var/tmp/isk-1', op: 'write' }); }).detail, /^got through: a write outside the work folder worked \(\/var\/tmp\/isk-1\)/);
  assert.match(g('write-outside', (ev) => { ev.trace.privileged = [ok({ name: 'mount' })]; }).detail, /^got through: a mount worked/);
  assert.match(g('write-outside', (ev) => { ev.trace.opens_outside = []; }).detail, /^nothing was tried: /);
});

test('R-SBX-10 raw-socket fails when the target reports any capability left, the bounding set included; the report cannot pass it', () => {
  const zero = '0000000000000000';
  const caps = (o) => ({ case: 'raw-socket', result: { caps: { CapInh: zero, CapPrm: zero, CapEff: zero, CapBnd: zero, CapAmb: zero, NoNewPrivs: '1', ...o }, attempts: [] } });
  const v = (report) => evaluateCase('raw-socket', { ...GOOD['raw-socket'](), report });
  assert.equal(v(caps({})).pass, true);
  assert.ok(v(caps({})).evidence.includes(`target: CapEff ${zero} CapBnd ${zero}`));
  const left = v(caps({ CapBnd: '00000000a80425fb' }));
  assert.equal(left.blocked, false);
  assert.match(left.detail, /^got through: the target reports capabilities left \(CapBnd 00000000a80425fb\)/);
  assert.equal(v(null).pass, true, 'no report: the settings check decides');
  const settings = evaluateCase('raw-socket', { ...GOOD['raw-socket'](), report: caps({}), inspect: { runtime: 'runsc', mismatches: ['capabilities are not all dropped'], canaryInEnv: false } });
  assert.equal(settings.pass, false, 'a report of no capabilities cannot outweigh the settings');
});

test('R-SBX-10 a datagram sent and not refused is no definite refusal, not a connection made', () => {
  const ev = GOOD['direct-ip']();
  ev.trace.network.sends[0] = ok({ family: 'AF_INET', addr: '8.8.8.8', port: 53 });
  for (const c of ev.trace.network.connects) c.errno = 4;
  const v = evaluateCase('direct-ip', ev);
  assert.equal(v.blocked, false);
  assert.match(v.detail, /^no definite refusal: 1 datagram\(s\) to an outside address were sent, not refused/);
  ev.trace.network.connects[0] = ok({ family: 'AF_INET', addr: '1.1.1.1', port: 443 });
  assert.match(evaluateCase('direct-ip', ev).detail, /^got through: 1 traced connection/);
});
