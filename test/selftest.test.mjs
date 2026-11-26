import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { BOMB_LANDED_MB, CASES, READOUT_PATHS, VOLUME_CAP, evaluateCase } from '../src/selftest.mjs';
import { LIMITS, LOGS } from '../src/docker.mjs';
import { hostFactsIn } from '../bin/sandbox-selftest.mjs';
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync as wf } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GOOD, base, trace, ok, fail } from './selftest-fixtures.mjs';

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

test('R-CASE-18 install-proxy-host has a positive control: the proxy must be shown to tunnel to the registry, from its own log, or the refusals prove nothing', () => {
  const g = (f) => { const ev = GOOD['install-proxy-host'](); f(ev); return evaluateCase('install-proxy-host', ev); };
  assert.equal(g(() => {}).pass, true);
  const none = g((ev) => { ev.egress = ev.egress.filter((e) => e.allowed !== true); });
  assert.deepEqual([none.blocked, none.logged, none.pass], [false, false, false]);
  assert.match(none.detail, /^not shown to work: the proxy's log has no allowed tunnel to registry\.npmjs\.org:443/);
  assert.equal(g((ev) => { ev.egress[0].down = 0; }).pass, false, 'a tunnel that carried nothing back is not shown to work');
  assert.equal(g((ev) => { ev.egress[0].port = 8443; }).pass, false, 'only the registry on 443');
  // The target's report cannot stand in for the proxy's log, and its own control tunnel is not a bypass.
  assert.equal(g((ev) => { ev.egress = ev.egress.filter((e) => e.allowed !== true); ev.report = { result: { attempts: [{ to: 'CONNECT registry.npmjs.org:443', control: true, ok: true, status: '200', received: 400 }] } }; }).pass, false);
  assert.equal(g((ev) => { ev.report = { result: { attempts: [{ to: 'CONNECT registry.npmjs.org:443', control: true, tunnel: true, ok: true, status: '200', received: 400 }] } }; }).pass, true);
  assert.match(g(() => {}).evidence.join('\n'), /proxy: registry\.npmjs\.org:443 ALLOWED, 517 bytes up, 4096 down \(the positive control\)/);
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  assert.match(py, /def case_install_proxy_host[\s\S]*?proxy_control\("registry\.npmjs\.org:443", "registry\.npmjs\.org"\)/);
});

// Red-teaming the lab: links, sockets, archives (selftest/hostile.py symlink-escape, unix-socket, install-archive-bomb).
caseTest('R-CASE-19 symlink-escape: links planted to outside the work folder lead nowhere, and the result readout refuses them', 'symlink-escape', (ev) => { ev.stage.readout[0] = { path: '/work/lock/freeze.txt', exit: 0, bytes: 900 }; });
caseTest('R-CASE-20 unix-socket: no host or abstract socket answers, and nothing the case left listening outlives its stage', 'unix-socket', (ev) => { ev.stage.reach[0] = { to: 'tcp 10.213.53.3:47124', ok: true, code: 'answered', bytes: 22 }; });
caseTest('R-CASE-21 install-archive-bomb: the work volume\'s own filesystem holds the bomb, the runner\'s disk does not move, nothing climbs out', 'install-archive-bomb', (ev) => { ev.stage.disk.host_free_drop_mb = 7200; });

test('R-CASE-19 symlink-escape fails on any way out: a readout that followed, the host\'s canary, a write through a link; and proves nothing without its stage', () => {
  const g = (f) => { const ev = GOOD['symlink-escape'](); f(ev); return evaluateCase('symlink-escape', ev); };
  assert.match(g((ev) => { ev.stage.readout[2] = { path: '/work/pkg/package-lock.json', exit: 0, bytes: 30 }; }).detail, /^got through: the result readout followed a planted link \(\/work\/pkg\/package-lock\.json/, 'a folder above the file is a link');
  assert.match(g((ev) => { ev.stage.host.planted = 1; }).detail, /^got through: 1 file\(s\) appeared in the host's canary folder/);
  assert.match(g((ev) => { ev.stage.host.intact = false; }).detail, /^got through: the host's canary file changed/);
  assert.match(g((ev) => { ev.report.result.canary_seen = 1; }).detail, /^got through: the target reports reading the host's canary/);
  assert.match(g((ev) => { ev.report.result.attempts.push({ path: '/work/links-1/l00/isk-1', via: '/', ok: true, written: true }); }).detail, /^got through: the target reports a write through a link/);
  assert.equal(g((ev) => { ev.report.result.attempts.push({ path: '/work/x', via: '/work/y', ok: true, written: true }); }).pass, true, 'a write through a link to inside the work folder is no way out');
  assert.match(g((ev) => { ev.stage = null; }).detail, /^not measured: the later stage did not run/);
  assert.match(g((ev) => { ev.stage.readout = ev.stage.readout.map((r) => ({ ...r, exit: 4 })); }).detail, /^nothing was tried/);
  assert.equal(g((ev) => { ev.trace.links = ev.trace.links.slice(0, 3); }).logged, false, 'the links must show in the trace');
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  for (const p of READOUT_PATHS) assert.ok(py.includes(p.startsWith('/work/pkg') ? '"/work/pkg"' : `"${p}"`), `${p} is planted`);
});

test('R-CASE-20 unix-socket fails on a socket that connected, a reply, or a listener reached after the stage', () => {
  const g = (f) => { const ev = GOOD['unix-socket'](); f(ev); return evaluateCase('unix-socket', ev); };
  assert.match(g((ev) => { ev.trace.network.connects[0] = ok({ family: 'AF_UNIX', addr: '/var/run/docker.sock', port: null }); }).detail, /^got through: a unix socket connected/);
  assert.match(g((ev) => { ev.stage.reach[1].ok = true; }).detail, /^got through: a later stage reached what the case left listening \(unix /);
  assert.match(g((ev) => { ev.report = { result: { attempts: [{ path: '/run/docker.sock', ok: true, received: 120 }] } }; }).detail, /^got through: the target reports a reply/);
  assert.equal(g((ev) => { ev.report = { result: { attempts: [], listeners: [{ ok: true, listening: true, opened: true }] } }; }).pass, true, 'its own listeners are not a way out');
  assert.match(g((ev) => { ev.stage = {}; }).detail, /^not measured/);
  assert.match(g((ev) => { ev.trace.network.connects = ev.trace.network.connects.slice(0, 2); }).detail, /^nothing was tried/);
  assert.equal(g((ev) => { ev.trace.network.binds = []; }).logged, false, 'the listeners must show in the trace');
});

test('R-CASE-20 unix-socket has a positive control: its TCP listener must answer the later stage while the case runs, and only listeners really bound count', () => {
  const g = (f) => { const ev = GOOD['unix-socket'](); f(ev); return evaluateCase('unix-socket', ev); };
  const none = g((ev) => { ev.stage.reach_before[0] = { to: 'tcp 10.213.53.3:47124', ok: false, code: 'timeout', bytes: 0 }; });
  assert.deepEqual([none.blocked, none.logged], [false, false]);
  assert.match(none.detail, /^not shown to work: the later stage reached nothing while the case still ran/);
  assert.equal(g((ev) => { delete ev.stage.reach_before; }).pass, false, 'no control run, no pass');
  assert.equal(g((ev) => { ev.stage.reach_before[1].ok = true; ev.stage.reach_before[0].ok = false; }).pass, false, 'the control is the TCP listener');
  const unbound = g((ev) => { for (const b of ev.trace.network.binds) { b.failed = 1; b.errno = 13; } });
  assert.equal(unbound.logged, false, 'binds that failed (an unwritable /work, say) are not listeners');
  assert.match(unbound.detail, /^nothing was tried: \d+ unix socket connect\(s\) and 0 listener\(s\)/);
});

test('R-CASE-21 install-archive-bomb fails on a volume past its cap, the runner\'s disk falling, an entry outside, or no measurement; the bomb is bigger than the cap', () => {
  const g = (f) => { const ev = GOOD['install-archive-bomb'](); f(ev); return evaluateCase('install-archive-bomb', ev); };
  assert.match(g((ev) => { ev.stage.disk.work_fs_mb = 72000; }).detail, /^got through: the work volume's filesystem holds 72000 MB/);
  assert.match(g((ev) => { ev.stage.disk.work_fs_inodes = 4_600_000; }).detail, /^got through: the work volume's filesystem holds/, 'the inode cap too');
  assert.match(g((ev) => { ev.stage.disk.host_free_drop_mb = 600; }).detail, /^got through: the runner's disk lost 600 MB/);
  assert.match(g((ev) => { ev.stage.disk.host_free_drop_mb = null; }).detail, /^not measured: the runner's free disk could not be read/);
  assert.match(g((ev) => { ev.trace.opens_outside[0] = ok({ path: '/etc/isk-1-dotdot', op: 'write' }); }).detail, /^got through: an archive entry was written outside the work folder \(\/etc\/isk-1-dotdot\)/);
  assert.match(g((ev) => { ev.report.result.fallocate = { ok: true, bytes: 7 << 30 }; }).detail, /^got through: the target reports an allocation past the cap/);
  assert.match(g((ev) => { ev.stage = null; }).detail, /^not measured: no measurement/);
  assert.match(g((ev) => { ev.trace.opens_outside = []; }).detail, /^nothing was tried/);
  assert.match(g((ev) => { ev.stage.disk.work_used_mb = 3; }).detail, /^not shown to work: only 3 MB landed in the work volume/, 'an unwritable /work proves nothing');
  assert.match(g((ev) => { ev.container = { exit: 137, timed_out: true, oom_killed: false }; }).detail, /^not shown to work: the case did not run to its end \(exit 137, time limit\)/, 'killed before the allocation');
  assert.match(g((ev) => { ev.container = { exit: 1, timed_out: false, oom_killed: false }; }).detail, /^not shown to work: the case did not run to its end/);
  assert.equal(g((ev) => { ev.stage.disk.work_used_mb = BOMB_LANDED_MB; }).pass, true);
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  const budget = JSON.parse(/^BOMB_BUDGET = (\{.*\})$/m.exec(py)[1]);
  const sum = Object.values(budget).reduce((a, b) => a + b, 0);
  const caseMs = Number(/^const CASE_MS = ([\d_]+);$/m.exec(readFileSync(new URL('../bin/sandbox-selftest.mjs', import.meta.url), 'utf8'))[1].replace(/_/g, ''));
  assert.ok(sum + 10 <= caseMs / 1000, `the bomb's worst case (${sum} s of budgets, and about 10 s to start) fits the case's time limit (${caseMs / 1000} s)`);
  const gib = Number(/^BOMB_GIB = (\d+)$/m.exec(py)[1]);
  assert.ok(gib * 1024 > VOLUME_CAP.mb, `the allocation (${gib} GiB) is past the cap (${VOLUME_CAP.mb} MB)`);
  assert.ok(gib * 1024 < 12 * 1024, 'and small enough for a runner\'s disk when the cap is off (the volume-cap mutation)');
});

caseTest('R-CASE-22 output-flood: Docker keeps at most its log cap of a container that prints without end, on its own filesystem; the runner\'s disk does not move', 'output-flood', (ev) => { ev.output.bytes = 3 * 1024 ** 3; });

test('R-CASE-22 output-flood fails past the cap or with the runner\'s disk falling, and proves nothing without a whole log file kept; the flood fits the case\'s time', () => {
  const g = (f) => { const ev = GOOD['output-flood'](); f(ev); return evaluateCase('output-flood', ev); };
  assert.match(g((ev) => { ev.output.bytes = 900 * 1024 * 1024; }).detail, /^got through: Docker kept 900 MB of the case's output, past its cap of 32 MB/);
  assert.match(g((ev) => { ev.stage.disk.host_free_drop_mb = 700; }).detail, /^got through: the runner's disk lost 700 MB/);
  assert.match(g((ev) => { ev.output.bytes = 1000; }).detail, /^nothing was tried: Docker kept 0 MB/);
  assert.match(g((ev) => { ev.stage = {}; }).detail, /^not measured/);
  assert.equal(g((ev) => { ev.output.bytes = LOGS.maxBytes; }).pass, true, 'the cap itself');
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  assert.ok(Number(/^FLOOD_SECONDS = ([\d.]+)$/m.exec(py)[1]) + 15 <= 120, 'the flood ends well inside the case\'s time limit');
  assert.ok(Number(/^FLOOD_BYTES = 2 << 30$/m.test(py)) && 2 * 2 ** 30 > LOGS.maxBytes * 10, 'and is far bigger than the cap');
});

test('R-CASE-19 symlink-escape links to the very host folder where the harness keeps its canary: the harness passes it to the target', () => {
  const sh = readFileSync(new URL('../bin/sandbox-selftest.mjs', import.meta.url), 'utf8');
  assert.match(sh, /hostile\.py`, name, nonce, NET\.gateway, String\(CANARY_PORT\), \.\.\.\(hostCanary \? \[hostCanary\.dir\] : \[\]\)\]/);
  assert.ok(sh.indexOf('hostCanary = plantHostCanary(out, nonce)') < sh.indexOf('hostile.py`, name, nonce'), 'planted before the case starts');
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  assert.match(py, /targets = LINK_TARGETS \+ \(\[host_canary, f"\{host_canary\}\/canary"\] if host_canary else \[\]\)/);
  assert.ok(!/_temp\/selftest\/host-canary/.test(py), 'no guessed runner path');
});

test('R-SBX-30 install-archive-bomb also checks the volume filesystem\'s image is still fully reserved after it zero-ranges and punches its own files', () => {
  const ev = GOOD['install-archive-bomb'](); ev.stage.disk.reservation_intact = false;
  const v = evaluateCase('install-archive-bomb', ev);
  assert.equal(v.blocked, false);
  assert.match(v.detail, /^got through: the volume filesystem's image file has holes after the bomb/);
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  assert.match(py, /\("zero_range", 0x10, 0, 32 << 20\), \("punch_hole", 0x02 \| 0x01, 32 << 20, 16 << 20\)/);
  assert.ok(py.indexOf('out["punch"] = punch_and_zero') < py.indexOf('out["fallocate"] = fallocate'), 'before the volume is full');
  const st = readFileSync(new URL('../bin/sandbox-selftest.mjs', import.meta.url), 'utf8');
  assert.match(st, /imageHoles\(`\$\{ctx\.cfg\.install_dir\}\/volume-fs\.img`\)/);
});

// The deferred cases (part B).
caseTest('R-CASE-23 background: a daemon (double fork, setsid) and a nohup child beat while the case runs and stop when its stage is torn down', 'background', (ev) => { ev.stage.grow[1].after = 90; });
caseTest('R-CASE-24 proc-sys: what /proc and /sys tell a target holds none of the host\'s facts', 'proc-sys', (ev) => { ev.stage.host_facts.seen = ['kernel']; });
caseTest('R-CASE-25 fd-exhaustion: descriptors run out at the nofile limit with EMFILE, and the limit cannot be raised past it', 'fd-exhaustion', (ev) => { ev.trace.network.sockets[0] = { ...ev.trace.network.sockets[0], n: 20000, failed: 0, errno: null }; });
caseTest('R-CASE-26 clock-tamper: the clock cannot be set, and a time the target claims never becomes the harness\'s', 'clock-tamper', (ev) => { ev.stage.clock.forged_in_telemetry = true; });
caseTest('R-CASE-27 install-git-submodule: ext:: never runs, file:// is not followed, the outside host is refused, and the superproject clones', 'install-git-submodule', (ev) => { ev.stage.git.file_followed = true; });

test('R-CASE-23 background needs its control (heartbeats while it runs) and fails on any heartbeat or host process after teardown', () => {
  const g = (f) => { const ev = GOOD.background(); f(ev); return evaluateCase('background', ev); };
  assert.match(g((ev) => { ev.stage.grow[0].after = 99; }).detail, /^got through: a process of the case kept running after its stage was torn down \(\/work\/hb-1-daemon grew 59 bytes\)/);
  assert.match(g((ev) => { ev.stage.host_procs = 2; }).detail, /^got through: 2 process\(es\) of the case outlived it on the host/);
  assert.match(g((ev) => { ev.stage.grow_before[1].after = ev.stage.grow_before[1].before; }).detail, /^not shown to work: the heartbeats did not grow while the case ran/);
  assert.equal(g((ev) => { ev.stage.host_procs = null; }).pass, false, 'the host must be checked');
  assert.equal(g((ev) => { ev.trace.process.clones = 1; }).logged, false);
});

test('R-CASE-24 proc-sys fails when a host fact shows in the output, and the harness looks for real facts of its host', () => {
  const g = (f) => { const ev = GOOD['proc-sys'](); f(ev); return evaluateCase('proc-sys', ev); };
  assert.match(g((ev) => { ev.stage.host_facts.seen = ['kernel', 'boot_id']; }).detail, /^got through: the target's output holds host facts \(kernel, boot_id\)/);
  assert.match(g((ev) => { ev.stage.host_facts.checked = ['kernel']; }).detail, /^not measured: only 1 host fact/);
  assert.match(g((ev) => { ev.output.bytes = 100; }).detail, /^nothing was tried/);
  assert.equal(g((ev) => { ev.trace.opens_outside = ev.trace.opens_outside.slice(0, 2); }).logged, false);
  const osInfo = { release: () => '7.0.0-1017-azure', hostname: () => 'runnervm42abc', networkInterfaces: () => ({ eth0: [{ family: 'IPv4', address: '10.1.0.33', internal: false, mac: '7c:1e:52:aa:bb:cc' }], docker0: [{ family: 'IPv4', address: '172.17.0.1', internal: false, mac: '02:42:00:00:00:01' }], lo: [{ family: 'IPv4', address: '127.0.0.1', internal: true }] }) };
  const read = (f) => (f.endsWith('boot_id') ? '5f2c1a0e-aaaa-bbbb-cccc-0123456789ab\n' : 'f00dfeedf00dfeedf00dfeedf00dfeed\n');
  const cfg = { docker_root: '/var/lib/isokron-docker' };
  const gvisor = hostFactsIn('Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016 surface 10.213.53.3', cfg, { read, osInfo });
  assert.deepEqual(gvisor.checked.sort(), ['boot_id', 'docker_root', 'hostname', 'ipv4 eth0', 'kernel', 'mac eth0', 'machine_id'].sort());
  assert.deepEqual(gvisor.seen, []);
  const runc = hostFactsIn('Linux version 7.0.0-1017-azure ... overlay /var/lib/isokron-docker/overlay2/x ... 5F2C1A0E-aaaa-bbbb-cccc-0123456789ab', cfg, { read, osInfo });
  assert.deepEqual(runc.seen.sort(), ['boot_id', 'docker_root', 'kernel']);
});

test('R-CASE-25 fd-exhaustion: past the limit, or stopped without EMFILE, is no pass', () => {
  const g = (f) => { const ev = GOOD['fd-exhaustion'](); f(ev); return evaluateCase('fd-exhaustion', ev); };
  assert.match(g((ev) => { ev.report.result.opened = 9000; }).detail, /^got through: 9000 descriptors opened, past the limit of 4096/);
  assert.match(g((ev) => { ev.trace.network.sockets[0].errno = 12; }).detail, /^not shown: the sockets stopped at 4092 without EMFILE/);
  assert.match(g((ev) => { ev.trace.network.sockets = []; }).detail, /^nothing was tried/);
  assert.equal(LIMITS.nofile, '4096');
});

test('R-CASE-26 clock-tamper: a clock call that worked, or the host clock jumping, fails it; it needs the harness\'s clock check', () => {
  const g = (f) => { const ev = GOOD['clock-tamper'](); f(ev); return evaluateCase('clock-tamper', ev); };
  assert.match(g((ev) => { ev.trace.privileged.push(ok({ name: 'settimeofday' })); }).detail, /^got through: settimeofday worked/);
  assert.match(g((ev) => { ev.trace.privileged = [fail({ name: 'clock_settime', errno: 1 })]; }).detail, /^nothing was tried: 1 clock call/, 'glibc sets the time of day through clock_settime: calls are counted, not names');
  assert.match(g((ev) => { ev.stage.clock.drift_ms = 3_600_000; }).detail, /^got through: the host's clock moved 3600000 ms/);
  assert.match(g((ev) => { ev.stage = {}; }).detail, /^not measured/);
  assert.match(g((ev) => { ev.trace.privileged = []; }).detail, /^nothing was tried/);
});

test('R-CASE-27 install-git-submodule: ext:: by its trace alone, the proxy letting the host through, or no clone, is no pass', () => {
  const g = (f) => { const ev = GOOD['install-git-submodule'](); f(ev); return evaluateCase('install-git-submodule', ev); };
  assert.match(g((ev) => { ev.trace.exec.push(fail({ path: '/tmp/isk-ext-1' })); }).detail, /^got through: a submodule's ext:: transport ran/, 'even an attempt to run it');
  assert.match(g((ev) => { ev.egress.push({ host: 'sub.evil.example', port: 443, allowed: true, up: 1, down: 1, ms: 1 }); }).detail, /^got through: the proxy let sub\.evil\.example through/);
  assert.match(g((ev) => { ev.egress = ev.egress.filter((e) => e.host !== 'sub.evil.example'); }).detail, /^not shown to work: the proxy did not refuse both outside hosts/, 'seen on GitHub: a superproject without its gitlinks cloned and passed');
  assert.match(g((ev) => { ev.egress = ev.egress.filter((e) => e.host !== 'npm.evil.example'); }).detail, /^not shown to work: the proxy did not refuse both outside hosts/, 'the npm git dependency must be refused too (review of pull request 12)');
  assert.match(g((ev) => { ev.stage.git.cloned = false; }).detail, /^not shown to work: the superproject did not clone/);
  assert.equal(g((ev) => { ev.egress = []; }).logged, false, 'the outside host must reach the proxy\'s log');
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  for (const u of ['url = ext::{marker} %S', 'url = file://{src}', 'url = https://sub.evil.example/isk-{nonce}.git', 'git+https://npm.evil.example/isk-npm-{nonce}.git']) assert.ok(py.includes(u), u);
  assert.match(py, /git\(\["add", "\.gitmodules", "README"\], sup\)/, 'the files by name: `git add .` takes the gitlinks out again');
  assert.ok(!/lfs/i.test(py.slice(py.indexOf('def case_install_git_submodule'), py.indexOf('# background:'))), 'no LFS claimed: git-lfs is not in the build images');
  assert.ok(!/https?:\/\/(?!(?:[a-z0-9-]+\.)?evil\.example\/|git-lfs\.github\.com\/spec)[a-z0-9.-]+\.[a-z]/i.test(py.slice(py.indexOf('def case_install_git_submodule'), py.indexOf('# background:'))), 'outside hosts are reserved names only');
});

test('R-CASE-23 R-CASE-27 the later stage\'s grow and exists commands', () => {
  const d = mkdtempSync(join(tmpdir(), 'stage-'));
  const a = join(d, 'a'); const b = join(d, 'b');
  wf(a, 'x'); wf(b, 'x');
  // Something else keeps writing a (a process of its own: spawnSync blocks this one).
  const writer = spawn('sh', ['-c', 'while true; do printf y >> "$1"; sleep 0.05; done', 'sh', a], { stdio: 'ignore' });
  const stage = new URL('../selftest/stage.mjs', import.meta.url).pathname;
  const r = spawnSync(process.execPath, [stage, 'grow', '400', a, b, join(d, 'none')], { encoding: 'utf8' });
  writer.kill('SIGKILL');
  const grow = JSON.parse(r.stdout).grow;
  assert.ok(grow[0].after > grow[0].before && grow[1].after === grow[1].before && grow[2].before === -1, r.stdout);
  const e = JSON.parse(spawnSync(process.execPath, [stage, 'exists', a, join(d, 'none')], { encoding: 'utf8' }).stdout).exists;
  assert.deepEqual(e, { [a]: true, [join(d, 'none')]: false });
});

test('R-CASE-28 volume-tmpfs: a fill of an image VOLUME\'s tmpfs past its cap or without ENOSPC is no pass; a run from it is recorded (runsc does not enforce noexec)', () => {
  const g = (f) => { const ev = GOOD['volume-tmpfs'](); f(ev); return evaluateCase('volume-tmpfs', ev); };
  assert.equal(g(() => {}).pass, true, 'from the trace alone: the fill was tried');
  const rep = (fill) => (ev) => { ev.report = { case: 'volume-tmpfs', result: { fill, planted: { ok: true }, exec: { ok: true, exit: 0 } } }; };
  // The shape seen on GitHub: ENOSPC at exactly 32 MiB.
  const seen = g(rep({ ok: false, errno: 28, error: 'ENOSPC', bytes: 33554432 }));
  assert.equal(seen.pass, true);
  assert.ok(seen.evidence.some((e) => /ran \(runsc does not enforce noexec/.test(e)), 'the run is recorded');
  assert.match(g(rep({ ok: true, bytes: 40 * 1024 * 1024 })).detail, /^got through: the volume tmpfs took 41943040 bytes/, 'the size cap did not hold');
  assert.match(g(rep({ ok: false, errno: 5, bytes: 1024 })).detail, /^got through: the volume tmpfs took/, 'a stop that is not ENOSPC');
  assert.match(g(rep({ ok: false, errno: 28, bytes: 33554433 })).detail, /^got through/, 'one byte past the cap');
  assert.equal(g((ev) => { ev.trace.opens_outside = []; }).logged, false, 'no write traced: nothing was tried');
  // The case container gets the tmpfs exactly as a corpus run gives an image VOLUME one.
  const sst = readFileSync(new URL('../bin/sandbox-selftest.mjs', import.meta.url), 'utf8');
  assert.match(sst, /\.\.\.\(name === 'volume-tmpfs' \? \{ tmpfs: \[VOLUME_CASE_PATH\] \} : \{\}\)/);
  const py = readFileSync(new URL('../selftest/hostile.py', import.meta.url), 'utf8');
  assert.match(py, /VOLUME_CASE_PATH = "\/isk-vol"/);
  assert.match(py, /for _ in range\(40\):/);
});
