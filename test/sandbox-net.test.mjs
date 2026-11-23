import test from 'node:test';
import { fakeHostRun } from './helpers.mjs';
import { loadRunscConfig as loadCfg } from '../src/runsc.mjs';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, statSync, writeFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { NETS, SANDBOX_RANGE, RESOLV_DIR, LOG_PREFIX, SINK_TCP, SINK_UDP, resolvConf, parseKernelLog, groupDrops, readHostLog, firewallProblems, jumpOrderProblems } from '../src/sandbox-net.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const ipNum = (ip) => ip.split('.').reduce((n, x) => n * 256 + Number(x), 0);
const inCidr = (ip, cidr) => { const [base, bits] = cidr.split('/'); const m = 2 ** (32 - Number(bits)); return Math.floor(ipNum(ip) / m) === Math.floor(ipNum(base) / m); };

test('both sandbox networks sit in the guarded range, every fixed address on its own network', () => {
  for (const [name, n] of Object.entries(NETS)) {
    assert.ok(inCidr(n.subnet.split('/')[0], SANDBOX_RANGE), `${name} subnet`);
    assert.equal(n.subnet.split('/')[1], '24');
    for (const k of ['gateway', 'netlog', 'target']) assert.ok(inCidr(n[k], n.subnet), `${name}.${k}`);
    assert.equal(n.gateway.split('.')[3], '1');
    assert.equal(n.netlog.split('.')[3], '2');
    assert.equal(n.resolv, `${RESOLV_DIR}/resolv-${name}.conf`);
  }
  assert.notEqual(NETS.run.subnet, NETS.install.subnet);
  assert.ok(inCidr(NETS.install.proxy, NETS.install.subnet) && inCidr(NETS.run.probe, NETS.run.subnet));
  assert.ok(SINK_TCP.includes(443) && SINK_TCP.includes(853) && SINK_TCP.includes(2375) && !SINK_TCP.includes(53));
  assert.ok(SINK_UDP.includes(443) && !SINK_UDP.includes(53));
  assert.match(resolvConf('run'), /^nameserver 10\.213\.53\.2$/m);
  assert.equal(resolvConf('install').match(/^nameserver /gm).length, 1, 'one name server, nothing to fall back to');
});

const JOURNAL = [
  '1763719200.100000 runner kernel: isk-sbx-fwd: IN=br-0a1b OUT=eth0 MAC=02:42:0a:d5:35:03 SRC=10.213.53.3 DST=1.1.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=63 ID=1 DF PROTO=TCP SPT=40000 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0',
  '1763719200.200000 runner kernel: isk-sbx-fwd: IN=br-0a1b OUT=eth0 MAC=02:42 SRC=10.213.53.3 DST=1.1.1.1 LEN=60 PROTO=TCP SPT=40001 DPT=443 SYN URGP=0',
  '1763719200.300000 runner kernel: isk-sbx-in: IN=br-0a1b OUT= MAC=02:42 SRC=10.213.53.3 DST=10.213.53.1 LEN=84 TOS=0x00 PROTO=ICMP TYPE=8 CODE=0 ID=7 SEQ=1',
  '1763719200.400000 runner kernel: isk-sbx-in6: IN=br-0a1b OUT= MAC=33:33 SRC=fe80:0000:0000:0000:0042:0aff:fed5:3503 DST=ff02:0000:0000:0000:0000:0000:0000:0002 LEN=56 TC=0 HOPLIMIT=255 FLOWLBL=0 PROTO=ICMPv6 TYPE=133 CODE=0',
  '1763719200.500000 runner kernel: isk-sbx-in: IN=br-0a1b OUT= SRC=10.213.53.3 DST=10.213.53.1 LEN=60 PROTO=TCP SPT=40002 DPT=2375 SYN',
  '1763719100.000000 runner kernel: isk-sbx-fwd: IN=br-0a1b OUT=eth0 SRC=10.213.53.3 DST=8.8.8.8 PROTO=UDP SPT=1 DPT=53',
  '1763719200.600000 runner kernel: [UFW BLOCK] IN=eth0 SRC=1.2.3.4 DST=10.0.0.4 PROTO=TCP DPT=22',
  '1763719200.700000 runner kernel: isk-sbx-fwd: IN=br-0a1b OUT=eth0 SRC=$(id) DST=1.1.1.1 PROTO=TCP SPT=1 DPT=99999999',
];

test('the firewall log comes back as drops: ours only, since the start of the run, fields checked', () => {
  const d = parseKernelLog(JOURNAL.join('\n'), { since: 1763719200 });
  assert.deepEqual(d.map((x) => x.chain), ['forward', 'forward', 'input', 'input6', 'input', 'forward']);
  assert.deepEqual([d[0].family, d[0].proto, d[0].src, d[0].dst, d[0].spt, d[0].dpt, d[0].in, d[0].out], [4, 'TCP', '10.213.53.3', '1.1.1.1', 40000, 443, 'br-0a1b', 'eth0']);
  assert.deepEqual([d[2].proto, d[2].icmp_type, d[2].dpt, d[2].out], ['ICMP', 8, null, null]);
  assert.deepEqual([d[3].family, d[3].proto, d[3].src.startsWith('fe80:'), d[3].icmp_type], [6, 'ICMPv6', true, 133]);
  assert.equal(d[4].dpt, 2375);
  assert.equal(d[5].src, null, 'a field that is not an address is dropped');
  const g = groupDrops(d);
  assert.equal(g.length, 5);
  assert.equal(g.find((x) => x.dst === '1.1.1.1' && x.dpt === 443).n, 2, 'two attempts at the same thing are one entry with a count');
  assert.equal(groupDrops(d, 2).length, 2);
  assert.equal(parseKernelLog(JOURNAL.join('\n')).length, 7, 'without a start time, every line of ours');
});

test('the host log is read with journalctl, then sudo -n, never a prompt; a failure says so', () => {
  const calls = [];
  const r = readHostLog(1763719200.9, (cmd, argv) => { calls.push([cmd, ...argv].join(' ')); return cmd === 'sudo' ? { status: 0, stdout: JOURNAL[0] } : { status: 1, stdout: '' }; });
  assert.deepEqual([r.ok, r.via, r.text], [true, 'sudo journalctl', JOURNAL[0]]);
  assert.match(calls[0], /^journalctl -k .*--since=@1763719200$/);
  assert.match(calls[1], /^sudo -n journalctl -k /);
  assert.deepEqual(readHostLog(1, () => ({ status: 1, stdout: '' })), { ok: false, text: '', via: null });
});

// A stand-in for iptables and ip6tables: records every call, answers the checks net-guard.sh makes.
const FAKE = `#!/usr/bin/env bash
echo "$(basename "$0") $*" >>"$FAKE_LOG"
case "$*" in
  "-C FORWARD -j DOCKER-USER") [ -z "\${FAKE_NO_JUMP:-}" ] && exit 0; exit 1 ;;
  "-S FORWARD") printf '%s\\n' '-P FORWARD DROP' \${FAKE_ACCEPT_FIRST:+'-A FORWARD -j ACCEPT'} '-A FORWARD -j DOCKER-USER' '-A FORWARD -j DOCKER-FORWARD'; exit 0 ;;
  -C*|-D*) exit 1 ;;
esac
exit 0
`;
function guard(env = {}) {
  const d = mkdtempSync(join(tmpdir(), 'guard-'));
  mkdirSync(join(d, 'bin'));
  for (const b of ['iptables', 'ip6tables']) { writeFileSync(join(d, 'bin', b), FAKE); chmodSync(join(d, 'bin', b), 0o755); }
  const r = spawnSync('bash', [join(root, 'scripts', 'net-guard.sh')], { cwd: root, encoding: 'utf8', env: { PATH: `${join(d, 'bin')}:${process.env.PATH}`, FAKE_LOG: join(d, 'calls'), SANDBOX_ETC_DIR: join(d, 'etc'), ...env } });
  return { r, d, calls: existsSync(join(d, 'calls')) ? readFileSync(join(d, 'calls'), 'utf8').trim().split('\n') : [] };
}

test('net-guard: logs and drops whatever leaves a sandbox network, the host, IPv6; writes the resolver files', () => {
  const { r, d, calls } = guard();
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(r.stdout.trim(), 'container networks guarded');
  const has = (line) => assert.ok(calls.includes(line), `missing: ${line}\n${calls.join('\n')}`);
  for (const n of Object.values(NETS)) has(`iptables -A ISK-SBX -s ${n.subnet} -d ${n.subnet} -j RETURN`);
  has(`iptables -A ISK-SBX -m limit --limit 20/second --limit-burst 200 -j LOG --log-prefix ${LOG_PREFIX.forward} --log-level 4`);
  has('iptables -A ISK-SBX -j DROP');
  has(`iptables -I DOCKER-USER -s ${SANDBOX_RANGE} -j ISK-SBX`);
  has(`iptables -I DOCKER-USER -d ${SANDBOX_RANGE} -j ISK-SBX`);
  has('iptables -I DOCKER-USER -d 169.254.0.0/16 -j DROP');
  has('iptables -I DOCKER-USER -d 168.63.129.16/32 -j DROP');
  has(`iptables -A ISK-SBX-IN -m limit --limit 20/second --limit-burst 200 -j LOG --log-prefix ${LOG_PREFIX.input} --log-level 4`);
  for (const ifc of ['docker0', 'br-+']) {
    has(`iptables -I INPUT -i ${ifc} -j ISK-SBX-IN`);
    has(`ip6tables -I FORWARD -i ${ifc} -j ISK-SBX6`);
    has(`ip6tables -I FORWARD -o ${ifc} -j ISK-SBX6`);
    has(`ip6tables -I INPUT -i ${ifc} -j ISK-SBX6-IN`);
  }
  has(`ip6tables -A ISK-SBX6 -m limit --limit 20/second --limit-burst 200 -j LOG --log-prefix ${LOG_PREFIX.forward6} --log-level 4`);
  has(`ip6tables -A ISK-SBX6-IN -m limit --limit 20/second --limit-burst 200 -j LOG --log-prefix ${LOG_PREFIX.input6} --log-level 4`);
  const logIdx = calls.indexOf('iptables -A ISK-SBX -j DROP');
  assert.ok(calls.findIndex((c) => c.includes('-j LOG --log-prefix isk-sbx-fwd:')) < logIdx, 'logged before it is dropped');
  assert.ok(!calls.some((c) => / -j ACCEPT/.test(c)), 'nothing is ever accepted');
  for (const net of Object.keys(NETS)) {
    const f = join(d, 'etc', `resolv-${net}.conf`);
    assert.equal(readFileSync(f, 'utf8'), resolvConf(net));
    assert.equal(statSync(f).mode & 0o777, 0o644);
  }
});

test('net-guard: stops before changing anything when forwarded traffic would skip its rules', () => {
  for (const env of [{ FAKE_NO_JUMP: '1' }, { FAKE_ACCEPT_FIRST: '1' }]) {
    const { r, d, calls } = guard(env);
    assert.equal(r.status, 1, JSON.stringify(env));
    assert.match(r.stdout, /^harness error: /);
    assert.ok(!calls.some((c) => / -[AI] /.test(c)), 'no rule was added');
    assert.ok(!existsSync(join(d, 'etc')), 'no resolver file was written');
  }
  const noIp6 = spawnSync('bash', [join(root, 'scripts', 'net-guard.sh')], { encoding: 'utf8', env: { PATH: '/usr/bin:/bin' } });
  if (spawnSync('bash', ['-c', 'command -v iptables'], { env: { PATH: '/usr/bin:/bin' } }).status !== 0) assert.match(noIp6.stdout, /^harness error: iptables not found/);
});

test('R-SBX-05 the firewall is checked live: every chain net-guard.sh makes, and every jump to it', () => {
  const cfg = loadCfg();
  assert.deepEqual(firewallProblems(fakeHostRun(cfg)), []);
  const bad = (drop) => firewallProblems(fakeHostRun(cfg, { drop }));
  assert.match(bad({ 'iptables INPUT': ['-A INPUT -i br-+ -j ISK-SBX-IN'] }).join(), /INPUT lacks: -A INPUT -i br-\+ -j ISK-SBX-IN/);
  assert.match(bad({ 'iptables ISK-SBX': ['-A ISK-SBX -j DROP'] }).join(), /ISK-SBX is not the chain/);
  assert.match(bad({ 'iptables DOCKER-USER': ['-A DOCKER-USER -s 10.213.52.0/22 -j ISK-SBX'] }).join(), /DOCKER-USER lacks/);
  assert.match(bad({ 'ip6tables ISK-SBX6-IN': true }).join(), /ip6tables ISK-SBX6-IN cannot be read/);
  assert.match(bad({ 'ip6tables FORWARD': ['-A FORWARD -i br-+ -j ISK-SBX6'] }).join(), /ip6tables FORWARD lacks/);
  const accept = (cmd, argv) => (argv.includes('FORWARD') && (cmd === 'iptables' || argv[1] === 'iptables') ? { status: 0, stdout: '-P FORWARD DROP\n-A FORWARD -j ACCEPT\n-A FORWARD -j DOCKER-USER' } : fakeHostRun(cfg)(cmd, argv));
  assert.match(firewallProblems(accept).join(), /accepts traffic before DOCKER-USER/);
  assert.equal(firewallProblems(() => ({ status: 1 })).length > 0, true, 'nothing readable is not live');
});

test('R-CI-07 iptables -S prints a LOG rule without --log-level when it is the default: that is still net-guard.sh\'s chain', () => {
  const cfg = loadCfg();
  const with4 = (cmd, argv) => { const r = fakeHostRun(cfg)(cmd, argv); return { ...r, stdout: String(r.stdout).replace(/(--log-prefix "isk-sbx-[a-z0-9]+: ")$/gm, '$1 --log-level 4') }; };
  assert.deepEqual(firewallProblems(fakeHostRun(cfg)), [], 'without --log-level, as the runner prints it');
  assert.deepEqual(firewallProblems(with4), [], 'with --log-level 4');
  const other = (cmd, argv) => { const r = fakeHostRun(cfg)(cmd, argv); return { ...r, stdout: String(r.stdout).replace(/(--log-prefix "isk-sbx-in: ")$/m, '$1 --log-level 7') }; };
  assert.match(firewallProblems(other).join(), /ISK-SBX-IN is not the chain/);
});

test('R-SBX-09 our jumps must come before any rule that could let a packet past them: an ACCEPT above them is refused', () => {
  const cfg = loadCfg();
  const top = (k, rules) => firewallProblems(fakeHostRun(cfg, { top: { [k]: rules } }));
  assert.match(top('iptables DOCKER-USER', ['-A DOCKER-USER -s 10.213.52.0/22 -j ACCEPT']).join(), /DOCKER-USER: -A DOCKER-USER -d 10\.213\.52\.0\/22 -j ISK-SBX comes after -A DOCKER-USER -s 10\.213\.52\.0\/22 -j ACCEPT/);
  assert.match(top('iptables INPUT', ['-A INPUT -i br-+ -p tcp -m tcp --dport 2375 -j ACCEPT']).join(), /INPUT: -A INPUT -i br-\+ -j ISK-SBX-IN comes after/);
  assert.match(top('ip6tables FORWARD', ['-A FORWARD -j DOCKER-USER']).join(), /ip6tables FORWARD: .* comes after -A FORWARD -j DOCKER-USER/, 'a jump to another chain is a way past too');
  assert.match(top('ip6tables INPUT', ['-A INPUT -j RETURN']).join(), /ip6tables INPUT: .* comes after -A INPUT -j RETURN/);
  // Rules that only drop, reject or log above ours, and Docker's RETURN at the very end, are fine.
  assert.deepEqual(top('iptables DOCKER-USER', ['-A DOCKER-USER -d 192.0.2.1/32 -j DROP', '-A DOCKER-USER -p tcp -j REJECT --reject-with tcp-reset', '-A DOCKER-USER -j LOG --log-prefix "x: "']), []);
  assert.deepEqual(firewallProblems(fakeHostRun(cfg)), [], 'the fixture ends DOCKER-USER with -j RETURN');
  assert.deepEqual(jumpOrderProblems('iptables', 'INPUT', ['-A INPUT -i br-+ -j ISK-SBX-IN', '-A INPUT -j ACCEPT'], ['-A INPUT -i br-+ -j ISK-SBX-IN']), [], 'an ACCEPT below our jump is fine');
});
