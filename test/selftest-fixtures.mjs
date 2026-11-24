// Evidence of a working sandbox for every self test case, shared by the verdict tests
// (test/selftest.test.mjs) and the telemetry check tests (test/check-selftest.test.mjs).
import { CANARY_PORT, CASE_LISTEN_PORT, READOUT_PATHS, VOLUME_CAP } from '../src/selftest.mjs';
import { NETS } from '../src/sandbox-net.mjs';

export const GW = NETS.run.gateway;
const IN = NETS.install;
const proxyLine = (host, port, error) => ({ host, port, allowed: false, error });
export const fail = (o) => ({ n: 1, failed: 1, errno: 101, ...o });
export const ok = (o) => ({ n: 1, failed: 0, errno: null, ...o });
export const conn = (addr, port, o = {}) => fail({ family: 'AF_INET', addr, port, ...o });
export const trace = (o = {}) => ({
  format: 'isokron-trace-summary/1', opens_outside: [], credential_paths: [], exec: [], privileged: [],
  process: { clones: 0, clone_failed: 0 },
  ...o,
  network: { sockets: [], raw_sockets: 0, connects: [], sends: [], binds: [], dns_names: [], ...(o.network || {}) },
});
export const base = (o = {}) => ({ inspect: { runtime: 'runsc', mismatches: [], canaryInEnv: false }, container: { exit: 0, timed_out: false, oom_killed: false }, canaryHits: 0, dns: [], conns: [], drops: [], egress: [], telemetryHasNonce: false, output: { bytes: 10 }, outputRecorded: true, report: null, ...o });

/** For every case, evidence of an attempt that was blocked and logged. */
export const GOOD = {
  'direct-ip': () => base({ trace: trace({ network: { connects: [conn('1.1.1.1', 443), conn('8.8.8.8', 53), conn('140.82.112.3', 443)], sends: [conn('8.8.8.8', 53)] } }) }),
  'doh-ip': () => base({
    trace: trace({ network: { connects: [conn('1.1.1.1', 443, { n: 2, failed: 2 }), conn('8.8.8.8', 443), conn('9.9.9.9', 443), ok({ family: 'AF_INET', addr: NETS.run.netlog, port: 443 })] } }),
    dns: [{ qname: 'dns.google', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: NETS.run.target }],
    conns: [{ from: NETS.run.target, proto: 'tcp', port: 443, bytes: 517, sni: 'dns.google' }],
  }),
  'raw-socket': () => base({ trace: trace({ network: { raw_sockets: 3, sockets: [fail({ family: 'AF_INET', type: 'SOCK_RAW', protocol: 'IPPROTO_TCP', raw: true, errno: 1 }), fail({ family: 'AF_INET', type: 'SOCK_RAW', protocol: 'IPPROTO_RAW', raw: true, errno: 1 }), fail({ family: 'AF_PACKET', type: 'SOCK_RAW', protocol: '0x300', raw: true, errno: 1 })] } }) }),
  ipv6: () => base({ trace: trace({ network: { connects: [fail({ family: 'AF_INET6', addr: '2606:4700:4700::1111', port: 443 }), fail({ family: 'AF_INET6', addr: 'fe80::1', port: 443 })], sends: [fail({ family: 'AF_INET6', addr: '2001:4860:4860::8888', port: 53 })] } }) }),
  icmp: () => base({
    trace: trace({ network: { sockets: [ok({ family: 'AF_INET', type: 'SOCK_DGRAM', protocol: 'IPPROTO_ICMP', n: 2 }), fail({ family: 'AF_INET', type: 'SOCK_RAW', protocol: 'IPPROTO_ICMP', raw: true, n: 2, failed: 2, errno: 1 })], sends: [conn('1.1.1.1', 0), ok({ family: 'AF_INET', addr: GW, port: 0 })] } }),
    drops: [{ chain: 'input', family: 4, proto: 'ICMP', src: NETS.run.target, dst: GW, dpt: null, icmp_type: 8, n: 1 }],
  }),
  'docker-host': () => base({
    trace: trace({ network: { connects: [ok({ family: 'AF_INET', addr: NETS.run.netlog, port: 2375 }), conn(GW, 2375, { errno: 4 }), conn(GW, 2376, { errno: 4 }), conn(GW, CANARY_PORT, { errno: 4 }), fail({ family: 'AF_UNIX', addr: '/var/run/docker.sock', port: null, errno: 2 })] } }),
    dns: [{ qname: 'host.docker.internal', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: NETS.run.target }],
    conns: [{ from: NETS.run.target, proto: 'tcp', port: 2375, bytes: 60, http: { method: 'GET', host: 'host.docker.internal', path: '/version' } }],
    drops: [{ chain: 'input', family: 4, proto: 'TCP', src: NETS.run.target, dst: GW, dpt: 2375, n: 3 }, { chain: 'input', family: 4, proto: 'TCP', src: NETS.run.target, dst: GW, dpt: CANARY_PORT, n: 3 }],
  }),
  metadata: () => base({
    trace: trace({ network: { connects: [conn('169.254.169.254', 80, { n: 2, failed: 2 }), conn('168.63.129.16', 80)] } }),
    dns: [{ qname: 'metadata.google.internal', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: NETS.run.target }],
    conns: [{ from: NETS.run.target, proto: 'tcp', port: 80, bytes: 90, http: { method: 'GET', host: 'metadata.google.internal', path: '/computeMetadata/v1/' } }],
  }),
  'install-proxy-host': () => base({
    trace: trace({ network: { connects: [ok({ family: 'AF_INET', addr: IN.proxy, port: 8080, n: 3 })] } }),
    egress: [{ host: 'registry.npmjs.org', port: 443, allowed: true, up: 517, down: 4096, ms: 180 }, proxyLine('example.com', 443, 'host not on the allowlist'), proxyLine('evil.example', 443, 'host not on the allowlist'), { host: 'example.com', port: null, method: 'GET', allowed: false, error: 'plain HTTP refused' }],
  }),
  'install-proxy-ip': () => base({
    trace: trace({ network: { connects: [ok({ family: 'AF_INET', addr: IN.proxy, port: 8080, n: 3 })] } }),
    egress: [proxyLine('1.1.1.1', 443, 'IP literal'), proxyLine('104.16.1.34', 443, 'IP literal'), proxyLine('[2606:4700:4700::1111]:443', null, 'not host:port')],
  }),
  'install-proxy-port': () => base({
    trace: trace({ network: { connects: [ok({ family: 'AF_INET', addr: IN.proxy, port: 8080, n: 3 })] } }),
    egress: [proxyLine('registry.npmjs.org', 80, 'port'), proxyLine('registry.npmjs.org', 22, 'port'), proxyLine('registry.npmjs.org', 8443, 'port')],
  }),
  'install-direct': () => base({
    trace: trace({ network: { connects: [conn('1.1.1.1', 443), conn('140.82.112.3', 443), conn('104.16.1.34', 443)], sends: [conn('8.8.8.8', 53)] } }),
    dns: [{ qname: 'registry.npmjs.org', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: IN.target }],
  }),
  'install-metadata': () => base({
    trace: trace({ network: { connects: [conn('169.254.169.254', 80, { n: 2, failed: 2 }), conn('168.63.129.16', 80), ok({ family: 'AF_INET', addr: IN.proxy, port: 8080, n: 2 })] } }),
    dns: [{ qname: 'metadata.google.internal', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: IN.target }],
    conns: [{ from: IN.target, proto: 'tcp', port: 80, bytes: 90, http: { method: 'GET', host: 'metadata.google.internal', path: '/computeMetadata/v1/' } }],
    egress: [proxyLine('169.254.169.254', 443, 'IP literal'), proxyLine('168.63.129.16', 443, 'IP literal')],
  }),
  'install-host': () => base({
    trace: trace({ network: { connects: [ok({ family: 'AF_INET', addr: IN.netlog, port: 2375 }), conn(IN.gateway, 2375, { errno: 4 }), conn(IN.gateway, 2376, { errno: 4 }), conn(IN.gateway, CANARY_PORT, { errno: 4 }), fail({ family: 'AF_UNIX', addr: '/var/run/docker.sock', port: null, errno: 2 })] } }),
    dns: [{ qname: 'host.docker.internal', qtype: 'A', answer: 'sinkhole', proto: 'udp', from: IN.target }],
    conns: [{ from: IN.target, proto: 'tcp', port: 2375, bytes: 60, http: { method: 'GET', host: 'host.docker.internal', path: '/version' } }],
    drops: [{ chain: 'input', family: 4, proto: 'TCP', src: IN.target, dst: IN.gateway, dpt: 2375, n: 3 }, { chain: 'input', family: 4, proto: 'TCP', src: IN.target, dst: IN.gateway, dpt: CANARY_PORT, n: 3 }],
  }),
  'env-token': () => base({ trace: trace({ credential_paths: [ok({ path: '/proc/self/environ', op: 'read' }), ok({ path: '/proc/1/environ', op: 'read' })] }), report: { case: 'env-token', result: { canary_in_env: 0, token_names: [], files: [{ ok: true, canary: 0 }] } } }),
  'write-outside': () => base({ trace: trace({ opens_outside: ['/etc/isk-1', '/usr/local/isk-1', '/opt/surface/forged-1.json', '/isk-1', '/proc/sys/kernel/hostname'].map((path) => fail({ path, op: 'write', call: 'openat', errno: 30 })), privileged: [fail({ name: 'mount', errno: 1 })] }) }),
  'fork-bomb': () => base({ trace: trace({ process: { clones: 512, clone_failed: 3 } }), report: { result: { bomb: { forked: 509, error: 'EAGAIN' } } } }),
  'symlink-escape': () => base({
    trace: trace({ links: ['/', '/etc', '/etc/shadow', '/proc/1/root', '/var/run/docker.sock', '/var/lib/docker', '/home/runner/work/_temp', '/opt/surface'].map((t, i) => ok({ kind: 'symlink', target: t, path: `/work/links-1/l0${i}` })).concat([ok({ kind: 'symlink', target: '/etc/passwd', path: '/work/lock/freeze.txt' }), ok({ kind: 'symlink', target: '/work/.isk-1-pkg', path: '/work/pkg' })]) }),
    stage: { readout: READOUT_PATHS.map((path) => ({ path, exit: 3, bytes: 0 })), host: { intact: true, planted: 0 } },
    report: { case: 'symlink-escape', result: { canary_seen: 0, attempts: [{ path: '/work/links-1/l01/isk-1', via: '/etc', ok: false, errno: 30 }] } },
  }),
  'unix-socket': () => base({
    trace: trace({ network: {
      connects: ['/var/run/docker.sock', '/run/containerd/containerd.sock', '/run/runsc/runsc.sock', '/run/dbus/system_bus_socket', '/dev/log', '\u0000/containerd-shim/moby/isk/shim.sock', '\u0000isk-absent'].map((addr) => fail({ family: 'AF_UNIX', addr, port: null, errno: 2 })),
      binds: [ok({ family: 'AF_UNIX', addr: '/work/isk-1.sock', port: null }), ok({ family: 'AF_UNIX', addr: '\u0000isk-listen-1', port: null }), ok({ family: 'AF_INET', addr: '0.0.0.0', port: CASE_LISTEN_PORT })],
    } }),
    stage: { reach: [{ to: `tcp ${NETS.run.target}:${CASE_LISTEN_PORT}`, ok: false, code: 'EHOSTUNREACH', bytes: 0 }, { to: 'unix /work/isk-1.sock', ok: false, code: 'ECONNREFUSED', bytes: 0 }, { to: 'abstract @isk-listen-1', ok: false, code: 'ECONNREFUSED', bytes: 0 }] },
    container: { exit: 137, timed_out: true, oom_killed: false },
  }),
  'install-archive-bomb': () => base({
    trace: trace({ opens_outside: ['/etc/isk-1-dotdot', '/etc/isk-1-abs', '/opt/surface/isk-1-abs', '/isk-1-root'].map((path) => fail({ path, op: 'write', call: 'openat', errno: 30 })) }),
    stage: { disk: { work_fs_mb: VOLUME_CAP.mb - 150, work_fs_inodes: VOLUME_CAP.inodes, work_used_mb: VOLUME_CAP.mb - 150, work_files: 40050, host_free_drop_mb: 3 } },
    report: { case: 'install-archive-bomb', result: { fallocate: { ok: false, errno: 28, error: 'ENOSPC' } } },
  }),
  'output-forgery': () => base({ trace: trace({ opens_outside: [fail({ path: '/opt/surface/telemetry.jsonl', op: 'write', errno: 30 })] }), output: { bytes: 700 } }),
};

