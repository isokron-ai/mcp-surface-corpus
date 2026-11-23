// Evidence of a working sandbox for every self test case, shared by the verdict tests
// (test/selftest.test.mjs) and the telemetry check tests (test/check-selftest.test.mjs).
import { CANARY_PORT } from '../src/selftest.mjs';
import { NETS } from '../src/sandbox-net.mjs';

export const GW = NETS.run.gateway;
export const fail = (o) => ({ n: 1, failed: 1, errno: 101, ...o });
export const ok = (o) => ({ n: 1, failed: 0, errno: null, ...o });
export const conn = (addr, port, o = {}) => fail({ family: 'AF_INET', addr, port, ...o });
export const trace = (o = {}) => ({
  format: 'isokron-trace-summary/1', opens_outside: [], credential_paths: [], exec: [], privileged: [],
  process: { clones: 0, clone_failed: 0 },
  ...o,
  network: { sockets: [], raw_sockets: 0, connects: [], sends: [], binds: [], dns_names: [], ...(o.network || {}) },
});
export const base = (o = {}) => ({ inspect: { runtime: 'runsc', mismatches: [], canaryInEnv: false }, container: { exit: 0, timed_out: false, oom_killed: false }, canaryHits: 0, dns: [], conns: [], drops: [], telemetryHasNonce: false, output: { bytes: 10 }, outputRecorded: true, report: null, ...o });

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
  'env-token': () => base({ trace: trace({ credential_paths: [ok({ path: '/proc/self/environ', op: 'read' }), ok({ path: '/proc/1/environ', op: 'read' })] }), report: { case: 'env-token', result: { canary_in_env: 0, token_names: [], files: [{ ok: true, canary: 0 }] } } }),
  'write-outside': () => base({ trace: trace({ opens_outside: ['/etc/isk-1', '/usr/local/isk-1', '/opt/surface/forged-1.json', '/isk-1', '/proc/sys/kernel/hostname'].map((path) => fail({ path, op: 'write', call: 'openat', errno: 30 })), privileged: [fail({ name: 'mount', errno: 1 })] }) }),
  'fork-bomb': () => base({ trace: trace({ process: { clones: 512, clone_failed: 3 } }), report: { result: { bomb: { forked: 509, error: 'EAGAIN' } } } }),
  'output-forgery': () => base({ trace: trace({ opens_outside: [fail({ path: '/opt/surface/telemetry.jsonl', op: 'write', errno: 30 })] }), output: { bytes: 700 } }),
};

