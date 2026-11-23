// The sandbox's networks, deny by default. Every container that runs target code is on an
// --internal Docker network of a fixed subnet (no route out), with our network logger at .2: it
// answers every DNS query with its own address (the sinkhole) and logs every query and every
// connection that reaches it. The install network also has the egress proxy at .3, the only way to
// a package registry. On the host, scripts/net-guard.sh logs and drops anything from or to these
// subnets that leaves its own network, and anything from a Docker bridge to the host itself; this
// module reads that log back (kernel log lines with our prefixes) into telemetry.
import { spawnSync } from 'node:child_process';

/** Both sandbox subnets sit in SANDBOX_RANGE; net-guard.sh drops anything to or from it that leaves its own /24. */
export const SANDBOX_RANGE = '10.213.52.0/22';
export const NETS = {
  run: { subnet: '10.213.53.0/24', gateway: '10.213.53.1', netlog: '10.213.53.2', target: '10.213.53.3', probe: '10.213.53.4', resolv: '/etc/isokron-sandbox/resolv-run.conf' },
  install: { subnet: '10.213.54.0/24', gateway: '10.213.54.1', netlog: '10.213.54.2', proxy: '10.213.54.3', target: '10.213.54.4', resolv: '/etc/isokron-sandbox/resolv-install.conf' },
};
export const RESOLV_DIR = '/etc/isokron-sandbox';
/** Kernel log prefixes of scripts/net-guard.sh's LOG rules (one per chain). */
export const LOG_PREFIX = { forward: 'isk-sbx-fwd: ', input: 'isk-sbx-in: ', forward6: 'isk-sbx-fwd6: ', input6: 'isk-sbx-in6: ' };
/** Ports the network logger listens on, TCP (the sinkhole) and UDP (QUIC, NTP and the like); 53 is DNS on both. */
export const SINK_TCP = [21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 853, 993, 1080, 2375, 2376, 3000, 3128, 3306, 4443, 5000, 5432, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017];
export const SINK_UDP = [123, 443, 853];

/** The resolv.conf a sandbox container gets (read-only): the network logger, nothing else. */
export const resolvConf = (net) => `# isokron sandbox: every name resolves to the network logger, which logs it\nnameserver ${NETS[net].netlog}\noptions ndots:0 timeout:1 attempts:1\n`;

const FIELD = /\b([A-Z]+)=(\S*)/g;
/**
 * Our firewall's log lines (journalctl -k -o short-unix, or dmesg) as drops:
 * { chain, family, proto, src, dst, spt, dpt, icmp_type, in, out, ts }. Other lines are ignored.
 */
export function parseKernelLog(text, { since = 0 } = {}) {
  const out = [];
  for (const line of String(text).split('\n')) {
    const chain = Object.keys(LOG_PREFIX).find((c) => line.includes(LOG_PREFIX[c]));
    if (!chain) continue;
    const ts = /^(\d{9,11}\.\d+)\s/.exec(line);
    const t = ts ? Number(ts[1]) : null;
    if (t !== null && t < since) continue;
    const f = {}; for (const m of line.slice(line.indexOf(LOG_PREFIX[chain])).matchAll(FIELD)) if (!(m[1] in f)) f[m[1]] = m[2];
    const num = (v) => (v !== undefined && /^\d+$/.test(v) ? Number(v) : null);
    const okIp = (v) => (v && /^[0-9a-fA-F:.]{2,64}$/.test(v) ? v : null);
    out.push({
      chain, family: chain.endsWith('6') ? 6 : 4, proto: String(f.PROTO ?? 'unknown').slice(0, 12),
      src: okIp(f.SRC), dst: okIp(f.DST), spt: num(f.SPT), dpt: num(f.DPT), icmp_type: num(f.TYPE),
      in: f.IN ? f.IN.slice(0, 16) : null, out: f.OUT ? f.OUT.slice(0, 16) : null, ts: t,
    });
  }
  return out;
}

/** Drops grouped by what was tried (chain, protocol, source, destination, port), with a count. */
export function groupDrops(drops, cap = 200) {
  const m = new Map();
  for (const d of drops) {
    const k = [d.chain, d.proto, d.src, d.dst, d.dpt, d.icmp_type].join(' ');
    const e = m.get(k);
    if (e) e.n++; else if (m.size < cap) m.set(k, { chain: d.chain, family: d.family, proto: d.proto, src: d.src, dst: d.dst, dpt: d.dpt, icmp_type: d.icmp_type, n: 1 });
  }
  return [...m.values()];
}

/**
 * The kernel log since a time (seconds since the epoch). The runner's user can read the journal on
 * GitHub's images; elsewhere `sudo -n` is tried (never a password prompt). { ok, text, via }.
 */
export function readHostLog(since, run = spawnSync) {
  const args = ['-k', '-o', 'short-unix', '--no-pager', '-q', `--since=@${Math.floor(since)}`];
  for (const [cmd, argv, via] of [['journalctl', args, 'journalctl'], ['sudo', ['-n', 'journalctl', ...args], 'sudo journalctl']]) {
    const r = run(cmd, argv, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 30_000 });
    if (r.status === 0) return { ok: true, text: r.stdout, via };
  }
  return { ok: false, text: '', via: null };
}
