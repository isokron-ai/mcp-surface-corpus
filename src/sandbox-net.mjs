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

/**
 * The rules net-guard.sh makes, as patterns for `iptables -S` / `ip6tables -S` output: each of our
 * chains holds exactly its lines in order; DOCKER-USER, INPUT and FORWARD hold our jumps.
 */
const LIMIT = String.raw`-m limit --limit 20/s(?:ec|econd)? --limit-burst 200`;
// iptables -S leaves out --log-level when it is the default (4, warning).
const LOGR = (chain, prefix) => new RegExp(String.raw`^-A ${chain} ${LIMIT} -j LOG --log-prefix "?${prefix.replace(/ $/, String.raw`\s?`)}"?(?: --log-level 4)?$`);
const lit = (s) => new RegExp(`^${s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')}$`);
const [RUN_NET, INSTALL_NET] = [NETS.run.subnet, NETS.install.subnet];
export const FIREWALL = {
  v4: {
    'ISK-SBX': [lit(`-A ISK-SBX -s ${RUN_NET} -d ${RUN_NET} -j RETURN`), lit(`-A ISK-SBX -s ${INSTALL_NET} -d ${INSTALL_NET} -j RETURN`), LOGR('ISK-SBX', LOG_PREFIX.forward), lit('-A ISK-SBX -j DROP')],
    'ISK-SBX-IN': [LOGR('ISK-SBX-IN', LOG_PREFIX.input), lit('-A ISK-SBX-IN -j DROP')],
  },
  v6: {
    'ISK-SBX6': [LOGR('ISK-SBX6', LOG_PREFIX.forward6), lit('-A ISK-SBX6 -j DROP')],
    'ISK-SBX6-IN': [LOGR('ISK-SBX6-IN', LOG_PREFIX.input6), lit('-A ISK-SBX6-IN -j DROP')],
  },
  jumps: {
    v4: {
      'DOCKER-USER': [`-A DOCKER-USER -s ${SANDBOX_RANGE} -j ISK-SBX`, `-A DOCKER-USER -d ${SANDBOX_RANGE} -j ISK-SBX`, '-A DOCKER-USER -d 169.254.0.0/16 -j DROP', '-A DOCKER-USER -d 168.63.129.16/32 -j DROP'],
      INPUT: ['-A INPUT -i docker0 -j ISK-SBX-IN', '-A INPUT -i br-+ -j ISK-SBX-IN'],
    },
    v6: {
      FORWARD: ['-A FORWARD -i docker0 -j ISK-SBX6', '-A FORWARD -o docker0 -j ISK-SBX6', '-A FORWARD -i br-+ -j ISK-SBX6', '-A FORWARD -o br-+ -j ISK-SBX6'],
      INPUT: ['-A INPUT -i docker0 -j ISK-SBX6-IN', '-A INPUT -i br-+ -j ISK-SBX6-IN'],
    },
  },
};

/** `iptables -S CHAIN` (or ip6tables) as lines, directly or through `sudo -n`; null when neither works. */
function ruleLines(tool, chain, run) {
  for (const [cmd, argv] of [[tool, ['-S', chain]], ['sudo', ['-n', tool, '-S', chain]]]) {
    const r = run(cmd, argv, { encoding: 'utf8', timeout: 30_000 });
    if (r.status === 0) return String(r.stdout).split('\n').map((l) => l.trim()).filter((l) => l.startsWith('-A '));
  }
  return null;
}

/**
 * Problems with where our rules sit in a chain we share (DOCKER-USER, INPUT, the IPv6 FORWARD): each
 * must come before any other rule that could let a packet past it, that is any rule of someone else
 * that ends in ACCEPT, RETURN or a jump to another chain. A last rule `-A CHAIN -j RETURN` (Docker's
 * own end of DOCKER-USER) is fine, and so are other rules that drop, reject or log.
 */
export function jumpOrderProblems(tool, chain, got, want) {
  const mine = new Set(want);
  const lets = (l, i) => !mine.has(l) && /-j (?!DROP$|REJECT\b|LOG\b)\S+/.test(l) && !(i === got.length - 1 && l === `-A ${chain} -j RETURN`);
  const first = got.findIndex(lets);
  if (first < 0) return [];
  return want.filter((w) => got.indexOf(w) > first).map((w) => `${tool} ${chain}: ${w} comes after ${String(got[first]).slice(0, 120)}`);
}

/**
 * Whether net-guard.sh's firewall is live on this host now: each of our chains holds exactly the
 * rules it makes, DOCKER-USER, INPUT and the IPv6 FORWARD hold our jumps ahead of any rule that could
 * let a packet past them (jumpOrderProblems), and in FORWARD the jump to DOCKER-USER comes before any
 * ACCEPT. Returns the problems; an empty list means live.
 */
export function firewallProblems(run = spawnSync) {
  const out = [];
  for (const [fam, tool] of [['v4', 'iptables'], ['v6', 'ip6tables']]) {
    for (const [chain, want] of Object.entries(FIREWALL[fam])) {
      const got = ruleLines(tool, chain, run);
      if (got === null) { out.push(`${tool} ${chain} cannot be read`); continue; }
      const i = want.findIndex((re, k) => !re.test(got[k] ?? ''));
      if (got.length !== want.length || i >= 0) out.push(`${tool} ${chain} is not the chain net-guard.sh makes (${got.length} rules; ${i >= 0 ? `rule ${i + 1}: ${String(got[i] ?? 'missing').slice(0, 120)}` : 'extra rules'})`);
    }
    for (const [chain, want] of Object.entries(FIREWALL.jumps[fam])) {
      const got = ruleLines(tool, chain, run);
      if (got === null) { out.push(`${tool} ${chain} cannot be read`); continue; }
      for (const w of want) if (!got.includes(w)) out.push(`${tool} ${chain} lacks: ${w}`);
      out.push(...jumpOrderProblems(tool, chain, got, want));
    }
  }
  const fwd = ruleLines('iptables', 'FORWARD', run);
  if (fwd) {
    const j = fwd.indexOf('-A FORWARD -j DOCKER-USER');
    const a = fwd.findIndex((l) => / -j ACCEPT$/.test(l));
    if (j < 0) out.push('iptables FORWARD does not jump to DOCKER-USER');
    else if (a >= 0 && a < j) out.push('iptables FORWARD accepts traffic before DOCKER-USER');
  } else out.push('iptables FORWARD cannot be read');
  return out;
}

/**
 * Packets each of our chains logged and dropped so far (`iptables -L CHAIN -v -x -n`): when a chain
 * dropped more than it logged, its log hit the rate limit. { chain: { logged, dropped } }, or null.
 */
export function firewallCounts(run = spawnSync) {
  const out = {};
  for (const [fam, tool] of [['v4', 'iptables'], ['v6', 'ip6tables']]) {
    for (const chain of Object.keys(FIREWALL[fam])) {
      let text = null;
      for (const [cmd, argv] of [[tool, ['-L', chain, '-v', '-x', '-n']], ['sudo', ['-n', tool, '-L', chain, '-v', '-x', '-n']]]) {
        const r = run(cmd, argv, { encoding: 'utf8', timeout: 30_000 });
        if (r.status === 0) { text = String(r.stdout); break; }
      }
      if (text === null) return null;
      const c = { logged: 0, dropped: 0 };
      for (const l of text.split('\n')) {
        const m = /^\s*(\d+)\s+\d+\s+(LOG|DROP)\b/.exec(l);
        if (m) c[m[2] === 'LOG' ? 'logged' : 'dropped'] += Number(m[1]);
      }
      out[chain] = c;
    }
  }
  return out;
}
