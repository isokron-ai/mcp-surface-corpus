// The sandbox self test's verdicts. Each case runs selftest/hostile.py in the real sandbox and tries
// one way out; this module decides, from the harness's own evidence, whether the attempt was
// blocked and whether it was logged. The target's report (the last line it printed) is untrusted:
// it can make a case fail ("I got through"), never pass. A run that shows no attempt at all is a
// failure, not a pass: an empty trace proves nothing.
//
// Evidence, all gathered by bin/sandbox-selftest.mjs:
//   trace      the runsc syscall trace summary (src/trace-summary.mjs), or null
//   dns, conns the network logger's lines as telemetry fields (dns_query, connection)
//   drops      the host firewall's drops for this case (src/sandbox-net.mjs groupDrops)
//   canaryHits connections that reached the harness's listener on the host (must be 0)
//   inspect    { runtime, mismatches } from docker inspect against the settings manifest
//   container  { exit, timed_out, oom_killed }
//   telemetryHasNonce  whether the case's nonce shows up anywhere in the run telemetry
//   output     { bytes } of the target's stdout
//   report     the target's own report, or null
//   stage      what a later stage of ours saw of what the case left behind, after its container
//              ended or was torn down (bin/sandbox-selftest.mjs STAGES): the result readout over
//              planted links, connections to what the case left listening, the work volume's size
import { NETS } from './sandbox-net.mjs';
import { LIMITS, LOGS } from './docker.mjs';
import { loadRunscConfig } from './runsc.mjs';

/**
 * The install network's cases: the same hostile target, run the way an npm install with scripts
 * runs (the node24-build image, on the install network, HTTPS_PROXY pointing at the egress proxy,
 * which allows registry.npmjs.org on 443 and nothing else). That network is the most permissive
 * one: the proxy is its only door, and these cases try every other way through it and around it.
 */
export const INSTALL_CASES = ['install-proxy-host', 'install-proxy-ip', 'install-proxy-port', 'install-direct', 'install-metadata', 'install-host', 'install-archive-bomb', 'install-git-submodule'];
export const CASES = ['direct-ip', 'doh-ip', 'raw-socket', 'ipv6', 'icmp', 'docker-host', 'metadata', 'env-token', 'write-outside', 'fork-bomb', 'output-forgery', 'symlink-escape', 'unix-socket', 'output-flood', 'background', 'proc-sys', 'fd-exhaustion', 'clock-tamper', 'volume-tmpfs', 'work-overlay', ...INSTALL_CASES];
/** Where volume-tmpfs's container gets the tmpfs an image VOLUME gets in a corpus run (selftest/hostile.py VOLUME_CASE_PATH). */
export const VOLUME_CASE_PATH = '/isk-vol';
/**
 * work-overlay: the files the harness seeds in the case's work volume before it runs (as an install would leave them:
 * READOUT_PATHS among them), what the case writes through its layer (each must land in the layer's upper volume, the
 * positive control), and how much it fills there (LAYER_FILL_MB) before one allocation past the volume filesystem's cap.
 */
export const LAYER_SEED = ['/work/lock/freeze.txt', '/work/lock/go-version-m.txt', '/work/pkg/package-lock.json', '/work/venv/lib/site-packages/isk_seed.py', '/work/venv/bin/isk-tool'];
export const LAYER_WRITES = (nonce) => [`/work/isk-new-${nonce}`, `/work/fill-${nonce}`, `/work/venv/lib/site-packages/logs/isk-${nonce}.log`, '/work/lock/freeze.txt'];
export const LAYER_FILL_MB = 64;
/** The sandbox network a case runs on: 'install' for the install cases, else 'run'. */
export const caseNet = (name) => (INSTALL_CASES.includes(name) ? 'install' : 'run');
/** What the install cases ask the proxy for, which it must refuse (the proxy-allowlist mutation lets these through). */
export const PROXY_DENIED_HOSTS = ['example.com', 'evil.example'];
export const PROXY_ALLOWED = ['registry.npmjs.org'];
/** The port the harness listens on, on the host side of the run network, for the docker-host case. */
export const CANARY_PORT = 47123;
/** The port unix-socket's target listens on, for a later stage to try. */
export const CASE_LISTEN_PORT = 47124;
/**
 * The files the corpus reads out of a work volume after an install (src/targets.mjs launchPlan
 * locks), where symlink-escape plants its links: the last part a link to outside, or a folder above
 * it a link to elsewhere.
 */
export const READOUT_PATHS = ['/work/lock/freeze.txt', '/work/lock/go-version-m.txt', '/work/pkg/package-lock.json'];
/** The work volume's cap (gvisor.json volume_fs_mb, volume_fs_inodes) and the runner's disk an archive bomb may cost at most. */
const RUNSC = loadRunscConfig();
export const VOLUME_CAP = { mb: RUNSC.volume_fs_mb, inodes: RUNSC.volume_fs_inodes };
export const HOST_DROP_MB = 512;
/** What install-archive-bomb must have landed in its work volume: its gibibyte of zeros, at least. */
export const BOMB_LANDED_MB = 1024;
const EINPROGRESS = new Set([114, 115]);

const NET = NETS.run;
const list = (x) => (Array.isArray(x) ? x : []);
/** A traced call that never got through: every try failed, and not with "in progress" (which says nothing). */
const failedAll = (e) => e.n > 0 && e.failed === e.n && !EINPROGRESS.has(e.errno);
/**
 * For an outside address, failing is not enough: a connect cut short by the target's own alarm
 * (EINTR, ERESTARTSYS) says nothing about the route. Only a definite refusal counts: EPERM, EACCES,
 * ENETUNREACH, ECONNREFUSED, EHOSTUNREACH. (The host's own address is different: there the firewall
 * drops packets silently, a connect can only time out, and the drop log and the listener decide.)
 */
const REFUSED = new Set([1, 13, 101, 111, 113]);
const refusedAll = (e) => e.n > 0 && e.failed === e.n && REFUSED.has(e.errno);
const fmt = (e) => `${e.family ?? ''} ${e.addr ?? e.path ?? e.name ?? ''}${e.port !== undefined && e.port !== null ? `:${e.port}` : ''} failed ${e.failed}/${e.n}${e.errno !== null && e.errno !== undefined ? ` (errno ${e.errno})` : ''}`.trim().slice(0, 200);
const attemptsOf = (report) => {
  const r = report && typeof report === 'object' && report.result && typeof report.result === 'object' ? report.result : {};
  return [...list(r.attempts), ...list(r.by_name), ...list(r.files)].filter((a) => a && typeof a === 'object');
};
/** What the target says got through: an attempt that worked and received bytes, or opened or wrote something. */
const reportGotThrough = (report, pred = () => true) => attemptsOf(report).some((a) => a.ok === true && pred(a) && ((Number(a.received) > 0) || a.tls === true || a.opened === true || a.written === true || a.mounted === true));

function net(trace) {
  const n = (trace && trace.network) || {};
  return { connects: list(n.connects), sends: list(n.sends), sockets: list(n.sockets), binds: list(n.binds), raw: Number(n.raw_sockets) || 0 };
}
const to = (entries, addrs) => entries.filter((e) => addrs.includes(e.addr));
/** Trace entries of sendto calls, marked so a send that was not refused is not read as a connection made. */
const sent = (entries) => entries.map((e) => ({ ...e, call: 'sendto' }));

/**
 * Why calls to an outside address do not show a block, most serious first: `got through` (a traced
 * connect worked, a name got a real answer, or the target reports a reply), `nothing was tried` (too
 * few calls traced), or `no definite refusal`: a datagram was sent and not refused (whether it
 * arrived is not known), or every call failed but not with a refusal (cut short by the target's
 * alarm, or timed out). `other` is a further reason of the case. null when the calls show a block.
 */
function outsideWhy(att, min, { reported = false, other = null } = {}) {
  const worked = att.filter((e) => e.failed < e.n);
  const connected = worked.filter((e) => e.call !== 'sendto');
  if (connected.length) return `got through: ${connected.length} traced connection(s) to an outside address worked (${fmt(connected[0])})`;
  if (reported) return 'got through: the target reports a reply from outside';
  if (other) return `got through: ${other}`;
  if (worked.length) return `no definite refusal: ${worked.length} datagram(s) to an outside address were sent, not refused (${fmt(worked[0])}); whether any arrived is not known`;
  if (att.length < min) return `nothing was tried: ${att.length} call(s) traced, at least ${min} expected`;
  const soft = att.filter((e) => !refusedAll(e));
  if (soft.length) return `no definite refusal: every call failed, but ${soft.length} not with a refusal (${fmt(soft[0])}), so it was cut short or timed out, not refused`;
  return null;
}

function hostRule(ev, NETX) {
    const n = net(ev.trace);
    const q = list(ev.dns).find((d) => d.qname === 'host.docker.internal');
    const sink = list(ev.conns).find((c) => c.port === 2375);
    const gwTried = to(n.connects, [NETX.gateway]);
    const gwDrops = list(ev.drops).filter((d) => d.chain === 'input' && d.dst === NETX.gateway && [2375, 2376, CANARY_PORT].includes(d.dpt));
    const sockets = n.connects.filter((c) => c.family === 'AF_UNIX' && /(?:docker|containerd)\.sock$/.test(String(c.addr)));
    const blocked = ev.canaryHits === 0 && gwTried.length >= 2 && gwTried.every(failedAll) && sockets.length >= 1 && sockets.every(failedAll) && (!q || q.answer === 'sinkhole') && !reportGotThrough(ev.report);
    const logged = !!q && !!sink && gwDrops.length >= 1 && sockets.length >= 1;
    return verdict(blocked, logged, [`canary: ${ev.canaryHits} connection(s) reached the host listener`, ...gwTried.map((e) => `trace: ${fmt(e)}`), ...sockets.map((e) => `trace: ${fmt(e)}`), q ? `dns: ${q.qname} -> ${q.answer}` : 'dns: no query for the host name', sink ? `sinkhole: ${sink.http ? `${sink.http.method} ${sink.http.path}` : 'connection'} on 2375, closed unanswered` : 'sinkhole: nothing on 2375', ...gwDrops.map((d) => `host: ${d.proto} to ${d.dst}:${d.dpt} dropped x${d.n}`)], blocked ? 'neither the host, its Docker API nor a socket of it was reachable' : ev.canaryHits !== 0 ? `got through: ${ev.canaryHits ?? 'an unknown number of'} connection(s) reached the host listener` : gwTried.some((e) => e.failed < e.n) || sockets.some((e) => e.failed < e.n) ? 'got through: a connection to the host or one of its sockets worked' : q && q.answer !== 'sinkhole' ? `got through: host.docker.internal got a real answer (${q.answer})` : reportGotThrough(ev.report) ? 'got through: the target reports a reply from the host' : gwTried.length < 2 || sockets.length < 1 ? `nothing was tried: ${gwTried.length} host connection(s) and ${sockets.length} socket(s) traced, at least 2 and 1 expected` : 'no clear block: a call to the host ended "in progress", which says nothing');
  }

/** Egress proxy lines of a case (sandbox/egress-proxy.mjs, as `egress` telemetry). */
const egressOf = (ev) => list(ev.egress).filter((e) => e && typeof e === 'object');
/** What the proxy let through: any CONNECT it allowed to a host not on the allowlist. */
const letThrough = (ev) => egressOf(ev).filter((e) => e.allowed === true && !PROXY_ALLOWED.includes(e.host));

/**
 * The positive control: the proxy's own log has an allowed tunnel to the allowlisted registry on 443
 * that carried bytes back from it (`down`: the proxy answered 200 and relayed the registry's TLS
 * reply). Harness evidence: the proxy is our code, its log our record; the target's report is not used.
 */
const controlOf = (ev) => egressOf(ev).filter((e) => e.allowed === true && PROXY_ALLOWED.includes(e.host) && e.port === 443 && Number(e.down) > 0);

/**
 * A case that asks the egress proxy for something it must refuse: blocked when the proxy logged at
 * least `min` refusals for the reason `why` (and `plain` refusals of plain HTTP), let nothing through,
 * and the target reached the proxy (traced) without getting a tunnel (its report can only fail it).
 * With `control`, the proxy must also be shown to work: a proxy that refuses everything passes the
 * refusals and proves nothing.
 */
function proxyRule(ev, { why, min, plain = 0, what, control = false }) {
  const n = net(ev.trace);
  const proxy = NETS.install.proxy;
  const reached = to(n.connects, [proxy]).filter((e) => e.failed < e.n);
  const refused = egressOf(ev).filter((e) => e.allowed === false && e.error === why);
  const plainRefused = egressOf(ev).filter((e) => e.allowed === false && e.error === 'plain HTTP refused');
  const through = letThrough(ev);
  const tunnel = reportGotThrough(ev.report, (a) => a.tunnel === true && a.control !== true);
  const works = control ? controlOf(ev) : [];
  const shown = !control || works.length >= 1;
  const blocked = !through.length && refused.length >= min && plainRefused.length >= plain && reached.length >= 1 && !tunnel && shown;
  const logged = refused.length >= min && plainRefused.length >= plain && reached.length >= 1 && shown;
  const evidence = [...reached.slice(0, 4).map((e) => `trace: ${fmt(e)} (the proxy)`), ...egressOf(ev).slice(0, 12).map((e) => `proxy: ${e.host}${e.port ? `:${e.port}` : ''} ${e.allowed ? 'ALLOWED' : `refused (${e.error ?? 'no reason'})`}`)];
  const detail = blocked ? `the proxy refused every ${what} and let nothing through`
    : through.length ? `got through: the proxy let ${through[0].host}:${through[0].port ?? '?'} through`
      : tunnel ? 'got through: the target reports a tunnel through the proxy'
        : !reached.length ? 'nothing was tried: no traced connection reached the proxy'
          : !(refused.length >= min && plainRefused.length >= plain) ? `not logged: the proxy logged ${refused.length} refusal(s) for "${why}" (at least ${min} expected)${plain ? ` and ${plainRefused.length} of plain HTTP (at least ${plain})` : ''}`
            : `not shown to work: the proxy's log has no allowed tunnel to ${PROXY_ALLOWED.join(', ')}:443 that carried bytes back; a proxy that refuses everything proves nothing`;
  return verdict(blocked, logged, [...(control ? [works.length ? `proxy: ${works[0].host}:443 ALLOWED, ${works[0].up} bytes up, ${works[0].down} down (the positive control)` : 'proxy: no allowed tunnel to the registry (the positive control)'] : []), ...evidence], detail);
}

/** What a later stage saw (case_evidence.stage), as an object. */
const stageOf = (ev) => (ev && ev.stage && typeof ev.stage === 'object' && !Array.isArray(ev.stage) ? ev.stage : {});
const inside = (p) => /^\/(?:work|tmp)(?:\/|$)/.test(String(p));
const resultOf = (report) => (report && typeof report === 'object' && report.result && typeof report.result === 'object' ? report.result : {});

function verdict(blocked, logged, evidence, detail) {
  return { blocked: !!blocked, logged: !!logged, pass: !!blocked && !!logged, evidence: evidence.slice(0, 20).map((s) => String(s).slice(0, 200)), detail: String(detail).slice(0, 600) };
}

const RULES = {
  'direct-ip': (ev) => {
    const n = net(ev.trace);
    const att = [...to(n.connects, ['1.1.1.1', '8.8.8.8', '140.82.112.3']), ...sent(to(n.sends, ['8.8.8.8']))];
    const blocked = att.length >= 2 && att.every(refusedAll) && !reportGotThrough(ev.report);
    return verdict(blocked, att.length >= 2, att.map((e) => `trace: ${fmt(e)}`), blocked ? 'no connection to an outside address got through' : outsideWhy(att, 2, { reported: reportGotThrough(ev.report) }));
  },
  'doh-ip': (ev) => {
    const n = net(ev.trace);
    const att = to(n.connects, ['1.1.1.1', '8.8.8.8', '9.9.9.9']);
    const q = list(ev.dns).find((d) => d.qname === 'dns.google');
    const sink = list(ev.conns).find((c) => c.sni === 'dns.google');
    const blocked = att.length >= 3 && att.every(refusedAll) && (!q || q.answer === 'sinkhole') && !reportGotThrough(ev.report, (a) => a.tls === true || Number(a.received) > 0);
    const logged = att.length >= 3 && !!q && !!sink;
    return verdict(blocked, logged, [...att.map((e) => `trace: ${fmt(e)}`), q ? `dns: ${q.qname} ${q.qtype} -> ${q.answer}` : 'dns: no query for dns.google', sink ? `sinkhole: TLS hello for ${sink.sni} on ${sink.port}, closed unanswered` : 'sinkhole: no TLS hello'], blocked ? 'DNS over HTTPS reached neither a literal resolver address nor a real resolver by name' : outsideWhy(att, 3, { reported: reportGotThrough(ev.report, (a) => a.tls === true || Number(a.received) > 0), other: q && q.answer !== 'sinkhole' ? `dns.google got a real answer (${q.answer})` : null }));
  },
  'raw-socket': (ev) => {
    const raws = net(ev.trace).sockets.filter((s) => s.raw);
    // What the target says of its own capability sets (/proc/self/status): any capability left, even
    // only in the bounding set, fails the case. The report can only fail it: the settings check of
    // docker inspect (cap-drop ALL) is what a pass rests on.
    const caps = ev.report && ev.report.result && ev.report.result.caps && typeof ev.report.result.caps === 'object' ? ev.report.result.caps : null;
    const capsLeft = caps ? ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'].filter((k) => typeof caps[k] === 'string' && /[1-9a-f]/i.test(caps[k])) : [];
    const opened = raws.some((s) => s.failed < s.n) || reportGotThrough(ev.report);
    const blocked = raws.length >= 2 && raws.every(failedAll) && !opened && !capsLeft.length;
    const why = raws.length < 2 ? `nothing was tried: ${raws.length} raw socket call(s) traced, at least 2 expected` : opened ? 'got through: a raw or packet socket opened' : `got through: the target reports capabilities left (${capsLeft.map((k) => `${k} ${String(caps[k]).slice(0, 16)}`).join(', ')})`;
    return verdict(blocked, raws.length >= 2, [...raws.map((s) => `trace: socket ${s.family} ${s.type} ${s.protocol} failed ${s.failed}/${s.n} (errno ${s.errno})`), ...(caps ? [`target: ${['CapEff', 'CapBnd'].map((k) => `${k} ${String(caps[k] ?? '?').slice(0, 16)}`).join(' ')}`] : [])], blocked ? 'no raw or packet socket could be opened, and no capability is left' : why);
  },
  ipv6: (ev) => {
    const n = net(ev.trace);
    const v6 = [...n.connects, ...sent(n.sends)].filter((e) => e.family === 'AF_INET6');
    const v6sock = n.sockets.filter((s) => s.family === 'AF_INET6');
    const drops6 = list(ev.drops).filter((d) => d.family === 6);
    const tried = v6.length > 0 || v6sock.length > 0;
    const blocked = tried && v6.every(refusedAll) && (v6.length > 0 || v6sock.every(failedAll)) && !reportGotThrough(ev.report);
    return verdict(blocked, tried, [...v6.map((e) => `trace: ${fmt(e)}`), ...v6sock.filter(failedAll).map((s) => `trace: socket AF_INET6 failed (errno ${s.errno})`), ...drops6.map((d) => `host: ${d.chain} ${d.proto} dropped x${d.n}`)], blocked ? 'nothing got out over IPv6' : (outsideWhy(v6, 1, { reported: reportGotThrough(ev.report) }) ?? (tried ? 'got through: an IPv6 socket opened' : 'nothing was tried: no IPv6 call traced')));
  },
  icmp: (ev) => {
    const n = net(ev.trace);
    const socks = n.sockets.filter((s) => /ICMP\b|^0x1$|^1$/.test(String(s.protocol)) && s.family === 'AF_INET');
    const outside = sent(to(n.sends, ['1.1.1.1']));
    const gw = to(n.sends, [NET.gateway]);
    const dropped = list(ev.drops).some((d) => d.chain === 'input' && /^ICMP$/i.test(d.proto) && d.dst === NET.gateway);
    const gwSent = gw.some((e) => e.failed < e.n);
    const tried = socks.length > 0;
    const blocked = tried && (socks.every(failedAll) || (outside.every(refusedAll) && (!gwSent || dropped))) && !reportGotThrough(ev.report);
    const logged = tried && (!gwSent || dropped);
    return verdict(blocked, logged, [...socks.map((s) => `trace: socket ${s.type} ${s.protocol} failed ${s.failed}/${s.n}`), ...[...outside, ...gw].map((e) => `trace: sendto ${fmt(e)}`), dropped ? `host: ICMP to ${NET.gateway} dropped and logged` : 'host: no ICMP drop logged'], blocked ? 'no echo left the sandbox network or reached the host' : !tried ? 'nothing was tried: no ICMP socket traced' : (gwSent && !dropped) ? 'got through: an echo to the host was sent and the firewall logged no drop' : (outsideWhy(outside, 0, { reported: reportGotThrough(ev.report) }) ?? 'got through: an echo may have left'));
  },
  'docker-host': (ev) => hostRule(ev, NETS.run),
  metadata: (ev) => {
    const n = net(ev.trace);
    const att = to(n.connects, ['169.254.169.254', '168.63.129.16']);
    const q = list(ev.dns).find((d) => d.qname === 'metadata.google.internal');
    const c = list(ev.conns).find((x) => x.http && x.http.host === 'metadata.google.internal');
    const blocked = att.length >= 2 && att.every(refusedAll) && (!q || q.answer === 'sinkhole') && !reportGotThrough(ev.report);
    const logged = att.length >= 2 && !!q && !!c;
    return verdict(blocked, logged, [...att.map((e) => `trace: ${fmt(e)}`), q ? `dns: ${q.qname} -> ${q.answer}` : 'dns: no metadata name query', c ? `sinkhole: ${c.http.method} ${c.http.path}, closed unanswered` : 'sinkhole: no metadata request'], blocked ? 'no instance metadata or host agent address answered' : outsideWhy(att, 2, { reported: reportGotThrough(ev.report), other: q && q.answer !== 'sinkhole' ? `metadata.google.internal got a real answer (${q.answer})` : null }));
  },
  // The install network: through the proxy, and around it.
  'install-proxy-host': (ev) => proxyRule(ev, { why: 'host not on the allowlist', min: 2, plain: 1, what: 'host not on its allowlist, and plain HTTP', control: true }),
  'install-proxy-ip': (ev) => proxyRule(ev, { why: 'IP literal', min: 2, what: 'IP literal' }),
  'install-proxy-port': (ev) => proxyRule(ev, { why: 'port', min: 3, what: 'port but 443' }),
  'install-direct': (ev) => {
    const n = net(ev.trace);
    const att = [...to(n.connects, ['1.1.1.1', '140.82.112.3', '104.16.1.34']), ...sent(to(n.sends, ['8.8.8.8']))];
    const q = list(ev.dns).find((d) => d.qname === 'registry.npmjs.org');
    const through = letThrough(ev);
    const blocked = att.length >= 3 && att.every(refusedAll) && (!q || q.answer === 'sinkhole') && !through.length && !reportGotThrough(ev.report);
    const logged = att.length >= 3 && !!q;
    return verdict(blocked, logged, [...att.map((e) => `trace: ${fmt(e)}`), q ? `dns: ${q.qname} -> ${q.answer}` : 'dns: no query for registry.npmjs.org'], blocked ? 'nothing on the install network got out around the proxy' : through.length ? `got through: the proxy let ${through[0].host} through` : outsideWhy(att, 3, { reported: reportGotThrough(ev.report), other: q && q.answer !== 'sinkhole' ? `registry.npmjs.org got a real answer (${q.answer})` : null }) ?? 'not logged: no DNS query for registry.npmjs.org reached the logger');
  },
  'install-metadata': (ev) => {
    const n = net(ev.trace);
    const att = to(n.connects, ['169.254.169.254', '168.63.129.16']);
    const q = list(ev.dns).find((d) => d.qname === 'metadata.google.internal');
    const c = list(ev.conns).find((x) => x.http && x.http.host === 'metadata.google.internal');
    const viaProxy = egressOf(ev).filter((e) => e.allowed === false && ['169.254.169.254', '168.63.129.16'].includes(e.host));
    const through = letThrough(ev);
    const blocked = att.length >= 2 && att.every(refusedAll) && (!q || q.answer === 'sinkhole') && !through.length && !reportGotThrough(ev.report);
    const logged = att.length >= 2 && !!q && !!c && viaProxy.length >= 1;
    return verdict(blocked, logged, [...att.map((e) => `trace: ${fmt(e)}`), q ? `dns: ${q.qname} -> ${q.answer}` : 'dns: no metadata name query', c ? `sinkhole: ${c.http.method} ${c.http.path}, closed unanswered` : 'sinkhole: no metadata request', ...viaProxy.map((e) => `proxy: ${e.host}:${e.port ?? '?'} refused (${e.error ?? 'no reason'})`)], blocked ? (logged ? 'no instance metadata or host agent address answered, directly or through the proxy' : 'blocked, but the metadata request through the proxy was not logged') : through.length ? `got through: the proxy let ${through[0].host} through` : outsideWhy(att, 2, { reported: reportGotThrough(ev.report), other: q && q.answer !== 'sinkhole' ? `metadata.google.internal got a real answer (${q.answer})` : null }));
  },
  'install-host': (ev) => hostRule(ev, NETS.install),
  'env-token': (ev) => {
    const r = ev.report && ev.report.result && typeof ev.report.result === 'object' ? ev.report.result : null;
    const said = r ? (Number(r.canary_in_env) || 0) + list(r.files).reduce((s, f) => s + (Number(f && f.canary) || 0), 0) + list(r.token_names).length : 0;
    const creds = list(ev.trace && ev.trace.credential_paths).filter((p) => /\/environ$/.test(String(p.path)));
    const blocked = !!ev.inspect && ev.inspect.canaryInEnv === false && said === 0;
    return verdict(blocked, creds.length >= 1, [`inspect: ${ev.inspect && ev.inspect.canaryInEnv === false ? 'no host token in the container environment' : 'a host token value is in the container environment'}`, ...creds.map((p) => `trace: read ${p.path}${p.failed ? ` failed ${p.failed}/${p.n}` : ''}`)], blocked ? 'no runner or Actions token reached the target' : 'a token reached the target');
  },
  'write-outside': (ev) => {
    const w = list(ev.trace && ev.trace.opens_outside).filter((o) => o.op === 'write');
    const priv = list(ev.trace && ev.trace.privileged).filter((p) => p.name === 'mount');
    const blocked = w.length >= 4 && w.every(failedAll) && priv.every(failedAll) && !reportGotThrough(ev.report, (a) => !String(a.path || '').startsWith('/work/') && !String(a.path || '').startsWith('/tmp/'));
    return verdict(blocked, w.length >= 4, [...w.map((o) => `trace: write ${o.path} failed ${o.failed}/${o.n} (errno ${o.errno})`), ...priv.map((p) => `trace: mount failed ${p.failed}/${p.n}`)], blocked ? 'nothing was written outside the work folder and /tmp' : w.length < 4 ? `nothing was tried: ${w.length} write(s) outside traced, at least 4 expected` : w.some((o) => o.failed < o.n) ? `got through: a write outside the work folder worked (${String(w.find((o) => o.failed < o.n).path).slice(0, 80)})` : priv.some((p) => p.failed < p.n) ? 'got through: a mount worked' : 'got through: the target reports a write outside the work folder');
  },
  'fork-bomb': (ev) => {
    const p = (ev.trace && ev.trace.process) || { clones: 0, clone_failed: 0 };
    const limit = ev.pidsLimit ?? Number(LIMITS.nproc);
    const worked = p.clones - p.clone_failed;
    const said = ev.report && ev.report.result && ev.report.result.bomb ? Number(ev.report.result.bomb.forked) : 0;
    const blocked = p.clone_failed >= 1 && worked < limit && !(said >= limit);
    return verdict(blocked, p.clones >= 1, [`trace: ${p.clones} clone calls, ${p.clone_failed} refused, limit ${limit}`, `container: exit ${ev.container ? ev.container.exit : 'unknown'}${ev.container && ev.container.oom_killed ? ', killed for memory' : ''}`], blocked ? 'the process limit stopped the fork bomb' : 'the fork bomb was not stopped by the process limit, or did not run');
  },
  // Links planted to outside the work folder: reading or writing through them reaches only the
  // sandbox's own read-only root, and the result readout (our code, after the case) refuses a link
  // anywhere in a path instead of following it. The host's canary folder stays as it was.
  'symlink-escape': (ev) => {
    const out = list(ev.trace && ev.trace.links).filter((l) => l.kind === 'symlink' && !inside(l.target));
    const st = stageOf(ev);
    const ro = list(st.readout).filter((r) => r && typeof r === 'object');
    const host = st.host && typeof st.host === 'object' ? st.host : null;
    const read = ro.filter((r) => r.exit === 0 && Number(r.bytes) > 0);
    const refused = ro.filter((r) => r.exit === 3);
    const seen = Number(resultOf(ev.report).canary_seen) || 0;
    const wrote = reportGotThrough(ev.report, (a) => a.written === true && !inside(a.via));
    const hostOk = !!host && host.intact === true && host.planted === 0;
    const blocked = refused.length >= READOUT_PATHS.length && !read.length && hostOk && !seen && !wrote;
    const logged = out.length >= 6 && ro.length >= READOUT_PATHS.length && !!host;
    const detail = blocked ? 'no planted link led out: the readout refused every one, and the host\'s canary folder is as it was'
      : read.length ? `got through: the result readout followed a planted link (${String(read[0].path).slice(0, 80)}, ${Number(read[0].bytes)} bytes)`
        : host && host.planted > 0 ? `got through: ${host.planted} file(s) appeared in the host's canary folder`
          : host && host.intact === false ? 'got through: the host\'s canary file changed'
            : seen ? 'got through: the target reports reading the host\'s canary through a link'
              : wrote ? 'got through: the target reports a write through a link to outside the work folder'
                : !host || ro.length < READOUT_PATHS.length ? 'not measured: the later stage did not run'
                  : `nothing was tried: ${refused.length} of ${READOUT_PATHS.length} read-out paths held a link`;
    return verdict(blocked, logged, [...out.slice(0, 8).map((l) => `trace: symlink ${String(l.path).slice(0, 70)} -> ${String(l.target).slice(0, 70)}`), ...ro.map((r) => `readout: ${String(r.path).slice(0, 80)} ${r.exit === 3 ? 'refused (a link in the path)' : r.exit === 4 ? 'no such file' : `exit ${r.exit}, ${Number(r.bytes) || 0} bytes`}`), host ? `host: canary ${host.intact ? 'intact' : 'CHANGED'}, ${host.planted} new file(s)` : 'host: not checked'], detail);
  },
  // Unix sockets of the host (Docker, containerd, runsc, systemd), abstract ones, and listeners for
  // a later stage: nothing connects, and once the stage is torn down nothing it left answers.
  'unix-socket': (ev) => {
    const n = net(ev.trace);
    const socks = n.connects.filter((c) => c.family === 'AF_UNIX');
    // Only listeners that were really bound count, and the TCP one must answer while the case still
    // runs (the positive control): a later stage that reaches nothing proves nothing otherwise.
    const binds = n.binds.filter((b) => (b.family === 'AF_UNIX' || (b.family === 'AF_INET' && b.port === CASE_LISTEN_PORT)) && b.failed < b.n);
    const reach = list(stageOf(ev).reach).filter((r) => r && typeof r === 'object');
    const before = list(stageOf(ev).reach_before).filter((r) => r && typeof r === 'object');
    const control = before.some((r) => r.ok === true && /^tcp /.test(String(r.to)));
    const reached = reach.filter((r) => r.ok === true);
    const opened = socks.filter((e) => e.failed < e.n);
    const blocked = socks.length >= 6 && !opened.length && reach.length >= 3 && !reached.length && ev.canaryHits === 0 && !reportGotThrough(ev.report) && control && binds.length >= 2;
    const logged = socks.length >= 6 && binds.length >= 2 && reach.length >= 3 && control;
    const detail = blocked ? 'no host or abstract socket answered, and nothing the case left listening outlived it (its TCP listener answered while it ran)'
      : reached.length ? `got through: a later stage reached what the case left listening (${String(reached[0].to).slice(0, 80)})`
        : opened.length ? `got through: a unix socket connected (${fmt(opened[0])})`
          : ev.canaryHits !== 0 ? `got through: ${ev.canaryHits ?? 'an unknown number of'} connection(s) reached the host listener`
            : reportGotThrough(ev.report) ? 'got through: the target reports a reply on a socket'
              : reach.length < 3 ? 'not measured: the later stage did not run'
                : !control ? 'not shown to work: the later stage reached nothing while the case still ran, so reaching nothing after it proves nothing'
                  : `nothing was tried: ${socks.length} unix socket connect(s) and ${binds.length} listener(s) traced, at least 6 and 2 expected`;
    return verdict(blocked, logged, [...socks.slice(0, 8).map((e) => `trace: ${fmt(e)}`), ...binds.slice(0, 4).map((b) => `trace: bind ${fmt(b)}`), ...before.slice(0, 1).map((r) => `while it ran: ${String(r.to).slice(0, 80)} ${r.ok ? 'answered' : `no (${String(r.code ?? '?').slice(0, 20)})`}`), ...reach.map((r) => `later stage: ${String(r.to).slice(0, 80)} ${r.ok ? `ANSWERED (${Number(r.bytes) || 0} bytes)` : `no (${String(r.code ?? '?').slice(0, 20)})`}`)], detail);
  },
  // An archive that expands to more than the work volume may hold, with thousands of entries, deep
  // folders, and entries that climb out: unpacked entry by entry with every entry trusted, then one
  // allocation past the cap. The work volume's own filesystem stops it, the runner's disk does not
  // move, and nothing lands outside the work folder.
  'install-archive-bomb': (ev) => {
    const d = stageOf(ev).disk && typeof stageOf(ev).disk === 'object' ? stageOf(ev).disk : null;
    const climbs = list(ev.trace && ev.trace.opens_outside).filter((o) => o.op === 'write');
    const drop = d && Number.isInteger(d.host_free_drop_mb) ? d.host_free_drop_mb : null;
    const hostOk = drop !== null && drop < HOST_DROP_MB;
    const capOk = !!d && Number(d.work_fs_mb) > 0 && Number(d.work_fs_mb) <= VOLUME_CAP.mb * 1.05 && Number(d.work_fs_inodes) > 0 && Number(d.work_fs_inodes) <= VOLUME_CAP.inodes * 1.05;
    const r = resultOf(ev.report);
    const said = !!(r.fallocate && r.fallocate.ok === true);
    const landed = climbs.filter((o) => o.failed < o.n);
    // The positive control: the bomb really landed (its gibibyte of zeros at least, so /work was
    // writable), and the case ran to its end (so the allocation past the cap was tried).
    const filled = !!d && Number(d.work_used_mb) >= BOMB_LANDED_MB;
    const ran = !!ev.container && ev.container.exit === 0 && ev.container.timed_out === false;
    const intact = !!d && d.reservation_intact === true;
    const blocked = hostOk && capOk && climbs.length >= 3 && !landed.length && !said && filled && ran && intact;
    const logged = climbs.length >= 3 && !!d && drop !== null;
    const detail = blocked ? `the work volume's own filesystem (${Number(d.work_fs_mb)} MB, ${Number(d.work_fs_inodes)} inodes) held the bomb, the runner's disk did not move, and nothing climbed out`
      : !d ? 'not measured: no measurement of the work volume after the case'
        : drop === null ? 'not measured: the runner\'s free disk could not be read'
          : !hostOk ? `got through: the runner's disk lost ${drop} MB while the case ran (at most ${HOST_DROP_MB} MB allowed)`
          : !capOk ? `got through: the work volume's filesystem holds ${Number(d.work_fs_mb)} MB and ${Number(d.work_fs_inodes)} inodes, past its cap of ${VOLUME_CAP.mb} MB and ${VOLUME_CAP.inodes}`
            : !intact ? 'got through: the volume filesystem\'s image file has holes after the bomb: the runner\'s disk pays for what the volume holds'
              : landed.length ? `got through: an archive entry was written outside the work folder (${String(landed[0].path).slice(0, 80)})`
              : said ? 'got through: the target reports an allocation past the cap'
                : !filled ? `not shown to work: only ${Number(d.work_used_mb)} MB landed in the work volume (at least ${BOMB_LANDED_MB} expected), so the bomb never filled it`
                  : !ran ? `not shown to work: the case did not run to its end (exit ${ev.container ? ev.container.exit : 'unknown'}${ev.container && ev.container.timed_out ? ', time limit' : ''})`
                : `nothing was tried: ${climbs.length} write(s) outside the work folder traced, at least 3 expected`;
    return verdict(blocked, logged, [d ? `later stage: the work volume's filesystem is ${Number(d.work_fs_mb)} MB, ${Number(d.work_fs_inodes)} inodes; ${Number(d.work_used_mb)} MB in use` : 'later stage: no measurement', drop !== null ? `host: the runner's disk lost ${drop} MB while the case ran` : 'host: not measured', ...climbs.slice(0, 8).map((o) => `trace: write ${String(o.path).slice(0, 80)} failed ${o.failed}/${o.n} (errno ${o.errno})`), r.fallocate ? `target: allocation ${r.fallocate.ok ? 'worked' : `refused (${String(r.fallocate.error ?? '?').slice(0, 20)})`}` : 'target: no allocation reported'], detail);
  },
  // stdout without end: Docker keeps at most container_logs of it (gvisor.json), on its own
  // filesystem, and the runner's disk does not move. At least one whole log file must have been
  // kept (the flood happened).
  'output-flood': (ev) => {
    const bytes = ev.output ? Number(ev.output.bytes) || 0 : 0;
    const d = stageOf(ev).disk && typeof stageOf(ev).disk === 'object' ? stageOf(ev).disk : null;
    const drop = d && Number.isInteger(d.host_free_drop_mb) ? d.host_free_drop_mb : null;
    const file = LOGS.maxBytes / Number(LOGS.maxFile);
    const tried = bytes >= file;
    const capOk = bytes <= LOGS.maxBytes * 1.1;
    const hostOk = drop !== null && drop < HOST_DROP_MB;
    const blocked = tried && capOk && hostOk;
    const logged = tried && drop !== null && ev.outputRecorded === true;
    const mb = (b) => Math.round(b / 1048576);
    const detail = blocked ? `Docker kept ${mb(bytes)} MB of the flood (its cap ${mb(LOGS.maxBytes)} MB), and the runner's disk did not move`
      : !capOk ? `got through: Docker kept ${mb(bytes)} MB of the case's output, past its cap of ${mb(LOGS.maxBytes)} MB`
        : drop === null ? 'not measured: the runner\'s free disk could not be read'
          : !hostOk ? `got through: the runner's disk lost ${drop} MB while the case ran (at most ${HOST_DROP_MB} MB allowed)`
            : `nothing was tried: Docker kept ${mb(bytes)} MB of the case's output, less than one log file (${mb(file)} MB)`;
    return verdict(blocked, logged, [`output: Docker kept ${bytes} bytes (cap ${LOGS.maxBytes})`, drop !== null ? `host: the runner's disk lost ${drop} MB while the case ran` : 'host: not measured'], detail);
  },
  // A daemon (double fork, setsid) and a nohup-style child, both ignoring TERM, beating into the work
  // volume. While the case runs they must beat (the positive control); once its stage is torn down
  // nothing may beat on, and no process of it may be left on the host.
  background: (ev) => {
    const st = stageOf(ev);
    const before = list(st.grow_before).filter((g) => g && typeof g === 'object');
    const after = list(st.grow).filter((g) => g && typeof g === 'object');
    const beats = (g) => Number(g.after) > Number(g.before);
    const control = before.length >= 2 && before.every(beats);
    const grew = after.filter(beats);
    const procs = Number.isInteger(st.host_procs) ? st.host_procs : null;
    const clones = Number((ev.trace && ev.trace.process && ev.trace.process.clones) || 0);
    const blocked = control && after.length >= 2 && !grew.length && procs === 0;
    const logged = control && after.length >= 2 && clones >= 3;
    const detail = blocked ? 'nothing the case started outlived its stage: both heartbeats stopped when it was torn down'
      : grew.length ? `got through: a process of the case kept running after its stage was torn down (${String(grew[0].path).slice(0, 80)} grew ${Number(grew[0].after) - Number(grew[0].before)} bytes)`
        : procs !== null && procs > 0 ? `got through: ${procs} process(es) of the case outlived it on the host`
          : !control ? 'not shown to work: the heartbeats did not grow while the case ran, so their stopping proves nothing'
            : 'not measured: the later stage did not run';
    return verdict(blocked, logged, [`trace: ${clones} clone calls`, ...before.map((g) => `while it ran: ${String(g.path).slice(0, 70)} ${g.before} -> ${g.after} bytes`), ...after.map((g) => `after teardown: ${String(g.path).slice(0, 70)} ${g.before} -> ${g.after} bytes`), `host: ${procs ?? '?'} process(es) of the case`], detail);
  },
  // What /proc and /sys tell a target about the machine: none of the host's facts (its kernel, boot
  // id, machine id, host name, addresses, Docker's data-root) may show in what the target printed.
  'proc-sys': (ev) => {
    const hf = stageOf(ev).host_facts && typeof stageOf(ev).host_facts === 'object' ? stageOf(ev).host_facts : null;
    const checked = hf ? list(hf.checked) : [];
    const seen = hf ? list(hf.seen) : [];
    const reads = list(ev.trace && ev.trace.opens_outside).filter((o) => o.op === 'read' && /^\/(?:proc|sys)\//.test(String(o.path)));
    const bytes = ev.output ? Number(ev.output.bytes) || 0 : 0;
    const blocked = !!hf && checked.length >= 3 && !seen.length && bytes >= 2000;
    const logged = !!hf && reads.length >= 5;
    const detail = blocked ? `the target read /proc and /sys and printed ${bytes} bytes, with none of the ${checked.length} host facts in them`
      : seen.length ? `got through: the target's output holds host facts (${seen.join(', ').slice(0, 120)})`
        : !hf ? 'not measured: the harness did not look for host facts'
          : checked.length < 3 ? `not measured: only ${checked.length} host fact(s) could be read on the host`
            : `nothing was tried: the target printed ${bytes} bytes`;
    return verdict(blocked, logged, [`host: looked for ${checked.join(', ').slice(0, 150)}`, `output: ${bytes} bytes`, ...reads.slice(0, 8).map((o) => `trace: read ${String(o.path).slice(0, 80)}${o.failed ? ` failed ${o.failed}/${o.n}` : ''}`)], detail);
  },
  // Descriptors until refused: the process meets EMFILE at --ulimit nofile, and cannot raise it past.
  'fd-exhaustion': (ev) => {
    const s = net(ev.trace).sockets.find((x) => x.family === 'AF_UNIX' && /SOCK_DGRAM/.test(String(x.type)));
    const limit = Number(LIMITS.nofile);
    const worked = s ? s.n - s.failed : 0;
    const said = Number(resultOf(ev.report).opened) || 0;
    const blocked = !!s && s.failed >= 1 && s.errno === 24 && worked <= limit && said <= limit;
    const logged = !!s && s.n >= 100;
    const detail = blocked ? `the descriptor limit (${limit}) refused the ${worked + 1}th socket with EMFILE`
      : s && (worked > limit || said > limit) ? `got through: ${Math.max(worked, said)} descriptors opened, past the limit of ${limit}`
        : !s ? 'nothing was tried: no socket calls traced'
          : `not shown: the sockets stopped at ${worked} without EMFILE (errno ${s.errno})`;
    return verdict(blocked, logged, [s ? `trace: socket AF_UNIX SOCK_DGRAM ${s.n} calls, ${s.failed} refused (errno ${s.errno})` : 'trace: no socket calls', `limit: nofile ${limit}`], detail);
  },
  // Setting the clock is refused, the host's clock does not jump, and a time the target claims
  // (its measured_at, forged records) never becomes the harness's time in the telemetry.
  // The tmpfs over an image's VOLUME (R-CASE-28): its size cap holds under runsc (ENOSPC at 32 MiB). runsc does not
  // enforce the noexec option (seen on GitHub, gVisor 20261116.0: a script written there ran), as /tmp is exec anyway,
  // so the run is recorded, not judged. The write is traced (openat under the volume); write(2) itself is not, so the
  // case's report, when there is one, must show ENOSPC at or under the cap, and vetoes otherwise.
  'volume-tmpfs': (ev) => {
    const opened = list(ev.trace && ev.trace.opens_outside).filter((o) => o.op === 'write' && String(o.path).startsWith(VOLUME_CASE_PATH + '/fill-'));
    const runs = list(ev.trace && ev.trace.exec).filter((e) => String(e.path).startsWith(VOLUME_CASE_PATH + '/'));
    const r = ev.report ? resultOf(ev.report) : null;
    const fill = r && r.fill && typeof r.fill === 'object' ? r.fill : null;
    const capBytes = Number(String(LIMITS.volTmp).replace(/m$/, '')) * 1024 * 1024;
    const overfull = !!r && (!fill || fill.ok !== false || fill.errno !== 28 || !(Number(fill.bytes) <= capBytes));
    const blocked = opened.length >= 1 && !overfull;
    return verdict(blocked, opened.length >= 1, [...opened.map((o) => `trace: write ${o.path} (${o.n} open${o.n === 1 ? '' : 's'})`), ...(fill ? [`report: fill ${fill.ok === false ? `stopped with errno ${fill.errno}` : 'did not stop'} after ${Number(fill.bytes) || 0} bytes (cap ${capBytes})`] : []), ...runs.map((e) => `trace: exec ${e.path} ${e.failed ? `failed ${e.failed}/${e.n} (errno ${e.errno})` : 'ran (runsc does not enforce noexec; /tmp is exec too)'}`)],
      !opened.length ? 'nothing was tried: no write under the volume tmpfs traced' : blocked ? `the volume tmpfs stopped the write at its ${LIMITS.volTmp} cap${fill ? ' with ENOSPC' : ''}` : `got through: the volume tmpfs took ${Number(fill && fill.bytes) || 0} bytes, past its ${LIMITS.volTmp} cap or without ENOSPC`);
  },
  // The writable layer a package kind's server gets (src/docker.mjs writableLayer): /work an overlay over the case's work
  // volume (seeded first, as an install leaves it), /data a tmpfs. The case writes through the layer (a logs folder in
  // site-packages, a copy-up, a whiteout, 64 MiB), plants links out of it (to the host's canary folder too), replaces
  // the read-out files with links, tries hard links, mounts, umount, open_by_handle_at, trusted.overlay xattrs and a
  // whiteout device, writes outside, and allocates past the volume filesystem's cap. Blocked when the work volume under
  // the layer is exactly as seeded (and the read-out reads it, never a link), a fresh layer over it shows nothing the
  // case wrote, the case's layer is gone after its teardown, its filesystem is the capped one, the runner's disk and
  // the host canary did not move, and nothing outside /work, /tmp and /data was written. The positive controls: the
  // case's writes landed in the layer's upper volume, and the fresh layer shows the seeded work volume.
  'work-overlay': (ev) => {
    const st = stageOf(ev);
    const o = (x) => (x && typeof x === 'object' && !Array.isArray(x) ? x : null);
    const d = o(st.disk); const lw = o(st.lower); const fr = o(st.fresh); const host = o(st.host);
    const ro = list(st.readout).filter((r) => r && typeof r === 'object');
    const outsideW = list(ev.trace && ev.trace.opens_outside).filter((x) => x.op === 'write' && !/^\/data\//.test(String(x.path)));
    const dataW = list(ev.trace && ev.trace.opens_outside).filter((x) => x.op === 'write' && /^\/data\//.test(String(x.path)));
    const priv = list(ev.trace && ev.trace.privileged).filter((p) => ['mount', 'umount2', 'open_by_handle_at'].includes(p.name));
    // A mount over /work and an umount of it, at least (open_by_handle_at too, where runsc traces it): none may work.
    const privTried = ['mount', 'umount2'].every((n) => priv.some((p) => p.name === n));
    const links = list(ev.trace && ev.trace.links);
    const outLinks = links.filter((l) => l.kind === 'symlink' && !inside(l.target));
    const hard = links.filter((l) => l.kind === 'hard' && l.failed < l.n);
    const r = resultOf(ev.report);
    const drop = d && Number.isInteger(d.host_free_drop_mb) ? d.host_free_drop_mb : null;
    const capOk = !!d && Number(d.layer_fs_mb) > 0 && Number(d.layer_fs_mb) <= VOLUME_CAP.mb * 1.05 && Number(d.layer_fs_inodes) > 0 && Number(d.layer_fs_inodes) <= VOLUME_CAP.inodes * 1.05;
    const hostDiskOk = drop !== null && drop < HOST_DROP_MB;
    const hostOk = !!host && host.intact === true && host.planted === 0;
    const lowerOk = !!lw && lw.intact === true;
    const leaked = fr ? list(fr.leaked) : [];
    const freshOk = !!fr && fr.seeded === true && !leaked.length;
    const gone = st.layer_gone === true;
    const readOk = ro.length >= READOUT_PATHS.length && ro.every((x) => x.exit === 0 && Number(x.bytes) > 0 && x.seeded === true);
    const landed = !!d && Number(d.landed) >= LAYER_WRITES('x').length && Number(d.layer_bytes_mb) >= LAYER_FILL_MB - 1;
    const said = (k) => !!(r[k] && typeof r[k] === 'object' && r[k].ok === true);
    const dataFill = r.data_fill && typeof r.data_fill === 'object' ? r.data_fill : null;
    const capBytes = Number(String(LIMITS.volTmp).replace(/m$/, '')) * 1024 * 1024;
    const veto = !ev.report ? null
      : said('fallocate') ? 'the target reports an allocation past the volume filesystem\'s cap'
        : !dataFill || dataFill.ok !== false || dataFill.errno !== 28 || !(Number(dataFill.bytes) <= capBytes) ? `the target reports /data took ${Number(dataFill && dataFill.bytes) || 0} bytes, past its ${LIMITS.volTmp} cap or without ENOSPC`
          : list(r.xattrs).some((x) => x && x.ok === true && /^trusted\./.test(String(x.name))) ? 'the target reports setting a trusted.overlay attribute'
            : said('whiteout') ? 'the target reports making a whiteout device'
              : (Number(r.canary_seen) || 0) > 0 ? 'the target reports reading the host\'s canary through a link'
                : reportGotThrough(ev.report, (a) => a.written === true && !inside(a.via)) ? 'the target reports a write through a link to outside the work folder'
                  : null;
    const blocked = lowerOk && freshOk && gone && readOk && hostOk && hostDiskOk && capOk && outsideW.length >= 4 && outsideW.every(failedAll) && privTried && priv.every(failedAll) && !hard.length && landed && !veto;
    const logged = !!d && !!lw && !!fr && outsideW.length >= 4 && outLinks.length >= 6 && dataW.length >= 1 && drop !== null;
    const detail = blocked ? `the work volume under the layer is as seeded, a fresh layer shows none of the case's writes, its layer is gone, the layer's filesystem (${Number(d.layer_fs_mb)} MB) held the fill, and nothing left /work, /tmp and /data`
      : !d || !lw || !fr ? 'not measured: the later stage did not run'
        : !lowerOk ? `got through: the case's writes reached the work volume under the overlay (${Number(lw.changed) || 0} entr${Number(lw.changed) === 1 ? 'y' : 'ies'} changed)`
          : leaked.length ? `got through: a fresh layer over the same work volume shows what the case wrote (${String(leaked[0]).slice(0, 80)})`
            : !gone ? 'got through: the case\'s layer outlived its teardown'
              : !readOk ? `got through: the result readout did not read the seeded files (${ro.map((x) => `${String(x.path).slice(0, 40)} exit ${x.exit}`).join(', ').slice(0, 160) || 'no readout'})`
                : !host ? 'not measured: the host\'s canary folder was not checked'
                  : !hostOk ? `got through: ${host.planted > 0 ? `${host.planted} file(s) appeared in the host's canary folder` : 'the host\'s canary file changed'}`
                    : drop === null ? 'not measured: the runner\'s free disk could not be read'
                      : !hostDiskOk ? `got through: the runner's disk lost ${drop} MB while the case ran (at most ${HOST_DROP_MB} MB allowed)`
                        : !capOk ? `got through: the layer's filesystem holds ${Number(d.layer_fs_mb)} MB and ${Number(d.layer_fs_inodes)} inodes, past the volume cap of ${VOLUME_CAP.mb} MB and ${VOLUME_CAP.inodes}`
                          : outsideW.some((x) => x.failed < x.n) ? `got through: a write outside /work, /tmp and /data worked (${String(outsideW.find((x) => x.failed < x.n).path).slice(0, 80)})`
                            : priv.some((p) => p.failed < p.n) ? `got through: ${priv.find((p) => p.failed < p.n).name} worked`
                              : hard.length ? `got through: a hard link was made (${String(hard[0].path).slice(0, 60)} -> ${String(hard[0].target).slice(0, 60)})`
                                : veto ? `got through: ${veto}`
                                  : !landed ? `not shown to work: the case's writes did not land in the layer (${Number(d.landed) || 0} of ${LAYER_WRITES('x').length} found, ${Number(d.layer_bytes_mb) || 0} MB), so the layer was not shown writable`
                                    : !fr.seeded ? 'not shown to work: a fresh layer does not show the seeded work volume'
                                      : `nothing was tried: ${outsideW.length} write(s) outside traced (at least 4 expected), mount ${priv.some((p) => p.name === 'mount') ? 'traced' : 'not traced'}, umount2 ${priv.some((p) => p.name === 'umount2') ? 'traced' : 'not traced'}`;
    return verdict(blocked, logged, [
      `later stage: work volume under the layer ${lw ? (lw.intact ? 'as seeded' : `CHANGED (${Number(lw.changed) || 0})`) : 'not read'}${lw ? `, ${Number(lw.entries) || 0} entries` : ''}`,
      `later stage: a fresh layer ${fr ? `shows ${fr.seeded ? 'the seeded files' : 'NOT the seeded files'} and ${leaked.length ? `${leaked.length} of the case's writes` : 'none of the case\'s writes'}` : 'not made'}`,
      `later stage: the case's layer ${gone ? 'is gone' : st.layer_gone === false ? 'is STILL THERE' : 'not checked'} after its teardown`,
      d ? `later stage: the layer's filesystem is ${Number(d.layer_fs_mb)} MB, ${Number(d.layer_fs_inodes)} inodes; ${Number(d.landed) || 0} of ${LAYER_WRITES('x').length} writes and ${Number(d.layer_bytes_mb) || 0} MB in its upper volume` : 'later stage: no measurement',
      drop !== null ? `host: the runner's disk lost ${drop} MB while the case ran` : 'host: not measured',
      host ? `host: canary ${host.intact ? 'intact' : 'CHANGED'}, ${host.planted} new file(s)` : 'host: not checked',
      ...ro.map((x) => `readout: ${String(x.path).slice(0, 60)} exit ${x.exit}, ${Number(x.bytes) || 0} bytes${x.seeded ? ', as seeded' : ''}`),
      ...outsideW.slice(0, 4).map((x) => `trace: write ${String(x.path).slice(0, 70)} failed ${x.failed}/${x.n} (errno ${x.errno})`),
      ...priv.map((p) => `trace: ${p.name} failed ${p.failed}/${p.n} (errno ${p.errno})`),
      ...dataW.slice(0, 2).map((x) => `trace: write ${String(x.path).slice(0, 70)} (the /data tmpfs)`),
      `trace: ${outLinks.length} link(s) out of the layer, ${links.filter((l) => l.kind === 'hard').length} hard link call(s), ${hard.length} made`,
    ], detail);
  },
  'clock-tamper': (ev) => {
    const priv = list(ev.trace && ev.trace.privileged).filter((p) => p.name === 'settimeofday' || p.name === 'clock_settime');
    const c = stageOf(ev).clock && typeof stageOf(ev).clock === 'object' ? stageOf(ev).clock : null;
    const set = priv.filter((p) => p.failed < p.n);
    const drift = c && Number.isFinite(Number(c.drift_ms)) ? Math.abs(Number(c.drift_ms)) : null;
    // glibc sets the time of day through clock_settime, so the calls are counted, not their names.
    const calls = priv.reduce((n, p) => n + (Number(p.n) || 0), 0);
    const blocked = calls >= 2 && !set.length && !!c && c.forged_in_telemetry === false && drift !== null && drift < 2000;
    const logged = calls >= 2 && !!c;
    const detail = blocked ? 'the clock could not be set, the host\'s clock held, and no time the target claimed reached the telemetry'
      : set.length ? `got through: ${set[0].name} worked`
        : c && c.forged_in_telemetry === true ? 'got through: a time the target claimed reached the telemetry'
          : drift !== null && drift >= 2000 ? `got through: the host's clock moved ${drift} ms against its monotonic clock while the case ran`
            : !c ? 'not measured: the harness did not check the clock'
              : `nothing was tried: ${calls} clock call(s) traced, at least 2 expected`;
    return verdict(blocked, logged, [...priv.map((p) => `trace: ${p.name} failed ${p.failed}/${p.n} (errno ${p.errno})`), c ? `host: clock drift ${drift} ms; forged time in telemetry: ${c.forged_in_telemetry ? 'YES' : 'no'}` : 'host: not checked'], detail);
  },
  // Submodules over ext:: (would run a command), file:// and an outside host, and an npm git
  // dependency on another: ext:: never runs and file:// is not followed (git's own defaults, which
  // our refusal of GIT_ names in a target's environment keeps in force), the proxy refuses both
  // outside hosts, and the superproject itself clones (the positive control).
  'install-git-submodule': (ev) => {
    const ex = stageOf(ev).git && typeof stageOf(ev).git === 'object' ? stageOf(ev).git : null;
    const execs = list(ev.trace && ev.trace.exec);
    const marker = execs.filter((e) => /^\/tmp\/isk-ext-/.test(String(e.path)));
    const extRan = marker.length > 0 || (ex && ex.ext_ran === true);
    const fileFollowed = !!ex && ex.file_followed === true;
    const cloned = !!ex && ex.cloned === true;
    const through = letThrough(ev);
    // The submodules and the npm dependency were really tried: the proxy refused each one's own host
    // (sub.evil.example only a submodule update asks for, npm.evil.example only npm).
    const refused = egressOf(ev).filter((e) => e.allowed === false && /(?:^|\.)evil\.example$/.test(String(e.host)));
    const tried = refused.some((e) => e.host === 'sub.evil.example') && refused.some((e) => e.host === 'npm.evil.example');
    const gitRan = execs.some((e) => /\/git$/.test(String(e.path)) && e.failed < e.n);
    const blocked = cloned && tried && !extRan && !fileFollowed && !through.length;
    const logged = refused.length >= 1 && gitRan && !!ex;
    const detail = blocked ? 'the superproject cloned; ext:: never ran, file:// was not followed, and the proxy refused both outside hosts'
      : extRan ? 'got through: a submodule\'s ext:: transport ran'
        : fileFollowed ? 'got through: a file:// submodule was followed'
          : through.length ? `got through: the proxy let ${through[0].host} through`
            : !ex ? 'not measured: the later stage did not run'
              : !cloned ? 'not shown to work: the superproject did not clone, so nothing of its submodules was tried'
                : 'not shown to work: the proxy did not refuse both outside hosts (sub.evil.example for the submodule, npm.evil.example for npm), so not everything was tried';
    return verdict(blocked, logged, [ex ? `later stage: cloned ${ex.cloned}, file:// followed ${ex.file_followed}, ext:: ran ${ex.ext_ran}` : 'later stage: none', ...marker.map((e) => `trace: exec ${String(e.path).slice(0, 60)}`), ...refused.slice(0, 3).map((e) => `proxy: ${e.host}:${e.port ?? '?'} refused (${e.error ?? '?'})`), `trace: git ${gitRan ? 'ran' : 'did not run'}`], detail);
  },
  'output-forgery': (ev) => {
    const forged = list(ev.trace && ev.trace.opens_outside).filter((o) => o.op === 'write' && String(o.path).startsWith('/opt/surface/'));
    const bytes = ev.output ? Number(ev.output.bytes) || 0 : 0;
    const blocked = ev.telemetryHasNonce === false && bytes > 0 && forged.every(failedAll);
    const logged = bytes > 0 && ev.outputRecorded === true && forged.length >= 1;
    return verdict(blocked, logged, [`telemetry: the forged lines' nonce ${ev.telemetryHasNonce === false ? 'appears nowhere' : 'appears'}`, `output: ${bytes} bytes kept apart as untrusted, recorded by size and hash only`, ...forged.map((o) => `trace: write ${o.path} failed ${o.failed}/${o.n}`)], blocked ? 'forged results and telemetry stayed target output' : 'forged output reached the results, or nothing was printed');
  },
};

/**
 * Why a trace cannot carry a verdict: lines a target may have forged (a path with a line break in
 * it, src/trace-summary.mjs), a trace cut short, or a call that worked and found no place in a list.
 */
export function traceProblems(t) {
  if (!t) return [];
  const out = [];
  if (t.injection_suspected) out.push(`the trace has lines a target may have forged (${Number(t.headerless_lines) || 0} without a header, ${Number(t.broken_lines) || 0} cut short)`);
  if (t.truncated) out.push('the trace was cut at its size limit');
  const lost = Object.values(t.omitted_ok || {}).reduce((s, n) => s + (Number(n) || 0), 0);
  if (lost) out.push(`${lost} call(s) that worked were left out of the trace summary`);
  return out;
}

/**
 * The verdict of one case: { blocked, logged, pass, evidence, detail }. A container that was not the
 * declared sandbox (not runsc, or settings that differ from the manifest) is never "blocked", and
 * without a trace nothing is "logged".
 */
export function evaluateCase(name, ev = {}) {
  if (!Object.prototype.hasOwnProperty.call(RULES, name)) throw new Error(`no such self test case: ${String(name).slice(0, 40)}`);
  const v = RULES[name](ev);
  const pre = [];
  const ins = ev.inspect;
  if (!ins || ins.runtime !== 'runsc') pre.push(`not run under gVisor (runtime ${ins ? String(ins.runtime).slice(0, 20) : 'unknown'})`);
  else if (list(ins.mismatches).length) pre.push(`settings differ from the manifest: ${list(ins.mismatches).join('; ')}`);
  if (pre.length) { v.blocked = false; v.pass = false; v.detail = `${pre.join('; ')}; ${v.detail}`.slice(0, 600); }
  if (!ev.trace) { v.logged = false; v.pass = false; v.detail = `no syscall trace; ${v.detail}`.slice(0, 600); }
  const tq = traceProblems(ev.trace);
  if (tq.length) { v.blocked = false; v.pass = false; v.detail = `${tq.join('; ')}; ${v.detail}`.slice(0, 600); }
  v.evidence = [`runtime: ${ins ? String(ins.runtime).slice(0, 20) : 'unknown'}, settings ${ins && !list(ins.mismatches).length ? 'as declared' : 'differ'}`, ...v.evidence].slice(0, 20);
  return v;
}
