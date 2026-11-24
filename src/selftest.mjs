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
export const INSTALL_CASES = ['install-proxy-host', 'install-proxy-ip', 'install-proxy-port', 'install-direct', 'install-metadata', 'install-host', 'install-archive-bomb'];
export const CASES = ['direct-ip', 'doh-ip', 'raw-socket', 'ipv6', 'icmp', 'docker-host', 'metadata', 'env-token', 'write-outside', 'fork-bomb', 'output-forgery', 'symlink-escape', 'unix-socket', 'output-flood', ...INSTALL_CASES];
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
    const blocked = hostOk && capOk && climbs.length >= 3 && !landed.length && !said && filled && ran;
    const logged = climbs.length >= 3 && !!d && drop !== null;
    const detail = blocked ? `the work volume's own filesystem (${Number(d.work_fs_mb)} MB, ${Number(d.work_fs_inodes)} inodes) held the bomb, the runner's disk did not move, and nothing climbed out`
      : !d ? 'not measured: no measurement of the work volume after the case'
        : drop === null ? 'not measured: the runner\'s free disk could not be read'
          : !hostOk ? `got through: the runner's disk lost ${drop} MB while the case ran (at most ${HOST_DROP_MB} MB allowed)`
          : !capOk ? `got through: the work volume's filesystem holds ${Number(d.work_fs_mb)} MB and ${Number(d.work_fs_inodes)} inodes, past its cap of ${VOLUME_CAP.mb} MB and ${VOLUME_CAP.inodes}`
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
