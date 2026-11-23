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
import { NETS } from './sandbox-net.mjs';
import { LIMITS } from './docker.mjs';

export const CASES = ['direct-ip', 'doh-ip', 'raw-socket', 'ipv6', 'icmp', 'docker-host', 'metadata', 'env-token', 'write-outside', 'fork-bomb', 'output-forgery'];
/** The port the harness listens on, on the host side of the run network, for the docker-host case. */
export const CANARY_PORT = 47123;
const EINPROGRESS = new Set([114, 115]);

const NET = NETS.run;
const list = (x) => (Array.isArray(x) ? x : []);
/** A traced call that never got through: every try failed, and not with "in progress" (which says nothing). */
const failedAll = (e) => e.n > 0 && e.failed === e.n && !EINPROGRESS.has(e.errno);
const fmt = (e) => `${e.family ?? ''} ${e.addr ?? e.path ?? e.name ?? ''}${e.port !== undefined && e.port !== null ? `:${e.port}` : ''} failed ${e.failed}/${e.n}${e.errno !== null && e.errno !== undefined ? ` (errno ${e.errno})` : ''}`.trim().slice(0, 200);
const attemptsOf = (report) => {
  const r = report && typeof report === 'object' && report.result && typeof report.result === 'object' ? report.result : {};
  return [...list(r.attempts), ...list(r.by_name), ...list(r.files)].filter((a) => a && typeof a === 'object');
};
/** What the target says got through: an attempt that worked and received bytes, or opened or wrote something. */
const reportGotThrough = (report, pred = () => true) => attemptsOf(report).some((a) => a.ok === true && pred(a) && ((Number(a.received) > 0) || a.tls === true || a.opened === true || a.written === true || a.mounted === true));

function net(trace) {
  const n = (trace && trace.network) || {};
  return { connects: list(n.connects), sends: list(n.sends), sockets: list(n.sockets), raw: Number(n.raw_sockets) || 0 };
}
const to = (entries, addrs) => entries.filter((e) => addrs.includes(e.addr));

function verdict(blocked, logged, evidence, detail) {
  return { blocked: !!blocked, logged: !!logged, pass: !!blocked && !!logged, evidence: evidence.slice(0, 20).map((s) => String(s).slice(0, 200)), detail: String(detail).slice(0, 600) };
}

const RULES = {
  'direct-ip': (ev) => {
    const n = net(ev.trace);
    const att = [...to(n.connects, ['1.1.1.1', '8.8.8.8', '140.82.112.3']), ...to(n.sends, ['8.8.8.8'])];
    const blocked = att.length >= 2 && att.every(failedAll) && !reportGotThrough(ev.report);
    return verdict(blocked, att.length >= 2, att.map((e) => `trace: ${fmt(e)}`), blocked ? 'no connection to an outside address got through' : 'an outside address was reached, or nothing was tried');
  },
  'doh-ip': (ev) => {
    const n = net(ev.trace);
    const att = to(n.connects, ['1.1.1.1', '8.8.8.8', '9.9.9.9']);
    const q = list(ev.dns).find((d) => d.qname === 'dns.google');
    const sink = list(ev.conns).find((c) => c.sni === 'dns.google');
    const blocked = att.length >= 3 && att.every(failedAll) && (!q || q.answer === 'sinkhole') && !reportGotThrough(ev.report, (a) => a.tls === true || Number(a.received) > 0);
    const logged = att.length >= 3 && !!q && !!sink;
    return verdict(blocked, logged, [...att.map((e) => `trace: ${fmt(e)}`), q ? `dns: ${q.qname} ${q.qtype} -> ${q.answer}` : 'dns: no query for dns.google', sink ? `sinkhole: TLS hello for ${sink.sni} on ${sink.port}, closed unanswered` : 'sinkhole: no TLS hello'], blocked ? 'DNS over HTTPS reached neither a literal resolver address nor a real resolver by name' : 'a DNS over HTTPS exchange may have completed, or nothing was tried');
  },
  'raw-socket': (ev) => {
    const raws = net(ev.trace).sockets.filter((s) => s.raw);
    const blocked = raws.length >= 2 && raws.every(failedAll) && !reportGotThrough(ev.report);
    return verdict(blocked, raws.length >= 2, raws.map((s) => `trace: socket ${s.family} ${s.type} ${s.protocol} failed ${s.failed}/${s.n} (errno ${s.errno})`), blocked ? 'no raw or packet socket could be opened' : 'a raw socket was opened, or none was tried');
  },
  ipv6: (ev) => {
    const n = net(ev.trace);
    const v6 = [...n.connects, ...n.sends].filter((e) => e.family === 'AF_INET6');
    const v6sock = n.sockets.filter((s) => s.family === 'AF_INET6');
    const drops6 = list(ev.drops).filter((d) => d.family === 6);
    const tried = v6.length > 0 || v6sock.length > 0;
    const blocked = tried && v6.every(failedAll) && (v6.length > 0 || v6sock.every(failedAll)) && !reportGotThrough(ev.report);
    return verdict(blocked, tried, [...v6.map((e) => `trace: ${fmt(e)}`), ...v6sock.filter(failedAll).map((s) => `trace: socket AF_INET6 failed (errno ${s.errno})`), ...drops6.map((d) => `host: ${d.chain} ${d.proto} dropped x${d.n}`)], blocked ? 'nothing got out over IPv6' : 'an IPv6 connection got through, or nothing was tried');
  },
  icmp: (ev) => {
    const n = net(ev.trace);
    const socks = n.sockets.filter((s) => /ICMP\b|^0x1$|^1$/.test(String(s.protocol)) && s.family === 'AF_INET');
    const outside = to(n.sends, ['1.1.1.1']);
    const gw = to(n.sends, [NET.gateway]);
    const dropped = list(ev.drops).some((d) => d.chain === 'input' && /^ICMP$/i.test(d.proto) && d.dst === NET.gateway);
    const gwSent = gw.some((e) => e.failed < e.n);
    const tried = socks.length > 0;
    const blocked = tried && (socks.every(failedAll) || (outside.every(failedAll) && (!gwSent || dropped))) && !reportGotThrough(ev.report);
    const logged = tried && (!gwSent || dropped);
    return verdict(blocked, logged, [...socks.map((s) => `trace: socket ${s.type} ${s.protocol} failed ${s.failed}/${s.n}`), ...[...outside, ...gw].map((e) => `trace: sendto ${fmt(e)}`), dropped ? `host: ICMP to ${NET.gateway} dropped and logged` : 'host: no ICMP drop logged'], blocked ? 'no echo left the sandbox network or reached the host' : 'an echo may have got through, or nothing was tried');
  },
  'docker-host': (ev) => {
    const n = net(ev.trace);
    const q = list(ev.dns).find((d) => d.qname === 'host.docker.internal');
    const sink = list(ev.conns).find((c) => c.port === 2375);
    const gwTried = to(n.connects, [NET.gateway]);
    const gwDrops = list(ev.drops).filter((d) => d.chain === 'input' && d.dst === NET.gateway && [2375, 2376, CANARY_PORT].includes(d.dpt));
    const sockets = n.connects.filter((c) => c.family === 'AF_UNIX' && /(?:docker|containerd)\.sock$/.test(String(c.addr)));
    const blocked = ev.canaryHits === 0 && gwTried.length >= 2 && gwTried.every(failedAll) && sockets.length >= 1 && sockets.every(failedAll) && (!q || q.answer === 'sinkhole') && !reportGotThrough(ev.report);
    const logged = !!q && !!sink && gwDrops.length >= 1 && sockets.length >= 1;
    return verdict(blocked, logged, [`canary: ${ev.canaryHits} connection(s) reached the host listener`, ...gwTried.map((e) => `trace: ${fmt(e)}`), ...sockets.map((e) => `trace: ${fmt(e)}`), q ? `dns: ${q.qname} -> ${q.answer}` : 'dns: no query for the host name', sink ? `sinkhole: ${sink.http ? `${sink.http.method} ${sink.http.path}` : 'connection'} on 2375, closed unanswered` : 'sinkhole: nothing on 2375', ...gwDrops.map((d) => `host: ${d.proto} to ${d.dst}:${d.dpt} dropped x${d.n}`)], blocked ? 'neither the host, its Docker API nor a socket of it was reachable' : 'something on the host was reached, or nothing was tried');
  },
  metadata: (ev) => {
    const n = net(ev.trace);
    const att = to(n.connects, ['169.254.169.254', '168.63.129.16']);
    const q = list(ev.dns).find((d) => d.qname === 'metadata.google.internal');
    const c = list(ev.conns).find((x) => x.http && x.http.host === 'metadata.google.internal');
    const blocked = att.length >= 2 && att.every(failedAll) && (!q || q.answer === 'sinkhole') && !reportGotThrough(ev.report);
    const logged = att.length >= 2 && !!q && !!c;
    return verdict(blocked, logged, [...att.map((e) => `trace: ${fmt(e)}`), q ? `dns: ${q.qname} -> ${q.answer}` : 'dns: no metadata name query', c ? `sinkhole: ${c.http.method} ${c.http.path}, closed unanswered` : 'sinkhole: no metadata request'], blocked ? 'no instance metadata or host agent address answered' : 'a metadata address was reached, or nothing was tried');
  },
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
    return verdict(blocked, w.length >= 4, [...w.map((o) => `trace: write ${o.path} failed ${o.failed}/${o.n} (errno ${o.errno})`), ...priv.map((p) => `trace: mount failed ${p.failed}/${p.n}`)], blocked ? 'nothing was written outside the work folder and /tmp' : 'a write outside the work folder worked, or nothing was tried');
  },
  'fork-bomb': (ev) => {
    const p = (ev.trace && ev.trace.process) || { clones: 0, clone_failed: 0 };
    const limit = ev.pidsLimit ?? Number(LIMITS.nproc);
    const worked = p.clones - p.clone_failed;
    const said = ev.report && ev.report.result && ev.report.result.bomb ? Number(ev.report.result.bomb.forked) : 0;
    const blocked = p.clone_failed >= 1 && worked < limit && !(said >= limit);
    return verdict(blocked, p.clones >= 1, [`trace: ${p.clones} clone calls, ${p.clone_failed} refused, limit ${limit}`, `container: exit ${ev.container ? ev.container.exit : 'unknown'}${ev.container && ev.container.oom_killed ? ', killed for memory' : ''}`], blocked ? 'the process limit stopped the fork bomb' : 'the fork bomb was not stopped by the process limit, or did not run');
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
  v.evidence = [`runtime: ${ins ? String(ins.runtime).slice(0, 20) : 'unknown'}, settings ${ins && !list(ins.mismatches).length ? 'as declared' : 'differ'}`, ...v.evidence].slice(0, 20);
  return v;
}
