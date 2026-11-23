#!/usr/bin/env node
/**
 * The network logger: the only name server and the sinkhole of a sandbox network. Ours, not a
 * target's. It runs in its own container at .2 of each sandbox network (src/sandbox-net.mjs NETS):
 *   - DNS on UDP and TCP port 53, for every name: an A query gets the logger's own address (so
 *     whatever a target looks up, it connects here next), PTR gets NXDOMAIN, any other type an empty
 *     answer; a query that is not a standard query is refused, one that cannot be read gets FORMERR;
 *   - the sinkhole, TCP on SINK_TCP and UDP on SINK_UDP: it reads what the client sends first (at
 *     most 4 KiB, at most 1.5 s), keeps the TLS server name (SNI), or the HTTP method, Host and path
 *     (the query string cut off), and the first bytes in hex, then closes without answering.
 *     Nothing reaches a real service.
 * One JSON line per query or connection on stdout ({ kind: 'dns' | 'conn', t, from, proto, ... }),
 * which the harness turns into run telemetry (src/telemetry.mjs fromNetlog). Every string in a line
 * came from a target and is printable, cut to size; past MAX_LINES lines are counted, not printed.
 *
 *   node netlog.mjs <own-address>
 */
import { createSocket } from 'node:dgram';
import { createServer, isIPv4 } from 'node:net';
import { parseQuestion, buildAnswer, RCODE } from '../src/dns.mjs';
import { SINK_TCP, SINK_UDP } from '../src/sandbox-net.mjs';

export const MAX_LINES = 20_000;
const FIRST_BYTES = 4096;
const FIRST_MS = 1500;
const MAX_OPEN = 256;

/** Untrusted bytes as printable text: [A-Za-z0-9] and a few marks kept, anything else \xHH. */
export function printable(buf, max = 253, lower = false) {
  let s = '';
  for (let b of buf) {
    if (lower && b >= 0x41 && b <= 0x5a) b += 0x20;
    const keep = (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x5a) || (b >= 0x61 && b <= 0x7a) || '-._~/%:@!$&()*+,;='.includes(String.fromCharCode(b));
    s += keep ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, '0')}`;
    if (s.length >= max) break;
  }
  return s.slice(0, max);
}

/** The answer to one DNS message and what to log about it; reply is null when nothing can be said. */
export function dnsReply(buf, own) {
  const q = parseQuestion(buf);
  if (!q) {
    if (!Buffer.isBuffer(buf) || buf.length < 12 || buf[2] & 0x80) return { reply: null, log: { qname: '', qtype: '', answer: 'formerr' } };
    const head = Buffer.from(buf.subarray(0, 12));
    head.writeUInt16BE(0x8000 | (buf[2] & 0x78) << 8 | RCODE.FORMERR, 2);
    head.fill(0, 4);
    return { reply: head, log: { qname: '', qtype: '', answer: 'formerr' } };
  }
  const log = { qname: q.name, qtype: q.type.slice(0, 10) };
  if (q.opcode !== 0 || q.qdcount !== 1 || q.qclass !== 1) return { reply: buildAnswer(buf, q, { rcode: RCODE.REFUSED }), log: { ...log, answer: 'refused' } };
  if (q.qtype === 1) return { reply: buildAnswer(buf, q, { a: own }), log: { ...log, answer: 'sinkhole' } };
  if (q.qtype === 12) return { reply: buildAnswer(buf, q, { rcode: RCODE.NXDOMAIN }), log: { ...log, answer: 'nxdomain' } };
  return { reply: buildAnswer(buf, q), log: { ...log, answer: 'empty' } };
}

/** The server name of a TLS ClientHello, or null. */
export function extractSni(buf) {
  try {
    if (buf.length < 9 || buf[0] !== 0x16 || buf[5] !== 0x01) return null;
    let o = 9 + 2 + 32;
    o += 1 + buf[o];
    o += 2 + buf.readUInt16BE(o);
    o += 1 + buf[o];
    const end = Math.min(buf.length, o + 2 + buf.readUInt16BE(o));
    o += 2;
    while (o + 4 <= end) {
      const type = buf.readUInt16BE(o); const len = buf.readUInt16BE(o + 2);
      if (type === 0 && o + 9 <= end && buf[o + 6] === 0) {
        const n = buf.readUInt16BE(o + 7);
        if (o + 9 + n > buf.length) return null;
        return printable(buf.subarray(o + 9, o + 9 + n), 253, true);
      }
      o += 4 + len;
    }
  } catch { /* a short or odd hello: no name */ }
  return null;
}

/** The method, Host and path (no query string, no fragment) of an HTTP request head, or null. */
export function parseHttpHead(buf) {
  const text = buf.subarray(0, Math.min(buf.length, FIRST_BYTES)).toString('latin1');
  const m = /^([A-Z]{3,10}) (\S{1,4096}) HTTP\/[0-9.]{1,3}\r?\n/.exec(text);
  if (!m) return null;
  let target = m[2]; let host = (/\r?\nhost:[ \t]*([^\r\n]*)/i.exec(text) || [])[1] ?? '';
  const abs = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)(.*)$/i.exec(target);
  if (abs) { host = host || abs[1]; target = abs[2] || '/'; }
  const path = target.replace(/[?#].*$/s, '');
  return { method: m[1].slice(0, 16), host: printable(Buffer.from(host.trim(), 'latin1'), 253, true), path: printable(Buffer.from(path, 'latin1'), 200) };
}

/** What a connection's first bytes say: { bytes, first_hex, sni?, http? }. */
export function describeFirst(buf) {
  const out = { bytes: buf.length, first_hex: buf.subarray(0, 32).toString('hex') };
  const sni = extractSni(buf); if (sni) out.sni = sni;
  const http = parseHttpHead(buf); if (http) out.http = http;
  return out;
}

const peer = (a) => (typeof a === 'string' ? a.replace(/^::ffff:/, '').slice(0, 64) : null);

/**
 * Starts the logger. Ports default to the real ones; the tests pass 0 (any free port) and a local
 * address. Resolves to { dns, tcp, udp, failed, close } with the ports actually bound.
 */
export async function startNetlog({ own, host = '0.0.0.0', dnsPort = 53, tcpPorts = SINK_TCP, udpPorts = SINK_UDP, log }) {
  if (!isIPv4(own)) throw new Error('netlog: the own address must be an IPv4 address');
  let lines = 0; let dropped = 0; let open = 0;
  const emit = (o) => { if (lines >= MAX_LINES) { dropped++; return; } lines++; log({ t: new Date().toISOString(), ...o }); };
  const closers = []; const failed = [];
  const udp = (port, onMsg) => new Promise((resolve) => {
    const s = createSocket('udp4');
    s.on('error', () => { failed.push(`udp/${port}`); try { s.close(); } catch { /* not bound */ } resolve(null); });
    s.on('message', (m, r) => onMsg(s, m, r));
    s.bind(port, host, () => { closers.push(() => s.close()); resolve(s.address().port); });
  });
  const tcp = (port, onConn) => new Promise((resolve) => {
    const srv = createServer({ pauseOnConnect: false }, (c) => {
      c.on('error', () => {});
      if (open >= MAX_OPEN) { emit({ kind: 'conn', from: peer(c.remoteAddress), proto: 'tcp', port: c.localPort, bytes: 0, error: 'too many connections' }); c.destroy(); return; }
      open++; c.on('close', () => { open--; });
      onConn(c);
    });
    srv.on('error', () => { failed.push(`tcp/${port}`); resolve(null); });
    srv.listen(port, host, () => { closers.push(() => srv.close()); resolve(srv.address().port); });
  });

  const dnsUdp = await udp(dnsPort, (s, m, r) => {
    const { reply, log: l } = dnsReply(m, own);
    emit({ kind: 'dns', from: peer(r.address), proto: 'udp', ...l });
    if (reply) s.send(reply, r.port, r.address);
  });
  const dnsTcp = await tcp(dnsPort, (c) => {
    let buf = Buffer.alloc(0); let n = 0;
    c.setTimeout(3000, () => c.destroy());
    c.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (buf.length > 70_000) { c.destroy(); return; }
      while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
        const len = buf.readUInt16BE(0); const msg = buf.subarray(2, 2 + len); buf = buf.subarray(2 + len);
        const { reply, log: l } = dnsReply(msg, own);
        emit({ kind: 'dns', from: peer(c.remoteAddress), proto: 'tcp', ...l });
        if (reply) { const h = Buffer.alloc(2); h.writeUInt16BE(reply.length); c.write(Buffer.concat([h, reply])); }
        if (++n >= 16) { c.end(); return; }
      }
    });
  });
  const tcpBound = []; const udpBound = [];
  for (const p of tcpPorts) {
    tcpBound.push(await tcp(p, (c) => {
      const chunks = []; let size = 0; let done = false;
      const finish = () => {
        if (done) return; done = true;
        emit({ kind: 'conn', from: peer(c.remoteAddress), proto: 'tcp', port: c.localPort, ...describeFirst(Buffer.concat(chunks).subarray(0, FIRST_BYTES)) });
        c.destroy();
      };
      const timer = setTimeout(finish, FIRST_MS);
      c.on('data', (d) => { chunks.push(d); size += d.length; if (size >= FIRST_BYTES) { clearTimeout(timer); finish(); } });
      c.on('end', () => { clearTimeout(timer); finish(); });
      c.on('close', () => { clearTimeout(timer); finish(); });
    }));
  }
  for (const p of udpPorts) {
    udpBound.push(await udp(p, (s, m, r) => {
      emit({ kind: 'conn', from: peer(r.address), proto: 'udp', port: s.address().port, ...describeFirst(m.subarray(0, FIRST_BYTES)) });
    }));
  }
  return {
    dns: { udp: dnsUdp, tcp: dnsTcp }, tcp: tcpBound, udp: udpBound, failed,
    stats: () => ({ lines, dropped }),
    close: () => { for (const c of closers) try { c(); } catch { /* already closed */ } },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const own = process.argv[2];
  const out = (o) => process.stdout.write(`${JSON.stringify(o)}\n`);
  if (!isIPv4(own ?? '')) { process.stderr.write('usage: netlog.mjs <own-address>\n'); process.exit(2); }
  const n = await startNetlog({ own, log: out });
  out({ kind: 'listening', own, dns: n.dns, tcp: n.tcp.length, udp: n.udp.length, failed: n.failed });
  for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => { out({ kind: 'stopped', ...n.stats() }); process.exit(0); });
}
