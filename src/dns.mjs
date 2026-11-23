// The few pieces of DNS the sandbox needs: read the question of a query (from the network logger,
// and from a traced sendto), and build the logger's answer (the sinkhole address, an empty answer,
// or NXDOMAIN). Every name is untrusted bytes; it is kept as printable text, at most 253 characters.

export const QTYPES = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS', 255: 'ANY' };
export const RCODE = { NOERROR: 0, FORMERR: 1, SERVFAIL: 2, NXDOMAIN: 3, NOTIMP: 4, REFUSED: 5 };

const printable = (b) => (b >= 0x30 && b <= 0x39) || (b >= 0x61 && b <= 0x7a) || b === 0x2d || b === 0x5f;

/** One label's bytes as text: lower case, anything but [a-z0-9-_] as \xHH. */
function labelText(bytes) {
  let s = '';
  for (let b of bytes) { if (b >= 0x41 && b <= 0x5a) b += 0x20; s += printable(b) ? String.fromCharCode(b) : `\\x${b.toString(16).padStart(2, '0')}`; }
  return s;
}

/**
 * The header and first question of a DNS message (no compression is allowed in a question).
 * Returns null when it is not one: too short, a response, no question, a label past the end.
 */
export function parseQuestion(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 17) return null;
  const id = buf.readUInt16BE(0); const flags = buf.readUInt16BE(2); const qd = buf.readUInt16BE(4);
  if (flags & 0x8000) return null;
  if (qd < 1) return null;
  const labels = []; let o = 12; let len = 0;
  for (;;) {
    if (o >= buf.length) return null;
    const n = buf[o];
    if (n === 0) { o += 1; break; }
    if (n & 0xc0) return null;
    if (o + 1 + n > buf.length) return null;
    labels.push(buf.subarray(o + 1, o + 1 + n));
    len += n + 1; o += 1 + n;
    if (len > 255 || labels.length > 127) return null;
  }
  if (o + 4 > buf.length) return null;
  const qtype = buf.readUInt16BE(o); const qclass = buf.readUInt16BE(o + 2);
  const name = labels.map(labelText).join('.').slice(0, 253) || '.';
  return { id, flags, opcode: (flags >> 11) & 0xf, rd: !!(flags & 0x100), qdcount: qd, name, qtype, type: QTYPES[qtype] ?? String(qtype), qclass, end: o + 4 };
}

/**
 * The answer to one query: header and question echoed, then either one A record (`a`, dotted quad,
 * TTL 5 s), nothing (NOERROR, empty: the AAAA of a sinkholed name) or an error rcode.
 */
export function buildAnswer(query, q, { a = null, rcode = RCODE.NOERROR } = {}) {
  const question = query.subarray(12, q.end);
  const head = Buffer.alloc(12);
  head.writeUInt16BE(q.id, 0);
  // QR, the query's opcode, AA, the query's RD, RA; then the rcode.
  head.writeUInt16BE(0x8000 | (q.opcode << 11) | 0x0400 | (q.rd ? 0x0100 : 0) | 0x0080 | (rcode & 0xf), 2);
  head.writeUInt16BE(1, 4);
  const answer = a && rcode === RCODE.NOERROR ? Buffer.concat([Buffer.from([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4]), Buffer.from(a.split('.').map(Number))]) : Buffer.alloc(0);
  head.writeUInt16BE(answer.length ? 1 : 0, 6);
  return Buffer.concat([head, question, answer]);
}

/** A DNS query to send (tests, the self test's own resolver checks). */
export function buildQuery(name, qtype = 1, id = 0x1234) {
  const parts = String(name).replace(/\.$/, '').split('.').filter(Boolean).map((l) => { const b = Buffer.from(l); return Buffer.concat([Buffer.from([b.length]), b]); });
  const head = Buffer.alloc(12); head.writeUInt16BE(id, 0); head.writeUInt16BE(0x0100, 2); head.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(4); tail.writeUInt16BE(qtype, 0); tail.writeUInt16BE(1, 2);
  return Buffer.concat([head, ...parts, Buffer.from([0]), tail]);
}

/** The A record of an answer, if any (tests). */
export function answerA(buf) {
  const q = parseQuestion(Buffer.concat([buf.subarray(0, 2), Buffer.from([buf[2] & 0x7f, buf[3]]), buf.subarray(4)]));
  if (!q || buf.readUInt16BE(6) < 1) return { rcode: buf[3] & 0xf, a: null };
  const r = buf.subarray(q.end);
  return { rcode: buf[3] & 0xf, a: r.length >= 16 && r.readUInt16BE(2) === 1 ? [...r.subarray(12, 16)].join('.') : null };
}
