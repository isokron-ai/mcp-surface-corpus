import test from 'node:test';
import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { connect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { dnsReply, extractSni, parseHttpHead, describeFirst, printable, startNetlog } from '../sandbox/netlog.mjs';
import { buildQuery, answerA, RCODE } from '../src/dns.mjs';
import { fromNetlog } from '../src/telemetry.mjs';

const OWN = '10.213.53.2';

test('DNS: every A is the logger itself, PTR does not exist, anything else is empty', () => {
  const a = dnsReply(buildQuery('Registry.NPMJS.org', 1), OWN);
  assert.deepEqual(a.log, { qname: 'registry.npmjs.org', qtype: 'A', answer: 'sinkhole' });
  assert.deepEqual(answerA(a.reply), { rcode: 0, a: OWN });
  const aaaa = dnsReply(buildQuery('dns.google', 28), OWN);
  assert.deepEqual([aaaa.log.answer, answerA(aaaa.reply).rcode, aaaa.reply.readUInt16BE(6)], ['empty', 0, 0]);
  const ptr = dnsReply(buildQuery('1.1.1.1.in-addr.arpa', 12), OWN);
  assert.deepEqual([ptr.log.answer, answerA(ptr.reply).rcode], ['nxdomain', RCODE.NXDOMAIN]);
  const https = dnsReply(buildQuery('example.com', 65), OWN);
  assert.equal(https.log.qtype, 'HTTPS');
});

test('DNS: not a standard query is refused, an unreadable one gets FORMERR, a response gets nothing', () => {
  const notify = buildQuery('example.com'); notify[2] |= 0x20; // opcode 4
  const r = dnsReply(notify, OWN);
  assert.deepEqual([r.log.answer, answerA(r.reply).rcode], ['refused', RCODE.REFUSED]);
  const chaos = buildQuery('version.bind', 16); chaos.writeUInt16BE(3, chaos.length - 2);
  assert.equal(dnsReply(chaos, OWN).log.answer, 'refused');
  const junk = Buffer.concat([Buffer.from([0xab, 0xcd, 0x01, 0x00]), Buffer.alloc(9, 0xff)]);
  const f = dnsReply(junk, OWN);
  assert.deepEqual([f.log.answer, f.reply.readUInt16BE(0), f.reply[3] & 0xf, f.reply.length], ['formerr', 0xabcd, RCODE.FORMERR, 12]);
  const resp = buildQuery('example.com'); resp[2] |= 0x80;
  assert.equal(dnsReply(resp, OWN).reply, null);
  assert.equal(dnsReply(Buffer.alloc(3), OWN).reply, null);
});

test('first bytes: TLS server name, HTTP method, host and path without the query string', () => {
  const h = parseHttpHead(Buffer.from('POST /v1/collect?token=s3cr3t#frag HTTP/1.1\r\nHost: Exfil.Example:8080\r\nContent-Length: 4\r\n\r\nabcd'));
  assert.deepEqual(h, { method: 'POST', host: 'exfil.example:8080', path: '/v1/collect' });
  assert.deepEqual(parseHttpHead(Buffer.from('GET http://169.254.169.254/latest/meta-data/?x=1 HTTP/1.1\r\n\r\n')), { method: 'GET', host: '169.254.169.254', path: '/latest/meta-data/' });
  assert.equal(parseHttpHead(Buffer.from('\x16\x03\x01')), null);
  assert.equal(parseHttpHead(Buffer.from('SSH-2.0-OpenSSH\r\n')), null);
  assert.equal(extractSni(Buffer.from('GET / HTTP/1.1\r\n')), null);
  assert.equal(extractSni(Buffer.from([0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00])), null, 'a cut hello');
  assert.equal(printable(Buffer.from('a\nb\x00c"d')), 'a\\x0ab\\x00c\\x22d');
  const d = describeFirst(Buffer.from('GET /?q=1 HTTP/1.0\r\n\r\n'));
  assert.equal(d.first_hex, Buffer.from('GET /?q=1 HTTP/1.0\r\n\r\n').subarray(0, 32).toString('hex'));
  assert.equal(d.http.path, '/');
});

const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(fn, ms = 4000) { const t = Date.now(); while (Date.now() - t < ms) { const v = fn(); if (v) return v; await wait(20); } return fn(); }

test('the logger on local ports: answers DNS over UDP and TCP, closes every sinkhole connection unanswered, logs all of it', async () => {
  const lines = [];
  const n = await startNetlog({ own: OWN, host: '127.0.0.1', dnsPort: 0, tcpPorts: [0, 0], udpPorts: [0], log: (o) => lines.push(o) });
  try {
    assert.deepEqual(n.failed, []);
    // UDP DNS
    const s = createSocket('udp4');
    const udpAnswer = await new Promise((resolve) => { s.on('message', (m) => resolve(m)); s.send(buildQuery('exfil.example', 1), n.dns.udp, '127.0.0.1'); });
    s.close();
    assert.deepEqual(answerA(udpAnswer), { rcode: 0, a: OWN });
    // TCP DNS, two queries on one connection
    const tcpAnswers = await new Promise((resolve, reject) => {
      const c = connect(n.dns.tcp, '127.0.0.1'); let buf = Buffer.alloc(0); const got = [];
      c.on('error', reject);
      c.on('connect', () => { for (const [name, t] of [['a.example', 1], ['b.example', 28]]) { const q = buildQuery(name, t); const h = Buffer.alloc(2); h.writeUInt16BE(q.length); c.write(Buffer.concat([h, q])); } });
      c.on('data', (d) => { buf = Buffer.concat([buf, d]); while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) { got.push(buf.subarray(2, 2 + buf.readUInt16BE(0))); buf = buf.subarray(2 + buf.readUInt16BE(0)); } if (got.length === 2) { c.destroy(); resolve(got); } });
    });
    assert.equal(answerA(tcpAnswers[0]).a, OWN);
    assert.equal(answerA(tcpAnswers[1]).a, null);
    // TLS to the sinkhole: the hello is read, nothing is answered
    const tlsErr = await new Promise((resolve) => {
      const c = tlsConnect({ host: '127.0.0.1', port: n.tcp[0], servername: 'dns.google', rejectUnauthorized: true });
      c.on('secureConnect', () => resolve('connected'));
      c.on('error', (e) => resolve(e.code || e.message));
    });
    assert.notEqual(tlsErr, 'connected');
    // HTTP to the sinkhole: no response bytes at all
    const httpGot = await new Promise((resolve) => {
      const c = connect(n.tcp[1], '127.0.0.1'); let got = 0;
      c.on('connect', () => c.write('GET /collect?k=SECRET HTTP/1.1\r\nHost: exfil.example\r\n\r\n'));
      c.on('data', (d) => { got += d.length; });
      c.on('error', () => {});
      c.on('close', () => resolve(got));
    });
    assert.equal(httpGot, 0);
    // UDP to the sinkhole
    const u = createSocket('udp4');
    await new Promise((r) => u.send(Buffer.from('quic-ish'), n.udp[0], '127.0.0.1', r));
    u.close();
    const all = await until(() => lines.filter((l) => l.kind === 'conn').length >= 3 && lines);
    const dns = all.filter((l) => l.kind === 'dns');
    assert.deepEqual(dns.map((l) => [l.proto, l.qname, l.qtype, l.answer]), [['udp', 'exfil.example', 'A', 'sinkhole'], ['tcp', 'a.example', 'A', 'sinkhole'], ['tcp', 'b.example', 'AAAA', 'empty']]);
    assert.ok(dns.every((l) => l.from === '127.0.0.1' && typeof l.t === 'string'));
    const conns = all.filter((l) => l.kind === 'conn');
    const tls = conns.find((l) => l.port === n.tcp[0]);
    assert.equal(tls.sni, 'dns.google');
    assert.ok(tls.bytes > 50);
    const http = conns.find((l) => l.port === n.tcp[1]);
    assert.deepEqual(http.http, { method: 'GET', host: 'exfil.example', path: '/collect' });
    assert.ok(!JSON.stringify(lines).includes('SECRET'), 'a query string is never kept');
    const q = conns.find((l) => l.proto === 'udp');
    assert.deepEqual([q.port, q.bytes, q.first_hex], [n.udp[0], 8, Buffer.from('quic-ish').toString('hex')]);
    for (const l of all) assert.ok(fromNetlog(l), 'every line becomes a telemetry record');
  } finally { n.close(); }
});

test('the logger refuses an own address that is not IPv4', async () => {
  await assert.rejects(startNetlog({ own: 'example.com', log: () => {} }), /IPv4/);
});
