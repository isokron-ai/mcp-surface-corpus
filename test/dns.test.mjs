import test from 'node:test';
import assert from 'node:assert/strict';
import { parseQuestion, buildAnswer, buildQuery, answerA, RCODE } from '../src/dns.mjs';

test('a query\'s question: name in lower case, type, id', () => {
  const q = parseQuestion(buildQuery('Registry.NPMJS.org', 1, 0xbeef));
  assert.deepEqual([q.id, q.name, q.type, q.qtype, q.rd], [0xbeef, 'registry.npmjs.org', 'A', 1, true]);
  assert.equal(parseQuestion(buildQuery('example.com', 28)).type, 'AAAA');
  assert.equal(parseQuestion(buildQuery('example.com', 65)).type, 'HTTPS');
  assert.equal(parseQuestion(buildQuery('example.com', 999)).type, '999');
});

test('untrusted name bytes stay printable text', () => {
  const raw = buildQuery('ab.example', 1);
  raw[13] = 0x0a; // the first label was "ab"; now a newline and "b"
  assert.equal(parseQuestion(raw).name, '\\x0ab.example');
  assert.ok(!/[\n\r\0]/.test(parseQuestion(raw).name));
  assert.match(parseQuestion(raw).name, /\\x0a/);
});

test('not a question: too short, a response, a compression pointer, a label past the end', () => {
  assert.equal(parseQuestion(Buffer.alloc(5)), null);
  assert.equal(parseQuestion('x'), null);
  const resp = buildQuery('example.com'); resp[2] |= 0x80;
  assert.equal(parseQuestion(resp), null);
  const ptr = buildQuery('example.com'); ptr[12] = 0xc0;
  assert.equal(parseQuestion(ptr), null);
  const cut = buildQuery('example.com').subarray(0, 20);
  assert.equal(parseQuestion(cut), null);
  const none = buildQuery('example.com'); none.writeUInt16BE(0, 4);
  assert.equal(parseQuestion(none), null);
});

test('answers: the sinkhole address, an empty answer, an error code', () => {
  const qb = buildQuery('evil.example', 1, 7); const q = parseQuestion(qb);
  const a = buildAnswer(qb, q, { a: '10.213.53.2' });
  assert.equal(a.readUInt16BE(0), 7);
  assert.ok(a[2] & 0x80, 'a response');
  assert.deepEqual(answerA(a), { rcode: 0, a: '10.213.53.2' });
  assert.deepEqual(answerA(buildAnswer(qb, q, {})), { rcode: 0, a: null });
  assert.deepEqual(answerA(buildAnswer(qb, q, { rcode: RCODE.NXDOMAIN, a: '10.213.53.2' })), { rcode: 3, a: null });
});
