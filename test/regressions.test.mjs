// REGRESSIONS.md, checked: every test a row names exists, in the file it names, and starts with the
// row's ID; every test whose name starts with an ID is in the ledger; every row has a fix commit.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const ID = /^R-(?:SBX|CASE|CI|MUT)-\d{2}$/;

/** The ledger's rows: { id, tests: [[file, name]], fixes }. */
export function ledgerRows(text) {
  const rows = [];
  for (const line of text.split('\n')) {
    if (!/^\| R-/.test(line)) continue;
    const cells = line.split(/(?<!\\)\|/).slice(1, -1).map((c) => c.trim());
    const tests = [];
    for (const part of cells[2].split('<br>')) {
      const m = /^`(test\/[\w.-]+\.test\.mjs)` `(.+)`$/.exec(part.trim());
      tests.push(m ? [m[1], m[2]] : [null, part.trim()]);
    }
    rows.push({ id: cells[0], tests, fixes: cells[3] });
  }
  return rows;
}

/** The names given to test() (or a helper ending in Test) in a file, as written. */
export function testNames(src) {
  const out = [];
  for (const m of src.matchAll(/\b(?:test|[a-z]+Test)\(\s*(['"`])((?:\\.|(?!\1)[^\\])*)\1/g)) out.push(m[2].replace(/\\(.)/g, '$1'));
  return out;
}

test('R-ledger: every row names tests that exist in the file it names, and each starts with the row\'s ID', () => {
  const rows = ledgerRows(readFileSync(join(root, 'REGRESSIONS.md'), 'utf8'));
  assert.ok(rows.length >= 8 + 11 + 7, `${rows.length} rows`);
  const seen = new Set();
  for (const r of rows) {
    assert.match(r.id, ID, r.id);
    assert.ok(!seen.has(r.id), `${r.id} twice`); seen.add(r.id);
    assert.match(r.fixes, /^[0-9a-f]{7,40}(?:, [0-9a-f]{7,40})*$/, `${r.id}: fix commits`);
    assert.ok(r.tests.length >= 1, `${r.id}: no test`);
    for (const [file, name] of r.tests) {
      assert.ok(file, `${r.id}: a test is not written as \`test/file.test.mjs\` \`name\`: ${name}`);
      assert.ok(name.startsWith(`${r.id} `), `${r.id}: the test name does not start with the ID: ${name}`);
      const names = testNames(readFileSync(join(root, file), 'utf8'));
      assert.ok(names.includes(name), `${r.id}: no test named "${name}" in ${file}`);
    }
  }
  for (const n of [...Array(8)].map((_, i) => `R-SBX-0${i + 1}`)) assert.ok(seen.has(n), `${n}: every review finding has a row`);
  for (let i = 1; i <= 11; i++) assert.ok(seen.has(`R-CASE-${String(i).padStart(2, '0')}`), `R-CASE-${i}: every hostile case has a row`);
});

test('R-ledger: every test named with an ID is in the ledger', () => {
  const rows = ledgerRows(readFileSync(join(root, 'REGRESSIONS.md'), 'utf8'));
  const listed = new Set(rows.flatMap((r) => r.tests.map(([f, n]) => `${f}\u0000${n}`)));
  for (const f of readdirSync(join(root, 'test')).filter((x) => x.endsWith('.test.mjs') && x !== 'regressions.test.mjs')) {
    for (const n of testNames(readFileSync(join(root, 'test', f), 'utf8'))) {
      const id = /^(R-[A-Z]+-\d{2}) /.exec(n);
      if (id) assert.ok(listed.has(`test/${f}\u0000${n}`), `test/${f}: "${n}" is not in REGRESSIONS.md`);
    }
  }
});

test('R-ledger: the checker itself finds a row that names a test that does not exist', () => {
  const rows = ledgerRows('| R-SBX-99 | x | `test/telemetry.test.mjs` `R-SBX-99 no such test` | abc1234 |\n');
  const names = testNames(readFileSync(join(root, 'test', 'telemetry.test.mjs'), 'utf8'));
  assert.equal(names.includes(rows[0].tests[0][1]), false);
  assert.deepEqual(testNames("test('a', () => {}); caseTest('R-CASE-01 b\\'s', 'x'); test(`c`, {}, () => {});"), ['a', "R-CASE-01 b's", 'c']);
});
