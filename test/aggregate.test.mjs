import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { aggregate, calibrationMarkdown, cell, categorical, dist, histogram, sub, size, diffStates, privateCalibration } from '../src/aggregate.mjs';
import { parseArgs, build, readJsonl } from '../bin/aggregate.mjs';
import { fingerprint } from '../src/compare.mjs';
import { row } from './helpers.mjs';

const M = createRequire(import.meta.url)('../engine/core.js');
const checks = M.CHECKS.map((c) => ({ id: c.id, section: c.section, severity: c.severity }));
const [C1, C2, C3, C4] = checks.map((c) => c.id);

test('a cell under 5 servers is withheld, and so is one whose complement is under 5; zero is published', () => {
  assert.deepEqual(cell(0, 100), { n: 0, of: 100, rate: 0 });
  assert.deepEqual(cell(50, 100), { n: 50, of: 100, rate: 0.5 });
  assert.deepEqual(cell(100, 100), { n: 100, of: 100, rate: 1 });
  for (const k of [1, 2, 3, 4]) assert.deepEqual(cell(k, 100), { n: null, of: 100, suppressed: true, bound: '<5' });
  for (const k of [96, 97, 98, 99]) assert.deepEqual(cell(k, 100), { n: null, of: 100, suppressed: true, bound: '>95' });
  assert.deepEqual(cell(5, 100).n, 5);
  assert.deepEqual(cell(95, 100).n, 95);
  assert.deepEqual(cell(3, 4), { n: null, of: null, suppressed: true }, 'a population under 5 hides its own size too');
  assert.deepEqual(cell(0, 0), { n: 0, of: 0, rate: null });
});

test('a sub-population that leaves out 1 to 4 of its parent gives rates only, never counts', () => {
  const parent = Array.from({ length: 50 }, (_, i) => i);
  const most = sub(parent, (i) => i >= 2);
  assert.equal(most.hide, true);
  assert.equal(size(most), null);
  assert.deepEqual(cell(24, most.length, 5, most.hide), { n: null, of: null, rate: 0.5, counts_withheld: true });
  assert.equal(cell(2, most.length, 5, most.hide).suppressed, true);
  assert.equal(cell(2, most.length, 5, most.hide).of, null);
  const half = sub(parent, (i) => i % 2 === 0);
  assert.equal(half.hide, false);
  assert.equal(size(half), 25);
  assert.equal(sub(most, (i) => i % 2 === 0).hide, true, 'hidden is inherited');
  assert.equal(categorical({ a: 40, b: 8 }, 5, true).of, null);
  assert.deepEqual(Object.keys(categorical({ a: 40, b: 8 }, 5, true).by.a), ['rate']);
  assert.equal(dist([1, 2, 3, 4, 5, 6], { hide: true }).n, null);
});

test('small categories are merged into "other" until it is at least 5, so none can be found by subtraction', () => {
  assert.deepEqual(categorical({ a: 50, b: 20, c: 3, d: 1 }), { of: 74, by: { a: { n: 50, rate: 0.6757 }, other: { n: 24, rate: 0.3243, merged_categories: 3 } } });
  assert.deepEqual(Object.keys(categorical({ a: 50, b: 20, c: 3, d: 2 }).by), ['a', 'b', 'other']);
  assert.deepEqual(categorical({ a: 3 }), { of: null, suppressed: true });
  assert.deepEqual(categorical({ a: 7, b: 1 }), { of: 8, by: { other: { n: 8, rate: 1, merged_categories: 2 } } });
  assert.deepEqual(categorical({}), { of: 0, by: {} });
  const shown = categorical({ a: 50, b: 20, c: 3, d: 1 });
  const named = Object.entries(shown.by).filter(([k]) => k !== 'other').reduce((s, [, v]) => s + v.n, 0);
  assert.ok(shown.of - named >= 5);
});

test('distributions: no minimum or maximum, nothing under 5 values, histogram buckets merged to at least 5', () => {
  assert.deepEqual(dist([1, 2, 3, 4]), { n: null, suppressed: true });
  const d = dist([1, 2, 3, 4, 100], { edges: [10] });
  assert.deepEqual(Object.keys(d).sort(), ['histogram', 'mean', 'n', 'p25', 'p50', 'p75']);
  assert.ok(!JSON.stringify(d).includes('100'), 'the one server with 100 is not shown');
  assert.deepEqual(d.histogram, { buckets: [{ range: '<10 .. >=10', n: 5 }] });
  const h = histogram({ a: 6, b: 2, c: 9, d: 1 });
  assert.ok(h.buckets.every((b) => b.n >= 5));
  assert.equal(h.buckets.reduce((s, b) => s + b.n, 0), 18);
  assert.ok('p10' in dist(Array.from({ length: 20 }, (_, i) => i)));
});

function rows100() {
  const rows = [];
  for (let i = 1; i <= 100; i++) {
    const fired = [C1];                       // fires on every server
    if (i <= 40) fired.push(C2);              // fires on 40
    if (i <= 3) fired.push(C3);               // fires on 3: withheld
    const svl = Object.fromEntries(checks.map((c) => [c.id, 'neither']));
    svl[C1] = 'both'; svl[C2] = i <= 40 ? (i <= 30 ? 'live_only' : 'both') : 'neither';
    rows.push(row(i, { fired, staticFired: i <= 10 ? [C1, C2] : [C1], svl, sdk: i <= 60 ? 'typescript-sdk' : i <= 97 ? 'python-sdk' : 'rmcp', live: i <= 90, tools: 5 + (i % 30) }));
  }
  return rows;
}

test('the aggregate: prevalence per check, SDK breakdown, calibration lists', () => {
  const agg = aggregate(rows100(), { checks, engine: { rubric_version: M.RUBRIC_VERSION, checks: checks.length } });
  assert.equal(agg.format, 'isokron-surface-aggregate/1');
  assert.equal(agg.targets.total, 100);
  assert.deepEqual(agg.acquisition.live_ok, { n: 90, of: 100, rate: 0.9 });
  const L = agg.checks.live;
  assert.equal(L.n, 90);
  assert.equal(Object.keys(L.per_check).length, checks.length);
  assert.deepEqual(L.per_check[C1].servers, { n: 90, of: 90, rate: 1 });
  assert.deepEqual(L.per_check[C2].servers, { n: 40, of: 90, rate: 0.4444 });
  assert.deepEqual(L.per_check[C3].servers, { n: null, of: 90, suppressed: true, bound: '<5' });
  assert.deepEqual(L.per_check[C4].servers, { n: 0, of: 90, rate: 0 });
  assert.deepEqual(Object.keys(agg.sdk.by_sdk.by), ['typescript-sdk', 'other'], 'rmcp (3 servers) is merged, and python-sdk with it so the 3 cannot be subtracted out');
  assert.deepEqual(Object.keys(agg.sdk.per_sdk), ['typescript-sdk']);
  assert.equal(agg.sdk.per_sdk['typescript-sdk'].servers, 60);
  const cal = agg.calibration;
  assert.deepEqual(cal.live.fires_on_almost_all.map((x) => x.id), [C1]);
  assert.ok(cal.live.never_fires.includes(C4) && !cal.live.never_fires.includes(C3));
  assert.deepEqual(cal.live.withheld, [C3]);
  assert.ok(cal.never_fires_anywhere.includes(C4) && !cal.never_fires_anywhere.includes(C2));
  const dis = cal.static_vs_live_disagree.find((x) => x.id === C2);
  assert.deepEqual([dis.live_only, dis.static_only, dis.disagree_rate], [30, 0, 0.3333]);
  const md = calibrationMarkdown(agg);
  assert.match(md, /Fire on almost every server/);
  assert.match(md, new RegExp(`\`${C1}\` \\(\\w+\\): 100%`));
  assert.match(md, /Counts of fewer than 5 servers are withheld/);
});

test('the public aggregate carries no target id and no count of 1 to 4 servers', () => {
  const rows = rows100();
  const agg = aggregate(rows, { checks, diff: diffStates(rows.slice(0, 98).map((r) => ({ id: r.id, tools: [], checks: [], grades: {} })), rows.map((r) => ({ id: r.id, tools: [], checks: [], grades: {} }))) });
  const text = JSON.stringify(agg);
  assert.ok(!/"s\d{3,4}"/.test(text) && !/\bs0\d\d\b/.test(text), 'no target id');
  const small = [];
  (function walk(x, path) {
    if (x === null || typeof x !== 'object') return;
    for (const [k, v] of Object.entries(x)) {
      if ((k === 'n' || k === 'servers') && typeof v === 'number' && v >= 1 && v <= 4) small.push(`${path}.${k}=${v}`);
      walk(v, `${path}.${k}`);
    }
  })(agg, '');
  assert.deepEqual(small, []);
  assert.equal(agg.diff.new_targets.suppressed, true, 'two new targets: withheld');
  assert.equal(agg.diff.counts_withheld, true, 'and the compared population (98 of 100) gives rates only');
  assert.equal(agg.diff.compared, null);
});

test('with almost every server live, live tables give rates but no counts (the few that failed stay hidden)', () => {
  const rows = rows100().map((r, i) => (i < 98 ? row(i + 1, { fired: i < 49 ? [C1, C2] : [C1] }) : row(i + 1, { live: false })));
  const agg = aggregate(rows, { checks });
  assert.equal(agg.acquisition.live_ok.suppressed, true);
  assert.equal(agg.live.n, null);
  assert.equal(agg.checks.live.n, null);
  assert.equal(agg.checks.live.counts_withheld, true);
  assert.deepEqual(agg.checks.live.per_check[C2].servers, { n: null, of: null, rate: 0.5, counts_withheld: true });
  assert.ok(!JSON.stringify(agg.live).includes('"of":98') && !JSON.stringify(agg.checks.live).includes('98'));
  assert.deepEqual(agg.calibration.live.fires_on_almost_all.map((x) => x.id), [C1]);
  assert.match(calibrationMarkdown(agg), /A withheld number of servers\./);
});

test('fewer than 5 servers: nothing is published but the fact that it is too few', () => {
  const agg = aggregate([row(1, { fired: [C1] }), row(2), row(3)], { checks });
  assert.equal(agg.targets.total, null);
  assert.equal(agg.checks.live.enough, false);
  assert.ok(Object.values(agg.checks.live.per_check).every((c) => c.servers.suppressed));
  assert.deepEqual(agg.calibration.never_fires_anywhere, []);
  assert.match(calibrationMarkdown(agg), /Too few servers/);
});

test('the diff against the previous run: tools added, removed, changed; checks and grades; private per target, counted in public', () => {
  const t = (name, d = 'x') => ({ name, description: d, inputSchema: { type: 'object' } });
  const prev = [{ id: 's001', acquired: 'live', commit: 'a', package_version: '1.0.0', sdk: { id: 'typescript-sdk', version: '1.0.0' }, protocol_version: '2025-11-25', bytes: 100, tools: fingerprint([t('a'), t('b'), t('c')]), checks: [C1], grades: { spec: 'A' } }, { id: 's009', tools: [], checks: [], grades: {} }];
  const cur = [{ id: 's001', acquired: 'live', commit: 'b', package_version: '1.0.0', sdk: { id: 'typescript-sdk', version: '1.1.0' }, protocol_version: '2025-11-25', bytes: 150, tools: fingerprint([t('a'), t('b', 'changed'), t('d')]), checks: [C2], grades: { spec: 'B' } }, { id: 's002', tools: [], checks: [], grades: {} }];
  const d = diffStates(prev, cur);
  const one = d.per_target.find((x) => x.id === 's001');
  assert.deepEqual([one.tools.added, one.tools.removed, one.tools.changed], [['d'], ['c'], [{ name: 'b', parts: ['description'] }]]);
  assert.deepEqual([one.commit_changed, one.version_changed, one.sdk_changed, one.bytes_delta, one.any], [true, false, true, 50, true]);
  assert.deepEqual([one.checks_added, one.checks_removed, one.grades], [[C2], [C1], { spec: ['A', 'B'] }]);
  assert.equal(d.per_target.find((x) => x.id === 's002').new, true);
  assert.deepEqual(d.gone, ['s009']);
});

test('bin/aggregate: a cell size under 5 needs --example, which marks the output; partial runs carry state forward', () => {
  assert.throws(() => parseArgs(['--rows', 'r', '--public', 'p', '--private', 'q', '--min-cell', '1']), /public example only/);
  assert.equal(parseArgs(['--rows', 'r', '--public', 'p', '--private', 'q']).minCell, 5);
  const d = mkdtempSync(join(tmpdir(), 'agg-'));
  const rows = [row(1, { fired: [C1] }), row(2, { fired: [C1] })];
  writeFileSync(join(d, 'rows.jsonl'), rows.map((r) => JSON.stringify(r)).join('\n') + '\nnot json\n{"format":"other","id":"s003"}\n');
  writeFileSync(join(d, 'state.jsonl'), `${JSON.stringify({ format: 'isokron-surface-state/1', id: 's001', tools: [], checks: [], grades: {} })}\n`);
  writeFileSync(join(d, 'prev.jsonl'), [{ format: 'isokron-surface-state/1', id: 's001', tools: [], checks: [C1], grades: {} }, { format: 'isokron-surface-state/1', id: 's002', tools: [], checks: [], grades: {} }].map((r) => JSON.stringify(r)).join('\n'));
  assert.equal(readJsonl(join(d, 'rows.jsonl'), 'isokron-surface-row/1').length, 2, 'lines of another format or not JSON are dropped');
  const o = { rows: [join(d, 'rows.jsonl')], state: [join(d, 'state.jsonl')], prev: join(d, 'prev.jsonl'), minCell: 1, example: true, partial: true, shards: 1 };
  const r = build(o);
  assert.equal(r.pub.example, true);
  assert.deepEqual(r.pub.checks.live.per_check[C1].servers, { n: 2, of: 2, rate: 1 });
  assert.deepEqual(r.state.map((s) => s.id), ['s001', 's002'], 's002 was not in this partial run: its state is kept');
  assert.deepEqual(r.diff.gone, []);
  assert.deepEqual(build({ ...o, partial: false }).diff.gone, ['s002']);
  assert.deepEqual(privateCalibration(rows, checks).per_check[C1].live, ['s001', 's002']);
});
