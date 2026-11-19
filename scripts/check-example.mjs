#!/usr/bin/env node
// Checks the example run: every reference server gave a live tool list and the engine graded it.
//   node scripts/check-example.mjs rows.jsonl aggregate.json
import { readFileSync } from 'node:fs';

const [rowsFile, aggFile] = process.argv.slice(2);
const rows = readFileSync(rowsFile, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
const agg = JSON.parse(readFileSync(aggFile, 'utf8'));
const problems = [];
if (rows.length !== 3) problems.push(`expected 3 rows, got ${rows.length}`);
for (const r of rows) {
  if (r.public_exit !== 0) problems.push(`${r.id}: exit ${r.public_exit}`);
  if (r.acquired !== 'live') problems.push(`${r.id}: best layer ${r.acquired}, not live`);
  if (!r.checks.live || !r.grades.live) problems.push(`${r.id}: no engine result for the live list`);
  if (!r.sdk || !r.sdk.version) problems.push(`${r.id}: no SDK version from the lock file`);
  if (!r.size || !(r.size.tools > 0)) problems.push(`${r.id}: no size`);
}
if (agg.example !== true || agg.checks.live.n !== 3 || Object.keys(agg.checks.live.per_check).length !== agg.engine.checks) problems.push('the aggregate is not the example aggregate of 3 live lists');
for (const r of rows) console.log(`${r.id}: ${r.acquired}, ${r.size ? r.size.tools : 0} tools, ${r.sdk ? `${r.sdk.id} ${r.sdk.version}` : 'no SDK'}, static ${r.layers.static ? r.layers.static.fidelity : 'none'}`);
if (problems.length) { for (const p of problems) console.error(`example check failed: ${p}`); process.exit(1); }
console.log('example ok');
