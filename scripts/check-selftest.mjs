#!/usr/bin/env node
// Checks a sandbox self test from its telemetry file alone (docs/TELEMETRY.md), separately from
// the harness's own exit status:
//
//   node scripts/check-selftest.mjs TELEMETRY.jsonl [--cases a,b]
//
// Passes only when every line is a valid record, the run is a self test that ended ok, nothing was
// skipped, and every case (all of src/selftest.mjs CASES unless --cases names some) has exactly one
// `bypass_result` with blocked, logged and pass all true, plus its own `settings`, a `container`
// that ran under runsc, and a runsc `trace_summary`. Prints one line per case and a total; exits 1
// on any failure.
import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { readTelemetry } from '../src/telemetry.mjs';
import { CASES } from '../src/selftest.mjs';
import { RUNTIME } from '../src/runsc.mjs';

export function checkSelftest(file, cases = CASES) {
  const lines = [];
  const problems = [];
  if (!existsSync(file)) return { ok: false, lines: [`telemetry: ${file} is missing`] };
  const { records, bad } = readTelemetry(file);
  for (const b of bad.slice(0, 5)) problems.push(`line ${b.line} is not a valid record (${b.errors.slice(0, 3).join(', ')})`);
  if (!records.length) problems.push('no records');
  const start = records.filter((r) => r.type === 'run_start');
  if (start.length !== 1 || start[0].kind !== 'selftest') problems.push('not exactly one self test run_start');
  if (new Set(records.map((r) => r.run)).size > 1) problems.push('records from more than one run');
  for (const s of records.filter((r) => r.type === 'skip')) problems.push(`skipped: ${s.reason} (${s.detail})`.slice(0, 200));
  const end = records.filter((r) => r.type === 'run_end');
  if (end.length !== 1 || end[0].ok !== true) problems.push('the run did not end ok');
  else if (end[0].telemetry_dropped !== 0) problems.push(`${Number.isInteger(end[0].telemetry_dropped) ? end[0].telemetry_dropped : 'an unknown number of'} record(s) of evidence were refused by the schema and left out`);
  for (const p of problems) lines.push(`telemetry: ${p}`);

  let passed = 0;
  for (const name of cases) {
    const mine = records.filter((r) => r.subject === `case:${name}`);
    const verdicts = mine.filter((r) => r.type === 'bypass_result' && r.case === name);
    const why = [];
    if (verdicts.length !== 1) why.push(`${verdicts.length} verdicts`);
    else {
      const v = verdicts[0];
      if (!v.blocked) why.push('not blocked');
      if (!v.logged) why.push('not logged');
      if (!v.pass) why.push('not passed');
    }
    if (!mine.some((r) => r.type === 'settings')) why.push('no settings record');
    const ctr = mine.filter((r) => r.type === 'container');
    if (!ctr.length || !ctr.every((r) => r.runtime === RUNTIME)) why.push(`no container record under ${RUNTIME}`);
    if (!mine.some((r) => r.type === 'trace_summary' && r.source === 'runsc')) why.push('no runsc trace summary');
    if (why.length) lines.push(`${name}: FAIL (${why.join(', ')})`);
    else { lines.push(`${name}: blocked and logged, ok`); passed++; }
  }
  const ok = !problems.length && passed === cases.length;
  lines.push(ok ? `selftest telemetry: all ${cases.length} cases blocked and logged` : `selftest telemetry: ${passed} of ${cases.length} cases blocked and logged${problems.length ? `, ${problems.length} run problem(s)` : ''}`);
  return { ok, lines };
}

function main(argv) {
  const file = argv[0];
  let cases = CASES;
  if (argv[1] === '--cases' && argv[2]) cases = argv[2].split(',').filter(Boolean);
  if (!file || (argv.length > 1 && argv[1] !== '--cases') || !cases.every((c) => CASES.includes(c))) {
    process.stdout.write('usage: check-selftest.mjs TELEMETRY.jsonl [--cases a,b]\n');
    return 1;
  }
  const r = checkSelftest(file, cases);
  process.stdout.write(`${r.lines.join('\n')}\n`);
  return r.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = main(process.argv.slice(2));
