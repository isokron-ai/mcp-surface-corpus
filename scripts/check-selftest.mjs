#!/usr/bin/env node
// Checks a sandbox self test from its telemetry file alone (docs/TELEMETRY.md), separately from
// the harness's own exit status:
//
//   node scripts/check-selftest.mjs TELEMETRY.jsonl [--cases a,b]
//
// Passes only when every line is a valid record, the run is a self test that ended ok, nothing was
// skipped or left out, and every case (all of src/selftest.mjs CASES unless --cases names some)
// passes on its evidence. The verdict is recomputed here with src/selftest.mjs evaluateCase from the
// raw records of the case alone (its `case_evidence`, `trace_summary`, `container`, `target_output`,
// network logger and firewall records), so this check is the source of pass and fail; the harness's
// own `bypass_result` must exist and agree, and can only veto (it also weighs the target's report,
// which can make a case fail, never pass). Each case also needs its `settings` and a `container`
// under runsc. Prints one line per case and a total; exits 1 on any failure.
import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { readTelemetry } from '../src/telemetry.mjs';
import { CASES, evaluateCase } from '../src/selftest.mjs';
import { RUNTIME } from '../src/runsc.mjs';
import { NETS } from '../src/sandbox-net.mjs';

/** The evidence of one case, rebuilt from its records the way bin/sandbox-selftest.mjs gathered it; null when a piece is missing. */
export function evidenceFrom(mine) {
  const ce = mine.filter((r) => r.type === 'case_evidence');
  const traces = mine.filter((r) => r.type === 'trace_summary' && r.source === 'runsc');
  const ctr = mine.filter((r) => r.type === 'container');
  const out = mine.filter((r) => r.type === 'target_output' && r.stream === 'stdout');
  if (ce.length !== 1 || ctr.length !== 1 || out.length !== 1 || traces.length > 1) return null;
  const e = ce[0]; const c = ctr[0];
  const target = NETS.run.target;
  const net = (type) => mine.filter((r) => r.type === type && r.source === 'netlog' && r.from === target);
  return {
    trace: traces.length ? traces[0].summary : null,
    dns: net('dns_query'),
    conns: net('connection'),
    drops: mine.filter((r) => r.type === 'host_drop' && r.source === 'host'),
    canaryHits: e.canary_hits,
    inspect: e.inspect && typeof e.inspect === 'object' ? { runtime: c.runtime === e.inspect.runtime ? e.inspect.runtime : `${c.runtime}/${e.inspect.runtime}`, mismatches: Array.isArray(e.inspect.mismatches) ? e.inspect.mismatches : ['unreadable'], canaryInEnv: e.inspect.canary_in_env } : null,
    container: { exit: c.exit, timed_out: c.timed_out, oom_killed: c.oom_killed },
    telemetryHasNonce: e.telemetry_has_nonce,
    output: { bytes: out[0].bytes },
    outputRecorded: true,
    report: null,
    pidsLimit: e.pids_limit,
  };
}

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
  if (end.length !== 1) problems.push('the run did not end');
  else if (end[0].ok !== true) problems.push('the harness recorded a failure');
  else if (end[0].telemetry_dropped !== 0) problems.push(`${Number.isInteger(end[0].telemetry_dropped) ? end[0].telemetry_dropped : 'an unknown number of'} record(s) of evidence were refused by the schema and left out`);
  for (const p of problems) lines.push(`telemetry: ${p}`);

  let passed = 0;
  for (const name of cases) {
    const mine = records.filter((r) => r.subject === `case:${name}`);
    const verdicts = mine.filter((r) => r.type === 'bypass_result' && r.case === name);
    const why = [];
    const ev = evidenceFrom(mine);
    if (!ev) why.push('evidence records missing');
    else {
      const v = evaluateCase(name, ev);
      if (!v.blocked) why.push('not blocked');
      if (!v.logged) why.push('not logged');
      if (!v.pass) why.push(`evidence: ${v.detail}`.slice(0, 300));
    }
    if (verdicts.length !== 1) why.push(`${verdicts.length} harness verdicts`);
    else if (!verdicts[0].pass) why.push('the harness verdict is not a pass');
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
