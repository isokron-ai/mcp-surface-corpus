#!/usr/bin/env node
// Recomputes a sandbox conformance verdict from the evidence alone, in a job that never ran a
// target: the telemetry artifacts the self test and each mutation uploaded, read with this
// checkout's own checkers (scripts/check-selftest.mjs, scripts/check-mutation.mjs). The outputs of
// the jobs that ran the hostile targets are never inputs here.
//
// What this does and does not guard against: it catches wiring bugs between jobs (an output that
// says pass while the evidence does not), and it keeps the verdict in a job that never ran a target.
// It is NOT a defence against a compromised self test runner: the telemetry files are written on
// that runner, so a target that took it over could write evidence that recomputes as a pass. If
// that ever needs defending, the fix is a separate job that signs provenance for the evidence
// (attested by GitHub, not by the runner that produced it).
//
//   node scripts/verify-conformance.mjs --evidence DIR --prefix PREFIX [--no-mutations] [--json FILE]
//
// DIR holds one folder per artifact (actions/download-artifact with a pattern and no merge):
// <PREFIX>-selftest/telemetry.jsonl (and environment.json), and <PREFIX>-mutation-<protection>/
// telemetry.jsonl for every protection scripts/check-mutation.mjs knows. Prints what it found;
// exits 0 only when the self test passed and (unless --no-mutations) every mutation was shown.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { checkSelftest } from './check-selftest.mjs';
import { EXPECT, checkMutation } from './check-mutation.mjs';
import { readTelemetry } from '../src/telemetry.mjs';
import { plain } from './runner-facts.mjs';

const ISO_S = (d) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');

/** The time the self test ended, from its run_end record, never later than now; null if none. */
export function evidenceTime(file, now = new Date()) {
  if (!existsSync(file)) return null;
  const end = readTelemetry(file).records.filter((r) => r.type === 'run_end');
  if (end.length !== 1) return null;
  const t = Date.parse(end[0].t);
  if (!Number.isFinite(t)) return null;
  return ISO_S(new Date(Math.min(t, now.getTime())));
}

/**
 * { selftest: pass|fail, mutations: pass|fail|skipped, checked_at, facts, lines }, from the
 * evidence folder only.
 */
export function verifyEvidence(dir, prefix, { mutations = true, now = new Date() } = {}) {
  if (!/^[a-z0-9][a-z0-9-]{0,39}$/.test(String(prefix))) throw new Error('prefix: lowercase letters, digits and dashes');
  const lines = [];
  const tel = join(dir, `${prefix}-selftest`, 'telemetry.jsonl');
  const st = checkSelftest(tel);
  lines.push(...st.lines.map((l) => `selftest: ${l}`));
  let mut = 'skipped';
  if (mutations) {
    mut = 'pass';
    for (const p of Object.keys(EXPECT)) {
      const r = checkMutation(join(dir, `${prefix}-mutation-${p}`, 'telemetry.jsonl'), p);
      lines.push(...r.lines.slice(-1));
      if (!r.ok) mut = 'fail';
    }
  }
  let facts = {};
  try { facts = JSON.parse(readFileSync(join(dir, `${prefix}-selftest`, 'environment.json'), 'utf8')); } catch { /* unknown */ }
  return {
    selftest: st.ok ? 'pass' : 'fail',
    mutations: mut,
    checked_at: evidenceTime(tel, now),
    // What the runner reported about itself: labels for people, never part of the verdict.
    facts: Object.fromEntries(['runner_image', 'kernel', 'docker', 'gvisor_release', 'runsc_version'].map((k) => [k, plain(facts?.[k])])),
    lines,
  };
}

function main(argv) {
  const o = { evidence: null, prefix: null, mutations: true, json: null };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--evidence' && i + 1 < argv.length) o.evidence = argv[++i];
    else if (argv[i] === '--prefix' && i + 1 < argv.length) o.prefix = argv[++i];
    else if (argv[i] === '--no-mutations') o.mutations = false;
    else if (argv[i] === '--json' && i + 1 < argv.length) o.json = argv[++i];
    else { o.evidence = null; break; }
  }
  if (!o.evidence || !o.prefix) { process.stderr.write('usage: verify-conformance.mjs --evidence DIR --prefix PREFIX [--no-mutations] [--json FILE]\n'); return 2; }
  const v = verifyEvidence(o.evidence, o.prefix, { mutations: o.mutations });
  process.stdout.write(`${v.lines.join('\n')}\nrecomputed: self test ${v.selftest}, mutations ${v.mutations}\n`);
  if (o.json) writeFileSync(o.json, `${JSON.stringify({ selftest: v.selftest, mutations: v.mutations, checked_at: v.checked_at, facts: v.facts }, null, 2)}\n`);
  return v.selftest === 'pass' && v.mutations !== 'fail' ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = main(process.argv.slice(2));
