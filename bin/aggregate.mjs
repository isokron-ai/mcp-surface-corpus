#!/usr/bin/env node
/**
 * Builds the public aggregate and the calibration report from the shards' rows.
 *
 *   node bin/aggregate.mjs --rows FILE [--rows FILE ...] [--state FILE ...] [--prev-state FILE]
 *                          --public DIR --private DIR [--min-cell N] [--example] [--partial] [--shards N]
 *
 * --public DIR    aggregate.json, calibration.md: counts over servers, disclosure rules applied
 *                 (src/aggregate.mjs), no target id. This is the only output that is not encrypted.
 * --private DIR   aggregate-exact.json, calibration-exact.md, calibration-ids.json, diffs.jsonl,
 *                 rows.jsonl, state.jsonl: exact counts and target ids, for the encrypted bundle.
 * --min-cell N    default 5. A value under 5 is refused unless --example is given, and --example
 *                 marks the output ("example": true): it is for the public example list only.
 *
 * --partial       the run covered some targets only: the others' previous state is carried forward.
 *
 * Rows and states are data (JSON lines); nothing in them is executed.
 */
import { createRequire } from 'node:module';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { aggregate, calibrationMarkdown, diffStates, privateCalibration, DEFAULT_MIN_CELL } from '../src/aggregate.mjs';
import { ROW_FORMAT, STATE_FORMAT } from '../src/record.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);

export function readJsonl(file, format) {
  const out = [];
  for (const line of readFileSync(file, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    let j; try { j = JSON.parse(line); } catch { continue; }
    if (j && typeof j === 'object' && j.format === format && typeof j.id === 'string' && /^s[0-9]{3,4}$/.test(j.id)) out.push(j);
  }
  return out;
}
const dedupe = (list) => [...new Map(list.map((x) => [x.id, x])).values()].sort((a, b) => Number(a.id.slice(1)) - Number(b.id.slice(1)));

export function parseArgs(argv) {
  const o = { rows: [], state: [], prev: null, pub: null, priv: null, minCell: DEFAULT_MIN_CELL, example: false, shards: null, partial: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; const v = () => { if (i + 1 >= argv.length) throw new Error(`${a} needs a value`); return argv[++i]; };
    if (a === '--rows') o.rows.push(v()); else if (a === '--state') o.state.push(v()); else if (a === '--prev-state') o.prev = v();
    else if (a === '--public') o.pub = v(); else if (a === '--private') o.priv = v(); else if (a === '--min-cell') o.minCell = Number(v());
    else if (a === '--example') o.example = true; else if (a === '--partial') o.partial = true; else if (a === '--shards') o.shards = Number(v());
    else throw new Error(`unknown option ${a}`);
  }
  if (!o.rows.length || !o.pub || !o.priv) throw new Error('usage: aggregate.mjs --rows FILE... --public DIR --private DIR [--state FILE...] [--prev-state FILE] [--min-cell N] [--example]');
  if (!(Number.isInteger(o.minCell) && o.minCell >= 1)) throw new Error('--min-cell must be a whole number');
  if (o.minCell < DEFAULT_MIN_CELL && !o.example) throw new Error(`--min-cell under ${DEFAULT_MIN_CELL} is for the public example only (--example)`);
  return o;
}

export function build(o) {
  const M = require(join(root, 'engine', 'core.js'));
  const vendored = JSON.parse(readFileSync(join(root, 'engine', 'VENDORED.json'), 'utf8'));
  const checks = M.CHECKS.map((c) => ({ id: c.id, section: c.section, severity: c.severity }));
  const engine = { rubric_version: M.RUBRIC_VERSION, spec_version: M.SPEC_VERSION, checks: checks.length, commit: vendored.commit };
  const rows = dedupe(o.rows.flatMap((f) => readJsonl(f, ROW_FORMAT)));
  const state = dedupe(o.state.flatMap((f) => readJsonl(f, STATE_FORMAT)));
  const prev = o.prev ? dedupe(readJsonl(o.prev, STATE_FORMAT)) : null;
  const now = new Date().toISOString();
  const diff = prev ? diffStates(prev, state) : null;
  // A run of some targets only (--partial) says nothing about the others: they are not "gone", and
  // their last known state is carried forward so the next full run still has it to compare with.
  if (diff && o.partial) diff.gone = [];
  const stamped = state.map((x) => ({ ...x, seen_at: now }));
  const nextState = o.partial && prev ? dedupe([...prev, ...stamped]) : stamped;
  const pub = aggregate(rows, { checks, minCell: o.minCell, engine, diff, example: o.example, now, shards: o.shards });
  const exact = aggregate(rows, { checks, minCell: 1, engine, diff, example: o.example, now, shards: o.shards });
  return { rows, state: nextState, diff, pub, exact, checks };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { process.stderr.write(`${e.message}\n`); process.exit(2); }
  const r = build(o);
  mkdirSync(o.pub, { recursive: true }); mkdirSync(o.priv, { recursive: true });
  writeFileSync(join(o.pub, 'aggregate.json'), `${JSON.stringify(r.pub, null, 1)}\n`);
  writeFileSync(join(o.pub, 'calibration.md'), calibrationMarkdown(r.pub));
  writeFileSync(join(o.priv, 'aggregate-exact.json'), `${JSON.stringify(r.exact, null, 1)}\n`);
  writeFileSync(join(o.priv, 'calibration-exact.md'), calibrationMarkdown({ ...r.exact, example: false, min_cell: 1 }).replace('Counts of fewer than 1 servers are withheld.', 'Exact counts: private, never published.'));
  writeFileSync(join(o.priv, 'calibration-ids.json'), `${JSON.stringify(privateCalibration(r.rows, r.checks))}\n`);
  writeFileSync(join(o.priv, 'rows.jsonl'), r.rows.map((x) => `${JSON.stringify(x)}\n`).join(''));
  writeFileSync(join(o.priv, 'state.jsonl'), r.state.map((x) => `${JSON.stringify(x)}\n`).join(''));
  if (r.diff) writeFileSync(join(o.priv, 'diffs.jsonl'), r.diff.per_target.map((x) => `${JSON.stringify(x)}\n`).join('') + (r.diff.gone.length ? `${JSON.stringify({ gone: r.diff.gone })}\n` : ''));
  // The only line printed: how many rows went in is itself a count of servers, so it is not printed.
  process.stdout.write('aggregate written\n');
}
