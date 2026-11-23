#!/usr/bin/env node
// Checks a protection-off run of the sandbox self test (bin/sandbox-selftest.mjs --lane
// selftest-mutation --disable PROTECTION) from its telemetry alone:
//
//   node scripts/check-mutation.mjs TELEMETRY.jsonl PROTECTION
//
// With one protection off, the self test must fail, and for the reason that protection explains:
// either the preflight refused (and no case ran), or a named case failed on its evidence, with the
// verdict recomputed from the raw records (scripts/check-selftest.mjs evidenceFrom). A run that
// crashed, ended without its records, or failed for some other reason does not count. Prints what
// it found; exits 0 only when the run failed as expected.
import { existsSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { readTelemetry } from '../src/telemetry.mjs';
import { evaluateCase } from '../src/selftest.mjs';
import { evidenceFrom } from './check-selftest.mjs';

/**
 * What each protection's absence must show. `preflight`: the preflight refuses with a skip whose
 * detail matches. `case`: that case runs to its verdict and fails it, the detail matching `why`;
 * `blocked` and `logged` are the values the recomputed verdict must have, where given.
 */
export const EXPECT = {
  'runtime-runc': { case: 'direct-ip', why: /not run under gVisor \(runtime runc\)/, blocked: false },
  'firewall-forward': { preflight: /the firewall is not the one net-guard\.sh makes: .*ISK-SBX/ },
  'firewall-input': { preflight: /the firewall is not the one net-guard\.sh makes: .*INPUT lacks/ },
  'firewall-order': { preflight: /the firewall is not the one net-guard\.sh makes: .*DOCKER-USER: -A DOCKER-USER -[sd] 10\.213\.52\.0\/22 -j ISK-SBX comes after -A DOCKER-USER -s 10\.213\.52\.0\/22 -j ACCEPT/ },
  // Shown twice: by docker inspect (the settings) and by the target's own capability report, which
  // only the harness's verdict holds (a report can fail a case, never pass it).
  'cap-drop': { case: 'raw-socket', why: /capabilities are not all dropped/, blocked: false, harness: /target: CapEff [0-9a-f]+ CapBnd 0*[1-9a-f]/ },
  'env-filter': { case: 'env-token', why: /a token reached the target/, blocked: false },
  'read-only': { case: 'write-outside', why: /^got through: a write outside the work folder worked/, blocked: false, logged: true },
  // On a network with a route out, the firewall's silent drop leaves the calls to time out: shown as
  // the absence of a definite refusal, not as a reply.
  'internal-net': { case: 'direct-ip', why: /^no definite refusal: /, blocked: false, logged: true },
};

export function checkMutation(file, protection) {
  const lines = [];
  const exp = EXPECT[protection];
  if (!exp) return { ok: false, lines: [`unknown protection ${protection}`] };
  if (!existsSync(file)) return { ok: false, lines: [`telemetry: ${file} is missing`] };
  const { records, bad } = readTelemetry(file);
  const start = records.filter((r) => r.type === 'run_start');
  const end = records.filter((r) => r.type === 'run_end');
  const fail = (why) => ({ ok: false, lines: [...lines, `mutation ${protection}: NOT SHOWN (${why})`] });
  if (bad.length) return fail(`${bad.length} line(s) are not valid records`);
  if (start.length !== 1 || start[0].kind !== 'selftest' || start[0].lane !== 'selftest-mutation' || start[0].disabled !== protection) return fail('not a self test run with this protection off');
  if (end.length !== 1) return fail('the run did not end: a crash is not a detection');
  if (end[0].ok !== false) return fail('the self test passed with the protection off');
  const verdicts = records.filter((r) => r.type === 'bypass_result');
  if (exp.preflight) {
    const skips = records.filter((r) => r.type === 'skip' && r.subject === null);
    const hit = skips.find((s) => s.reason === 'sandbox_setup_missing' && exp.preflight.test(s.detail));
    lines.push(...skips.map((s) => `preflight: ${s.reason}: ${s.detail}`.slice(0, 300)));
    if (!hit) return fail('the preflight did not refuse for this reason');
    if (verdicts.length) return fail('cases ran after the preflight refused');
    lines.push(`mutation ${protection}: shown, the preflight refused`);
    return { ok: true, lines };
  }
  const mine = records.filter((r) => r.subject === `case:${exp.case}`);
  const ev = evidenceFrom(mine);
  const harness = verdicts.find((r) => r.case === exp.case);
  if (!harness) return fail(`${exp.case} has no verdict`);
  if (/^harness:/.test(harness.detail)) return fail(`${exp.case} ended in a harness error: ${harness.detail.slice(0, 200)}`);
  if (!ev) return fail(`${exp.case} has no evidence records`);
  const v = evaluateCase(exp.case, ev);
  lines.push(`${exp.case}: recomputed blocked ${v.blocked}, logged ${v.logged}: ${v.detail}`.slice(0, 400));
  if (v.pass) return fail(`${exp.case} passed on its evidence`);
  if (!exp.why.test(v.detail)) return fail(`${exp.case} failed for another reason`);
  if (exp.blocked !== undefined && v.blocked !== exp.blocked) return fail(`${exp.case}: blocked is ${v.blocked}`);
  if (exp.logged !== undefined && v.logged !== exp.logged) return fail(`${exp.case}: logged is ${v.logged}`);
  if (exp.harness && !harness.evidence.some((e) => exp.harness.test(e))) return fail(`${exp.case}: the harness's evidence does not show it (${String(exp.harness)})`);
  lines.push(`mutation ${protection}: shown by ${exp.case}`);
  return { ok: true, lines };
}

function main(argv) {
  if (argv.length !== 2) { process.stdout.write('usage: check-mutation.mjs TELEMETRY.jsonl PROTECTION\n'); return 1; }
  const r = checkMutation(argv[0], argv[1]);
  process.stdout.write(`${r.lines.join('\n')}\n`);
  return r.ok ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = main(process.argv.slice(2));
