#!/usr/bin/env node
// The public status of the nightly sandbox conformance run (conformance-nightly.yml): one small JSON
// file, published as the asset conformance-status.json of the release tagged `conformance`, so
// anyone can read it without a token:
//
//   https://github.com/isokron-ai/mcp-surface-corpus/releases/download/conformance/conformance-status.json
//
// tool-qa's pump and watchdog read it as a circuit breaker: when it is red, older than 36 hours or
// unreadable, nothing that runs third-party code is dispatched. It holds no secret and nothing a
// target printed: verdicts, a date, the run, and versions.
//
//   node scripts/conformance-status.mjs --out FILE      (reads the environment; see fromEnv)
//
// Exits 0 once a well-formed status is written, red or green (a red one must still be published,
// so the breaker trips at once); 1 when it could not build one, 2 on a usage error.
import { writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

export const STATUS_FORMAT = 'isokron-sandbox-conformance/1';
export const STATUS_ASSET = 'conformance-status.json';
export const STATUS_TAG = 'conformance';
const VERDICT = new Set(['pass', 'fail']);
const MUT = new Set(['pass', 'fail', 'skipped']);
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._+/:-]{0,79}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const SHA = /^[0-9a-f]{40}$/;

const tok = (v) => (TOKEN.test(String(v ?? '')) ? String(v) : 'unknown');

/**
 * The status from what the nightly run knows. `result` is the conformance call's result (success,
 * failure, cancelled, skipped); `selftest` and `mutations` are its outputs. Anything missing or
 * malformed counts against it: ok only when the call succeeded and both verdicts are pass.
 */
export function buildStatus({ result, selftest, mutations, checkedAt, now = new Date(), runId, runAttempt, serverUrl = 'https://github.com', repo, sandboxSha, runnerImage, kernel, docker, gvisorRelease, runscVersion }) {
  const s = VERDICT.has(selftest) ? selftest : 'fail';
  const m = MUT.has(mutations) ? mutations : 'fail';
  const ok = result === 'success' && s === 'pass' && m === 'pass';
  const at = ISO.test(String(checkedAt ?? '')) ? checkedAt : now.toISOString().replace(/\.\d{3}Z$/, 'Z');
  const id = /^\d{1,20}$/.test(String(runId ?? '')) ? Number(runId) : null;
  const repoOk = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(repo ?? ''));
  return {
    format: STATUS_FORMAT,
    ok,
    selftest: s,
    mutations: m,
    result: tok(result),
    checked_at: at,
    run_id: id,
    run_attempt: /^\d{1,4}$/.test(String(runAttempt ?? '')) ? Number(runAttempt) : null,
    run_url: id !== null && repoOk && /^https:\/\/[A-Za-z0-9.-]+$/.test(serverUrl) ? `${serverUrl}/${repo}/actions/runs/${id}` : null,
    sandbox_sha: SHA.test(String(sandboxSha ?? '')) ? sandboxSha : null,
    runner_image: tok(runnerImage),
    kernel: tok(kernel),
    docker: tok(docker),
    gvisor_release: tok(gvisorRelease),
    runsc_version: tok(runscVersion),
  };
}

/** Problems with a status document (the same rules a reader applies); [] when it is well formed. */
export function statusProblems(s) {
  const p = [];
  if (!s || typeof s !== 'object' || Array.isArray(s)) return ['not an object'];
  if (s.format !== STATUS_FORMAT) p.push('format');
  if (typeof s.ok !== 'boolean') p.push('ok');
  if (!VERDICT.has(s.selftest)) p.push('selftest');
  if (!MUT.has(s.mutations)) p.push('mutations');
  if (!ISO.test(String(s.checked_at))) p.push('checked_at');
  if (s.ok === true && !(s.selftest === 'pass' && s.mutations === 'pass')) p.push('ok without both passes');
  if (s.sandbox_sha !== null && !SHA.test(String(s.sandbox_sha))) p.push('sandbox_sha');
  for (const k of ['runner_image', 'kernel', 'docker', 'gvisor_release', 'runsc_version']) if (!TOKEN.test(String(s[k]))) p.push(k);
  return p;
}

/** The inputs from the nightly publish step's environment. */
export const fromEnv = (env) => ({
  result: env.CONFORMANCE_RESULT, selftest: env.SELFTEST, mutations: env.MUTATIONS, checkedAt: env.CHECKED_AT,
  runId: env.GITHUB_RUN_ID, runAttempt: env.GITHUB_RUN_ATTEMPT, serverUrl: env.GITHUB_SERVER_URL, repo: env.GITHUB_REPOSITORY,
  sandboxSha: env.SANDBOX_SHA, runnerImage: env.RUNNER_IMAGE, kernel: env.KERNEL, docker: env.DOCKER,
  gvisorRelease: env.GVISOR_RELEASE, runscVersion: env.RUNSC_VERSION,
});

function main(argv, env = process.env) {
  if (argv.length !== 2 || argv[0] !== '--out') { process.stderr.write('usage: conformance-status.mjs --out FILE\n'); return 2; }
  const s = buildStatus(fromEnv(env));
  const bad = statusProblems(s);
  if (bad.length) { process.stderr.write(`conformance status is malformed: ${bad.join(', ')}\n`); return 1; }
  writeFileSync(argv[1], `${JSON.stringify(s, null, 2)}\n`);
  process.stdout.write(`conformance: ${s.ok ? 'ok' : 'NOT OK'} (self test ${s.selftest}, mutations ${s.mutations}, call ${s.result}) at ${s.checked_at} on ${s.runner_image}, gVisor ${s.gvisor_release}\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = main(process.argv.slice(2));
