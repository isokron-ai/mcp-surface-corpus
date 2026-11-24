#!/usr/bin/env node
// Pin drift: compares what this repository pins with the newest releases, and proposes the new
// pins as a pull request (pin-drift.yml, weekly). Pins:
//
//   gvisor.json              the gVisor (runsc) release, its bundle URLs and their sha512. A new
//                            bundle's sha512 must equal the .sha512 file published beside it, and
//                            the bundle is downloaded and hashed here to be sure.
//   scripts/install-age.sh   the age release tarball (linux-amd64) and its sha256, hashed here.
//   pins/actions.json        each action the workflows use: the release tag and the commit it is.
//
//   node scripts/pin-drift.mjs --check            print what is behind; exit 0 (nothing) or 3
//   node scripts/pin-drift.mjs --open-pr          the same, then open a pull request with the new
//                                                 pins (GITHUB_TOKEN, GITHUB_REPOSITORY)
//   node scripts/pin-drift.mjs --sync-workflows   rewrite every `uses: actions/...` line to match
//                                                 pins/actions.json (run by a person: see below)
//
// The pull request is made through the API (a tree, a commit, a branch, the pull request), so the
// token needs contents: write and pull-requests: write and nothing else, and no git credentials are
// kept. Two things that token cannot do, by GitHub's design, are left to a person and said in the
// pull request: change workflow files (so action pins land in pins/actions.json, and
// --sync-workflows applies them to the uses: lines), and start workflows (a pull request opened with
// it runs no checks; pushing the sync commit, or closing and reopening the pull request, starts ci
// and sandbox-selftest).
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const GVISOR_ARCHES = ['x86_64', 'aarch64'];
const GVISOR_URL = (rel, arch) => `https://storage.googleapis.com/gvisor/releases/release/${rel}/${arch}/gvisor.tar.bz2`;
const AGE_ASSET = (tag) => `https://github.com/FiloSottile/age/releases/download/${tag}/age-${tag}-linux-amd64.tar.gz`;
const SEMVER = /^v\d{1,4}\.\d{1,4}\.\d{1,4}$/;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
export const recorded = (d) => `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;

/** The files the pins live in, and the files whose uses: lines follow pins/actions.json. */
export function workflowFiles(root = ROOT) {
  return [...readdirSync(join(root, '.github/workflows')).filter((f) => /\.ya?ml$/.test(f)).sort().map((f) => `.github/workflows/${f}`), 'sandbox-guard/action.yml'];
}
export function readFiles(root = ROOT, extra = []) {
  const out = {};
  for (const f of ['gvisor.json', 'scripts/install-age.sh', 'pins/actions.json', ...extra]) out[f] = readFileSync(join(root, f), 'utf8');
  return out;
}

/** The current pins, read from the files. */
export function currentPins(files) {
  const g = JSON.parse(files['gvisor.json']);
  const url = /^AGE_URL=(\S+)$/m.exec(files['scripts/install-age.sh']);
  const sha = /^AGE_SHA256=([0-9a-f]{64})$/m.exec(files['scripts/install-age.sh']);
  if (!url || !sha) throw new Error('scripts/install-age.sh has no AGE_URL= and AGE_SHA256= lines');
  const ver = /\/download\/(v[^/]+)\//.exec(url[1]);
  return {
    gvisor: { release: g.release, bundles: Object.fromEntries(GVISOR_ARCHES.map((a) => [a, { url: g.bundles[a].url, sha512: g.bundles[a].sha512 }])) },
    age: { version: ver ? ver[1] : null, url: url[1], sha256: sha[1] },
    actions: JSON.parse(files['pins/actions.json']).actions,
  };
}

/** The hex digest of what a URL serves (streamed). */
export async function hashUrl(fetchFn, url, algo) {
  const res = await fetchFn(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  const h = createHash(algo);
  if (res.body && typeof res.body[Symbol.asyncIterator] === 'function') for await (const chunk of res.body) h.update(chunk);
  else h.update(Buffer.from(await res.arrayBuffer()));
  return h.digest('hex');
}

/** A GitHub REST client: api(path, { method, body }) -> parsed JSON; a 404 or 422 throws with .status. */
export function githubApi({ fetchFn = globalThis.fetch, token, apiUrl = 'https://api.github.com' } = {}) {
  return async (path, { method = 'GET', body } = {}) => {
    const headers = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', 'user-agent': 'isokron-pin-drift' };
    if (token) headers.authorization = `Bearer ${token}`;
    if (body !== undefined) headers['content-type'] = 'application/json';
    const res = await fetchFn(`${apiUrl}${path}`, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
    const text = await res.text();
    if (!res.ok) { const e = new Error(`${method} ${path}: HTTP ${res.status} ${text.slice(0, 200)}`); e.status = res.status; throw e; }
    return text ? JSON.parse(text) : null;
  };
}

/** The commit a release tag points to, through an annotated tag if it is one. */
export async function tagCommit(api, repo, tag) {
  const ref = await api(`/repos/${repo}/git/ref/tags/${encodeURIComponent(tag)}`);
  let { sha, type } = ref.object;
  for (let i = 0; type === 'tag' && i < 3; i++) ({ sha, type } = (await api(`/repos/${repo}/git/tags/${sha}`)).object);
  if (type !== 'commit' || !/^[0-9a-f]{40}$/.test(sha)) throw new Error(`${repo} ${tag} does not point at a commit`);
  return sha;
}

/** The newest pins. Anything that does not check out (a hash, a tag) throws: nothing is guessed. */
export async function latestPins({ api, fetchFn = globalThis.fetch, current }) {
  const next = structuredClone(current);
  const g = (await api('/repos/google/gvisor/releases/latest')).tag_name;
  const rel = /^release-(\d{8}\.\d+)$/.exec(String(g));
  if (!rel) throw new Error(`gVisor's latest release tag is not release-YYYYMMDD.N: ${String(g).slice(0, 40)}`);
  if (rel[1] !== current.gvisor.release) {
    next.gvisor.release = rel[1];
    for (const arch of GVISOR_ARCHES) {
      const url = GVISOR_URL(rel[1], arch);
      const res = await fetchFn(`${url}.sha512`, { redirect: 'follow' });
      if (!res.ok) throw new Error(`${url}.sha512: HTTP ${res.status}`);
      const published = /^([0-9a-f]{128})\b/.exec((await res.text()).trim());
      if (!published) throw new Error(`${url}.sha512 holds no sha512`);
      const got = await hashUrl(fetchFn, url, 'sha512');
      if (got !== published[1]) throw new Error(`${url}: the bundle's sha512 differs from the published one`);
      next.gvisor.bundles[arch] = { url, sha512: got };
    }
  }
  const a = (await api('/repos/FiloSottile/age/releases/latest')).tag_name;
  if (!SEMVER.test(String(a))) throw new Error(`age's latest release tag is not vX.Y.Z: ${String(a).slice(0, 40)}`);
  if (a !== current.age.version) next.age = { version: a, url: AGE_ASSET(a), sha256: await hashUrl(fetchFn, AGE_ASSET(a), 'sha256') };
  for (const name of Object.keys(current.actions)) {
    const tag = (await api(`/repos/${name}/releases/latest`)).tag_name;
    if (!SEMVER.test(String(tag))) throw new Error(`${name}'s latest release tag is not vX.Y.Z: ${String(tag).slice(0, 40)}`);
    if (tag === current.actions[name].version) continue;
    next.actions[name] = { sha: await tagCommit(api, name, tag), version: tag };
  }
  return next;
}

/** What moved, one line each. */
export function describe(cur, next) {
  const out = [];
  if (cur.gvisor.release !== next.gvisor.release) out.push(`gVisor ${cur.gvisor.release} -> ${next.gvisor.release} (gvisor.json)`);
  if (cur.age.version !== next.age.version) out.push(`age ${cur.age.version} -> ${next.age.version} (scripts/install-age.sh)`);
  for (const [n, p] of Object.entries(next.actions)) if (cur.actions[n]?.sha !== p.sha) out.push(`${n} ${cur.actions[n]?.version} -> ${p.version} (${p.sha}) (pins/actions.json)`);
  return out;
}

/** The pin files with the new pins written in, keeping everything else as it was. Pure. */
export function applyPins(files, cur, next, now = new Date()) {
  const out = {};
  if (cur.gvisor.release !== next.gvisor.release) {
    let s = files['gvisor.json'];
    s = s.replace(`"release": "${cur.gvisor.release}"`, `"release": "${next.gvisor.release}"`);
    for (const arch of GVISOR_ARCHES) {
      s = s.replace(cur.gvisor.bundles[arch].url, next.gvisor.bundles[arch].url).replace(cur.gvisor.bundles[arch].sha512, next.gvisor.bundles[arch].sha512);
    }
    s = s.replace(/Recorded \d{1,2} [A-Z][a-z]{2} \d{4}/, `Recorded ${recorded(now)}`);
    const g = JSON.parse(s);
    if (g.release !== next.gvisor.release || GVISOR_ARCHES.some((a) => g.bundles[a].url !== next.gvisor.bundles[a].url || g.bundles[a].sha512 !== next.gvisor.bundles[a].sha512)) throw new Error('gvisor.json did not take the new pins');
    out['gvisor.json'] = s;
  }
  if (cur.age.version !== next.age.version) {
    out['scripts/install-age.sh'] = files['scripts/install-age.sh']
      .replace(/^# age v\S+, linux-amd64 release tarball \(sha256 recorded [^)]*\)\.$/m, `# age ${next.age.version}, linux-amd64 release tarball (sha256 recorded ${recorded(now)}).`)
      .replace(/^AGE_URL=\S+$/m, `AGE_URL=${next.age.url}`)
      .replace(/^AGE_SHA256=[0-9a-f]{64}$/m, `AGE_SHA256=${next.age.sha256}`);
  }
  let pins = files['pins/actions.json'];
  for (const [n, p] of Object.entries(next.actions)) {
    const c = cur.actions[n];
    if (c.sha === p.sha) continue;
    pins = pins.replace(`"${n}": { "sha": "${c.sha}", "version": "${c.version}" }`, `"${n}": { "sha": "${p.sha}", "version": "${p.version}" }`);
  }
  if (pins !== files['pins/actions.json']) {
    if (JSON.stringify(JSON.parse(pins).actions) !== JSON.stringify(next.actions)) throw new Error('pins/actions.json did not take the new pins');
    out['pins/actions.json'] = pins;
  }
  return out;
}

/** Workflow texts with every `uses: actions/<name>@<sha> # <version>` set to pins/actions.json. Pure. */
export function syncUses(text, actions) {
  return text.replace(/uses: (actions\/[a-z0-9-]+)@[0-9a-f]{40} # v\d+\.\d+\.\d+/g, (m, name) => (actions[name] ? `uses: ${name}@${actions[name].sha} # ${actions[name].version}` : m));
}

/** Opens the pull request through the API; null when a branch for these very pins already exists. */
export async function openPr({ api, repo, changes, lines, base = 'main' }) {
  const digest = createHash('sha256').update(JSON.stringify(Object.entries(changes).sort())).digest('hex').slice(0, 12);
  const branch = `pin-drift/${digest}`;
  try {
    await api(`/repos/${repo}/git/ref/heads/${branch}`);
    return null;
  } catch (e) { if (e.status !== 404) throw e; }
  const head = (await api(`/repos/${repo}/git/ref/heads/${base}`)).object.sha;
  const baseTree = (await api(`/repos/${repo}/git/commits/${head}`)).tree.sha;
  const tree = await api(`/repos/${repo}/git/trees`, { method: 'POST', body: { base_tree: baseTree, tree: Object.entries(changes).map(([path, content]) => ({ path, mode: '100644', type: 'blob', content })) } });
  const commit = await api(`/repos/${repo}/git/commits`, { method: 'POST', body: { message: `Pins: newer releases\n\n${lines.map((l) => `- ${l}`).join('\n')}\n`, tree: tree.sha, parents: [head] } });
  await api(`/repos/${repo}/git/refs`, { method: 'POST', body: { ref: `refs/heads/${branch}`, sha: commit.sha } });
  const actionsMoved = 'pins/actions.json' in changes;
  const body = [
    'Newer releases of what this repository pins, found by `pin-drift.yml`:',
    '',
    ...lines.map((l) => `- ${l}`),
    '',
    'Hashes: each new gVisor bundle was downloaded and its sha512 matched the `.sha512` file published beside it; the age tarball was downloaded and hashed. Action pins are the commits their release tags point to.',
    '',
    '**Before merging (a person):**',
    '',
    '1. This pull request was opened with the workflow token, which cannot start workflows, so no check has run on it yet.',
    actionsMoved
      ? '2. The workflow token cannot change workflow files either, so the action pins are only in `pins/actions.json` so far. Check out this branch, run `node scripts/pin-drift.mjs --sync-workflows`, and commit and push the result (signed). That push starts `ci` and `sandbox-selftest` on this pull request.'
      : '2. Start the checks: close and reopen this pull request (or push a commit to the branch). That runs `ci` and, for a gVisor change, `sandbox-selftest` with its mutation matrix.',
    '3. Merge only when `ci-ok` and `sandbox-selftest` pass. The nightly `conformance-nightly` run then checks the new pins on main and publishes the status tool-qa reads.',
  ].join('\n');
  const pr = await api(`/repos/${repo}/pulls`, { method: 'POST', body: { title: `Pins: ${lines.length} newer release${lines.length === 1 ? '' : 's'}`, head: branch, base, body, maintainer_can_modify: true } });
  return { branch, number: pr.number, url: pr.html_url };
}

async function main(argv, env = process.env) {
  const mode = argv[0];
  if (argv.length !== 1 || !['--check', '--open-pr', '--sync-workflows'].includes(mode)) {
    process.stderr.write('usage: pin-drift.mjs --check | --open-pr | --sync-workflows\n');
    return 2;
  }
  const files = readFiles();
  const cur = currentPins(files);
  if (mode === '--sync-workflows') {
    let n = 0;
    for (const f of workflowFiles()) {
      const s = readFileSync(join(ROOT, f), 'utf8');
      const t = syncUses(s, cur.actions);
      if (t !== s) { writeFileSync(join(ROOT, f), t); n += 1; process.stdout.write(`updated ${f}\n`); }
    }
    process.stdout.write(n ? `${n} file(s) now match pins/actions.json\n` : 'every uses: line already matches pins/actions.json\n');
    return 0;
  }
  const api = githubApi({ token: env.GITHUB_TOKEN || env.GH_TOKEN });
  const next = await latestPins({ api, current: cur });
  const lines = describe(cur, next);
  if (!lines.length) { process.stdout.write('every pin is the newest release\n'); return 0; }
  for (const l of lines) process.stdout.write(`behind: ${l}\n`);
  if (mode === '--check') return 3;
  const repo = env.GITHUB_REPOSITORY;
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(String(repo ?? ''))) { process.stderr.write('GITHUB_REPOSITORY is required\n'); return 2; }
  const pr = await openPr({ api, repo, changes: applyPins(files, cur, next), lines });
  process.stdout.write(pr ? `opened ${pr.url} from ${pr.branch}\n` : 'a branch for these pins already exists; nothing opened\n');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.argv.slice(2)).then((c) => { process.exitCode = c; }, (e) => { process.stderr.write(`pin-drift: ${String(e?.message ?? e).replace(/gh[pousr]_[A-Za-z0-9]+/g, '***')}\n`); process.exitCode = 1; });
}
