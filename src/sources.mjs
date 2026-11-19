// Host-side fetches (our code, fixed hosts, bounded): GitHub repository facts and the source archive
// of one commit, and the official MCP Registry entry. Nothing fetched here is executed; the archive
// goes to the static reader's container on stdin. The GitHub token (the job's read-only GITHUB_TOKEN,
// for the API rate limit) is sent to api.github.com only and never reaches a container.
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

export const ARCHIVE_CAP = 256 * 1024 * 1024;
export const REGISTRY_BASE = 'https://registry.modelcontextprotocol.io';
const UA = 'isokron-surface-corpus';
const SHA = /^[0-9a-f]{40}$/;

async function getJson(fetchFn, url, headers = {}, ms = 30_000, cap = 8 * 1024 * 1024) {
  const r = await fetchFn(url, { headers: { 'user-agent': UA, accept: 'application/json', ...headers }, signal: AbortSignal.timeout(ms), redirect: 'follow' });
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > cap) throw new Error(`answer over ${cap} bytes`);
  if (!r.ok) throw Object.assign(new Error(`HTTP ${r.status}`), { status: r.status });
  return JSON.parse(buf.toString('utf8'));
}

/**
 * Repository facts and the commit to read. `t.commit` is used as given; `t.ref` is resolved here and
 * the SHA recorded. Returns { ok, sha, pinned, repo: { stars, forks, license_spdx, archived, fork,
 * pushed_at, default_branch, created_at, size_kb, topics_n, open_issues }, commit: { date }, errors }.
 */
export async function githubFacts(t, { fetchFn = fetch, token = null, cacheDir = null } = {}) {
  const h = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28', ...(token ? { authorization: `Bearer ${token}` } : {}) };
  const out = { ok: false, sha: t.commit ?? null, pinned: !!t.commit, ref: t.ref ?? null, repo: null, commit: null, errors: [] };
  try {
    const j = await getJson(fetchFn, `https://api.github.com/repos/${t.repo}`, h);
    out.repo = {
      stars: num(j.stargazers_count), forks: num(j.forks_count), open_issues: num(j.open_issues_count),
      license_spdx: j.license && typeof j.license.spdx_id === 'string' ? j.license.spdx_id.slice(0, 40) : null,
      archived: !!j.archived, fork: !!j.fork, disabled: !!j.disabled,
      pushed_at: iso(j.pushed_at), created_at: iso(j.created_at), default_branch: typeof j.default_branch === 'string' ? j.default_branch.slice(0, 120) : null,
      size_kb: num(j.size), topics_n: Array.isArray(j.topics) ? j.topics.length : null, has_mcp_topic: Array.isArray(j.topics) ? j.topics.some((x) => /^(mcp|mcp-server|model-context-protocol)$/.test(String(x))) : null,
      language: typeof j.language === 'string' ? j.language.slice(0, 40) : null,
    };
  } catch (e) { out.errors.push({ step: 'repo', error: msg(e), status: e.status ?? null }); }
  try {
    const j = await getJson(fetchFn, `https://api.github.com/repos/${t.repo}/commits/${encodeURIComponent(t.commit ?? t.ref)}`, h);
    if (typeof j.sha === 'string' && SHA.test(j.sha)) {
      if (t.commit && j.sha !== t.commit) out.errors.push({ step: 'commit', error: 'the API answered another commit' });
      else out.sha = j.sha;
      out.commit = { date: iso(j.commit && j.commit.committer && j.commit.committer.date), author_date: iso(j.commit && j.commit.author && j.commit.author.date), verified: !!(j.commit && j.commit.verification && j.commit.verification.verified) };
    }
  } catch (e) { out.errors.push({ step: 'commit', error: msg(e), status: e.status ?? null }); }
  // A mirror or an offline machine may hold the facts beside the archive (<sha>.facts.json); used only
  // for what the API did not answer, and marked.
  if (cacheDir && out.sha && (!out.repo || !out.commit) && existsSync(join(cacheDir, `${out.sha}.facts.json`))) {
    try {
      const c = JSON.parse(readFileSync(join(cacheDir, `${out.sha}.facts.json`), 'utf8'));
      if (!out.repo && c.repo && typeof c.repo === 'object') { out.repo = { stars: num(c.repo.stars), forks: num(c.repo.forks), open_issues: null, license_spdx: str(c.repo.license_spdx, 40), archived: !!c.repo.archived, fork: !!c.repo.fork, disabled: false, pushed_at: iso(c.repo.pushed_at), created_at: null, default_branch: null, size_kb: null, topics_n: null, has_mcp_topic: null, language: null }; out.via_cache = true; }
      if (!out.commit && c.commit && typeof c.commit === 'object') { out.commit = { date: iso(c.commit.date), author_date: null, verified: false }; out.via_cache = true; }
    } catch { /* an unreadable cache file is no facts */ }
  }
  out.ok = !!out.sha;
  return out;
}

/**
 * The tar.gz of one commit. From `cacheDir/<sha>.tar.gz` when it is there (a mirror, a machine that
 * cannot reach codeload, tests), else from codeload.github.com. Returns { buf, sha256, bytes, via }.
 */
export async function sourceArchive(repo, sha, { fetchFn = fetch, cacheDir = null } = {}) {
  if (!SHA.test(sha)) throw new Error('the source archive needs a full commit SHA');
  let buf; let via;
  if (cacheDir && existsSync(join(cacheDir, `${sha}.tar.gz`))) { buf = readFileSync(join(cacheDir, `${sha}.tar.gz`)); via = 'cache'; } else {
    const r = await fetchFn(`https://codeload.github.com/${repo}/tar.gz/${sha}`, { headers: { 'user-agent': UA }, signal: AbortSignal.timeout(180_000), redirect: 'follow' });
    if (!r.ok) throw Object.assign(new Error(`HTTP ${r.status}`), { status: r.status });
    const len = Number(r.headers.get('content-length') || 0);
    if (len > ARCHIVE_CAP) throw new Error('the source archive is over the size cap');
    const chunks = []; let n = 0;
    for await (const c of r.body) { n += c.length; if (n > ARCHIVE_CAP) throw new Error('the source archive is over the size cap'); chunks.push(c); }
    buf = Buffer.concat(chunks); via = 'codeload';
  }
  if (buf.length > ARCHIVE_CAP) throw new Error('the source archive is over the size cap');
  if (!(buf[0] === 0x1f && buf[1] === 0x8b)) throw new Error('the source archive is not gzip');
  return { buf, sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length, via };
}

/**
 * Layer (a): the official MCP Registry entry (server.json) for a server name. The registry carries
 * how to run a server (packages, remotes, declared environment variables), not its tool list, so
 * this layer supplies the launch facts and the declared env; tools come from the layers below unless
 * the entry's _meta carries a static tools/list.
 */
export async function registryEntry(name, { fetchFn = fetch, base = REGISTRY_BASE } = {}) {
  const out = { ok: false, name, found: false, version: null, packages: [], remotes: [], env: [], repository: null, tools: null, raw: null, error: null };
  try {
    const d = await getJson(fetchFn, `${base}/v0/servers?search=${encodeURIComponent(name)}&version=latest&limit=30`);
    out.ok = true;
    const hit = (Array.isArray(d.servers) ? d.servers : []).map((x) => (x && x.server) || x).find((s) => s && s.name === name);
    if (!hit) return out;
    out.found = true;
    out.raw = hit;
    out.version = typeof hit.version === 'string' ? hit.version.slice(0, 64) : null;
    out.repository = hit.repository && typeof hit.repository.url === 'string' ? { url: hit.repository.url.slice(0, 300), subfolder: typeof hit.repository.subfolder === 'string' ? hit.repository.subfolder.slice(0, 200) : null } : null;
    for (const p of Array.isArray(hit.packages) ? hit.packages.slice(0, 20) : []) {
      if (!p || typeof p !== 'object') continue;
      const env = Array.isArray(p.environmentVariables) ? p.environmentVariables.filter((e) => e && typeof e.name === 'string').slice(0, 100) : [];
      out.packages.push({ registry_type: str(p.registryType, 20), identifier: str(p.identifier, 200), version: str(p.version, 64), transport: p.transport && str(p.transport.type, 30), runtime_hint: str(p.runtimeHint, 30), env_n: env.length });
      for (const e of env) out.env.push({ name: e.name.slice(0, 128), required: !!e.isRequired, secret: !!e.isSecret, has_default: e.default !== undefined });
    }
    for (const r of Array.isArray(hit.remotes) ? hit.remotes.slice(0, 20) : []) {
      if (r && typeof r.url === 'string') out.remotes.push({ type: str(r.type, 30), templated: /\{/.test(r.url), needs_headers: Array.isArray(r.headers) && r.headers.some((x) => x && x.isRequired) });
    }
    const metas = hit._meta && typeof hit._meta === 'object' ? Object.values(hit._meta) : [];
    for (const m of metas) { const tl = m && m.static_responses && m.static_responses['tools/list']; if (tl && Array.isArray(tl.tools)) { out.tools = tl.tools; break; } }
  } catch (e) { out.error = msg(e); }
  return out;
}

const num = (x) => (Number.isFinite(x) ? x : null);
const iso = (x) => (typeof x === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(x) ? x.slice(0, 30) : null);
const str = (x, n) => (typeof x === 'string' ? x.slice(0, n) : null);
const msg = (e) => String((e && e.message) || e).slice(0, 200);
