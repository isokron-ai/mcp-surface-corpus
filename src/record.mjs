// From one target's pieces (probe, static reader, analysis, facts) to the two compact shapes the
// aggregate is made from: the row (numbers, booleans and fixed-vocabulary strings; no name, no
// description, no tool text of the target) and the state (fingerprints, for the diff against the
// previous run). Both are private (encrypted) in transit; only sums of rows are ever public.
import { minor, SDKS } from './sdk.mjs';
import { isSecretName } from './env-refs.mjs';

export const ROW_FORMAT = 'isokron-surface-row/1';
export const STATE_FORMAT = 'isokron-surface-state/1';
export const RECORD_FORMAT = 'isokron-surface-record/1';

const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
const SDK_IDS = new Set(SDKS.map((s) => s[0]));
const LICENCES = new Set(['MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'ISC', 'GPL-2.0', 'GPL-3.0', 'AGPL-3.0', 'LGPL', 'LGPL-2.1', 'LGPL-3.0', 'MPL-2.0', 'Unlicense', 'BUSL-1.1', 'CC0-1.0', '0BSD', 'NOASSERTION']);
const PROTOCOLS = new Set(['2024-11-05', '2025-03-26', '2025-06-18', '2025-11-25', '2026-07-28']);
const CAPS = new Set(['tools', 'prompts', 'resources', 'logging', 'completions', 'experimental', 'tasks', 'elicitation', 'sampling', 'roots', 'extensions']);

/** Values from a target that go into a row are mapped onto a fixed vocabulary; anything else is "other". */
export const vocab = (set, v) => (v === null || v === undefined ? null : set.has(v) ? v : 'other');
export const licence = (v) => (typeof v === 'string' ? vocab(LICENCES, v.replace(/-(only|or-later)$/, '')) : null);

const daysBetween = (a, b) => { const x = Date.parse(a); const y = Date.parse(b); return Number.isFinite(x) && Number.isFinite(y) ? Math.max(0, Math.round((y - x) / 86400000)) : null; };

/** Which installed, locked or declared SDK the server runs on: prefer one its own manifest declares. */
export function resolveSdk(hits) {
  const list = (hits || []).filter((h) => h && SDK_IDS.has(h.sdk));
  if (!list.length) return null;
  const rank = { installed: 0, locked: 1, declared: 2 };
  const minDepth = Math.min(...list.filter((h) => h.kind === 'declared').map((h) => h.depth ?? 0), Infinity);
  const declared = new Set(list.filter((h) => h.kind === 'declared' && (h.depth ?? 0) === minDepth).map((h) => h.sdk));
  const order = (h) => SDKS.findIndex((s) => s[0] === h.sdk);
  const sorted = [...list].sort((a, b) => (declared.has(b.sdk) - declared.has(a.sdk)) || (rank[a.kind] - rank[b.kind]) || ((a.depth ?? 0) - (b.depth ?? 0)) || (order(a) - order(b)));
  // The declared SDK, with the version of its best (installed, then locked) hit.
  const top = sorted[0];
  const versioned = sorted.find((h) => h.sdk === top.sdk && h.version) ?? top;
  return { id: top.sdk, ecosystem: top.ecosystem, version: versioned.version ?? null, minor: minor(versioned.version), kind: versioned.kind, source: versioned.source, declared: declared.has(top.sdk) };
}

function probeSummary(p) {
  if (!p) return null;
  const tl = p.lists && p.lists['tools/list'];
  return { ok: !!(tl && tl.ok), era: p.era ?? null, error: p.error ? 'transport' : p.initialize_error && !(tl && tl.ok) ? 'initialize' : tl && tl.error ? 'tools_list' : null, tools: tl && Array.isArray(tl.items) ? tl.items.length : null, exit: p.transport ? p.transport.exit : null };
}

/**
 * The row. `p` is the primary probe (the one whose list is graded), `bare` the probe with no env,
 * `withEnv` the probe with dummy env values (either may be null).
 */
export function buildRow({ id, publicExit, launch, facts, registry, stat, bare, withEnv, primary, analysis, envNames, lockHits, timing, baselineMs, now = new Date().toISOString() }) {
  const A = analysis || {};
  const runs = A.runs || {};
  const p = primary;
  const liveOk = !!(runs.live && runs.live.ok && p);
  const best = stat && stat.static && stat.static.best;
  const row = {
    format: ROW_FORMAT, id, public_exit: publicExit,
    acquired: liveOk ? 'live' : runs.static_best && runs.static_best.ok ? 'static' : runs.readme && runs.readme.ok ? 'readme' : runs.registry && runs.registry.ok ? 'registry' : 'none',
    layers: {
      registry: registry ? { looked_up: true, found: !!registry.found, tools: Array.isArray(registry.tools) ? registry.tools.length : 0, packages: registry.packages ? registry.packages.length : 0, remotes: registry.remotes ? registry.remotes.length : 0 } : { looked_up: false },
      live: { attempted: !!launch, kind: launch ? launch.kind : null, transport: launch ? launch.transport ?? 'stdio' : null, ok: liveOk, bare: probeSummary(bare), with_env: probeSummary(withEnv), primary: p ? (p === withEnv ? 'with_env' : 'bare') : null },
      static: best ? { kind: best.kind, fidelity: best.fidelity, tools: best.tools, candidates: stat.static.candidates.length } : null,
      readme: stat && stat.readme ? { tools: stat.readme.tools.length } : null,
    },
    live: null, env: null, size: null, sdk: null,
    language: stat ? stat.primary_language ?? null : null,
    checks: {}, grades: {}, engine_error: {}, features: {}, static_vs_live: null,
    repo: null, timing: timing || null,
  };
  if (p && liveOk) {
    const init = isObj(p.initialize) ? p.initialize : {};
    const caps = isObj(init.capabilities) ? Object.keys(init.capabilities) : [];
    const lf = A.list_features || { lists: {}, consistency: {}, list_changed: {} };
    const n = (m) => (lf.lists[m] && lf.lists[m].ok ? lf.lists[m].items : null);
    const bareTools = probeSummary(bare); const envTools = probeSummary(withEnv);
    row.live = {
      era: p.era ?? null, protocol_version: vocab(PROTOCOLS, typeof init.protocolVersion === 'string' ? init.protocolVersion : null),
      capabilities: [...new Set(caps.map((c) => vocab(CAPS, c)))].sort(), list_changed: lf.list_changed,
      starts_without_env: bareTools ? bareTools.ok : null, starts_with_dummy_env: envTools ? envTools.ok : null,
      env_changes_list: bareTools && envTools && bareTools.ok && envTools.ok ? bareTools.tools !== envTools.tools : null,
      initialize_ms: p.timing ? p.timing.initialize_ms : null, tools_ms: p.timing ? p.timing.tools_ms : null, total_ms: p.timing ? p.timing.total_ms : null,
      baseline_ms: baselineMs ?? null,
      startup_ms: p.timing && Number.isFinite(p.timing.initialize_ms) ? Math.max(0, p.timing.initialize_ms - (baselineMs ?? 0)) : null,
      pages: lf.lists['tools/list'] ? lf.lists['tools/list'].pages : null, paginated: lf.lists['tools/list'] ? !!lf.lists['tools/list'].paginated : null,
      prompts: n('prompts/list'), resources: n('resources/list'), resource_templates: n('resources/templates/list'),
      consistency: lf.consistency,
      instructions_chars: typeof init.instructions === 'string' ? init.instructions.length : 0,
      server_info: { has: isObj(init.serverInfo), title: isObj(init.serverInfo) && typeof init.serverInfo.title === 'string', version: isObj(init.serverInfo) && typeof init.serverInfo.version === 'string', icons: isObj(init.serverInfo) && Array.isArray(init.serverInfo.icons) },
      stderr_bytes: p.stderr_bytes ?? 0, non_json_lines: p.transport ? p.transport.non_json_lines : 0,
      notifications: p.transport ? p.transport.notifications.length : 0, server_requests: p.transport ? [...new Set(p.transport.server_requests)].filter((m) => ['ping', 'roots/list', 'sampling/createMessage', 'elicitation/create'].includes(m)).sort() : [],
    };
  }
  const reg = registry && registry.env ? registry.env : [];
  const names = envNames || {};
  row.env = {
    list: (names.list || []).length, registry_declared: reg.length, registry_required: reg.filter((e) => e.required).length, registry_secret: reg.filter((e) => e.secret).length,
    readme: (names.readme || []).length, source: (names.source || []).length,
    used: (names.used || []).length, secret_named: (names.used || []).filter(isSecretName).length,
    source_secret_named: (names.source || []).filter(isSecretName).length,
  };
  const sizeFrom = liveOk && A.tokens && A.tokens.live ? ['live', A.tokens.live, runs.live.tool_count] : A.tokens && A.tokens.static_best && runs.static_best && runs.static_best.ok ? ['static', A.tokens.static_best, runs.static_best.tool_count] : null;
  if (sizeFrom) row.size = { from: sizeFrom[0], tools: sizeFrom[2], bytes: sizeFrom[1].bytes, tokens: { bytes_div_4: sizeFrom[1].bytes_div_4, bpe_approx: sizeFrom[1].bpe_approx, claude_approx: sizeFrom[1].claude_approx } };
  row.sdk = resolveSdk([...(lockHits || []), ...((stat && stat.sdk && stat.sdk.hits) || [])]);
  for (const [k, key] of [['live', 'live'], ['static', 'static_best'], ['readme', 'readme']]) {
    const r = runs[key];
    if (!r) continue;
    if (!r.ok) { row.engine_error[k] = String(r.error_type || 'error').slice(0, 40); continue; }
    row.checks[k] = Object.fromEntries(Object.entries(r.matrix).filter(([, v]) => v.findings > 0).map(([cid, v]) => [cid, [v.findings, v.tools]]));
    row.grades[k] = Object.fromEntries(Object.entries(r.grades).map(([s, g]) => [s, { grade: g.grade, score: g.score, ready: g.ready }]));
    if (A.features && A.features[key]) row.features[k] = A.features[key];
  }
  if (A.static_vs_live && A.static_vs_live.best) {
    const b = A.static_vs_live.best;
    row.static_vs_live = { kind: b.kind, fidelity: b.fidelity, static_tools: b.static_tools, live_tools: b.live_tools, shared: b.shared, only_live: b.only_live.length, only_static: b.only_static.length, name_jaccard: b.name_jaccard, agree: b.agree, param_jaccard_mean: b.param_jaccard_mean, checks: A.static_vs_live.checks || null, readme: A.static_vs_live.readme ? { name_jaccard: A.static_vs_live.readme.name_jaccard, shared: A.static_vs_live.readme.shared, only_live: A.static_vs_live.readme.only_live.length, only_static: A.static_vs_live.readme.only_static.length } : null };
  }
  const g = facts || {};
  const licFile = stat && stat.license_files && stat.license_files[0] ? stat.license_files[0].spdx_guess : null;
  row.repo = {
    pinned: !!g.pinned, stars: g.repo ? g.repo.stars : null, forks: g.repo ? g.repo.forks : null, archived: g.repo ? g.repo.archived : null, fork: g.repo ? g.repo.fork : null,
    licence: licence((g.repo && g.repo.license_spdx && g.repo.license_spdx !== 'NOASSERTION' ? g.repo.license_spdx : null) ?? licFile), licence_from: g.repo && g.repo.license_spdx && g.repo.license_spdx !== 'NOASSERTION' ? 'github' : licFile ? 'file' : null,
    commit_age_days: g.commit && g.commit.date ? daysBetween(g.commit.date, now) : null, pushed_age_days: g.repo && g.repo.pushed_at ? daysBetween(g.repo.pushed_at, now) : null,
    has_server_json: !!(stat && stat.server_json && stat.server_json.length), has_lockfile: !!(stat && stat.manifests && stat.manifests.some((m) => /(lock|shrinkwrap|go\.mod)/.test(m.path))),
  };
  return row;
}

/** The state kept for the next run's diff: per-tool fingerprints of the best list, and what fired. */
export function buildState({ id, row, analysis, sha, resolved }) {
  const src = row.acquired === 'live' ? 'live' : row.acquired === 'static' ? 'static_best' : row.acquired === 'readme' ? 'readme' : null;
  const fp = src && analysis && analysis.fingerprints ? analysis.fingerprints[src] || [] : [];
  const k = row.acquired === 'static' ? 'static' : row.acquired;
  return {
    format: STATE_FORMAT, id, acquired: row.acquired, commit: sha ?? null, package_version: resolved ?? null,
    sdk: row.sdk ? { id: row.sdk.id, version: row.sdk.version } : null,
    protocol_version: row.live ? row.live.protocol_version : null,
    bytes: row.size ? row.size.bytes : null,
    tools: fp,
    checks: Object.keys(row.checks[k] || {}).sort(),
    grades: Object.fromEntries(Object.entries(row.grades[k] || {}).map(([s, g]) => [s, g.grade])),
  };
}
