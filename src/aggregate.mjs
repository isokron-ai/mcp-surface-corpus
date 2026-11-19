// From rows (one per target) to the public aggregate and the calibration report.
//
// Disclosure control. The public aggregate carries counts over servers, never a target id or any
// text a target wrote. A count of 1 to minCell-1 servers is not published ("cells under 5"), and
// neither is a count whose complement is that small (96 of 98 would give away the 2). In a
// breakdown by category, small categories are merged into "other" until "other" is itself at least
// minCell (or the breakdown is withheld), so a hidden count cannot be worked out by subtraction.
// A count of zero is published: it describes no server. Quantiles are published from minCell
// values up; minima and maxima never (each is one server's value). When a sub-population (say, the
// servers with a live list) is all but a few of its parent, its size would give those few away, so
// tables over it carry rates only (two decimals) and no counts ("counts_withheld").
import { diffRuns } from './compare.mjs';

export const AGG_FORMAT = 'isokron-surface-aggregate/1';
export const DEFAULT_MIN_CELL = 5;
export const ALMOST_ALL = 0.9;
export const DISAGREE = 0.2;

const round = (x, d = 4) => (Number.isFinite(x) ? Math.round(x * 10 ** d) / 10 ** d : null);

/** k of N servers. `hide`: the population's size is itself withheld, so only a rounded rate is given. */
export function cell(k, N, min = DEFAULT_MIN_CELL, hide = false) {
  if (N === 0) return { n: 0, of: hide ? null : 0, rate: null };
  if (N < min) return { n: null, of: null, suppressed: true };
  if (k > 0 && k < min) return { n: null, of: hide ? null : N, suppressed: true, ...(hide ? {} : { bound: `<${min}` }) };
  if (N - k > 0 && N - k < min) return { n: null, of: hide ? null : N, suppressed: true, ...(hide ? { bound: 'nearly all' } : { bound: `>${N - min}` }) };
  if (hide) return { n: k === 0 ? 0 : null, of: null, rate: round(k / N, 2), counts_withheld: true };
  return { n: k, of: N, rate: round(k / N) };
}

/** A sub-population. It is marked `hide` when it leaves out 1 to min-1 of its parent (or the parent is hidden). */
export function sub(parent, f, min = DEFAULT_MIN_CELL) {
  const R = parent.filter(f);
  const gap = parent.length - R.length;
  R.hide = !!parent.hide || (gap > 0 && gap < min);
  return R;
}

/** The size of a population, when it may be given. */
export const size = (R, min = DEFAULT_MIN_CELL) => (R.hide || (R.length > 0 && R.length < min) ? null : R.length);

/** Counts by category, with small categories merged into "other" (see the header). */
export function categorical(counts, min = DEFAULT_MIN_CELL, hide = false) {
  const entries = Object.entries(counts).filter(([, c]) => c > 0).sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
  const total = entries.reduce((s, [, c]) => s + c, 0);
  if (total === 0) return { of: 0, by: {} };
  if (total < min) return { of: null, suppressed: true };
  const shown = entries.filter(([, c]) => c >= min);
  let other = entries.filter(([, c]) => c < min).reduce((s, [, c]) => s + c, 0);
  let merged = entries.length - shown.length;
  while (other > 0 && other < min && shown.length) { other += shown.pop()[1]; merged++; }
  const one = (c) => (hide ? { rate: round(c / total, 2) } : { n: c, rate: round(c / total) });
  const by = Object.fromEntries(shown.map(([k, c]) => [k, one(c)]));
  if (other > 0) by.other = { ...one(other), merged_categories: merged };
  return hide ? { of: null, counts_withheld: true, by } : { of: total, by };
}

/** A numeric distribution: quartiles from minCell values, deciles from four times that, and a histogram. */
export function dist(values, { min = DEFAULT_MIN_CELL, edges = null, hide = false } = {}) {
  const v = values.filter((x) => Number.isFinite(x)).sort((a, b) => a - b);
  if (v.length === 0) return { n: 0 };
  if (v.length < min) return { n: null, suppressed: true };
  const q = (p) => { const i = (v.length - 1) * p; const lo = Math.floor(i); const hi = Math.ceil(i); return round(v[lo] + (v[hi] - v[lo]) * (i - lo), 2); };
  const out = { n: hide ? null : v.length, p25: q(0.25), p50: q(0.5), p75: q(0.75), mean: round(v.reduce((a, b) => a + b, 0) / v.length, 2) };
  if (v.length >= 4 * min) { out.p10 = q(0.1); out.p90 = q(0.9); }
  if (edges && !hide) {
    const counts = {};
    const label = (i) => (i === 0 ? `<${edges[0]}` : i === edges.length ? `>=${edges[edges.length - 1]}` : `${edges[i - 1]}-${edges[i] - 1}`);
    for (let i = 0; i <= edges.length; i++) counts[label(i)] = 0;
    for (const x of v) { let i = edges.findIndex((e) => x < e); if (i < 0) i = edges.length; counts[label(i)]++; }
    out.histogram = histogram(counts, min);
  }
  return out;
}

/** Ordered buckets: a bucket under minCell is merged with its neighbour until none is (order is kept). */
export function histogram(counts, min = DEFAULT_MIN_CELL) {
  let b = Object.entries(counts).map(([k, c]) => ({ from: k, to: k, n: c }));
  const total = b.reduce((s, x) => s + x.n, 0);
  if (total < min) return { suppressed: true };
  b = b.filter((x, i) => x.n > 0 || (i > 0 && i < b.length - 1));
  for (;;) {
    const i = b.findIndex((x) => x.n > 0 && x.n < min);
    if (i < 0 || b.length === 1) break;
    const j = i === 0 ? 1 : i === b.length - 1 ? i - 1 : b[i - 1].n <= b[i + 1].n ? i - 1 : i + 1;
    const [lo, hi] = i < j ? [i, j] : [j, i];
    b.splice(lo, 2, { from: b[lo].from, to: b[hi].to, n: b[lo].n + b[hi].n });
  }
  return { buckets: b.filter((x) => x.n > 0).map((x) => ({ range: x.from === x.to ? x.from : `${x.from} .. ${x.to}`, n: x.n })) };
}

const count = (rows, f) => rows.filter(f).length;
const tally = (rows, f) => { const o = {}; for (const r of rows) { const k = f(r); if (k === null || k === undefined) continue; for (const x of Array.isArray(k) ? k : [k]) o[x] = (o[x] || 0) + 1; } return o; };
const share = (a, b) => (b > 0 ? a / b : null);

function checksTable(R, key, checks, min) {
  const per = {};
  for (const c of checks) {
    const hit = R.filter((r) => r.checks[key][c.id]);
    const servers = cell(hit.length, R.length, min, R.hide);
    // Over the servers the check fired on: the share of their tools it fired on. Its size would repeat the cell, so it is not given.
    // The default severity is the check's; the severity seen is the worst one each server's findings carried (an envelope check is advice on an earlier-era server).
    const seen = tally(hit, (r) => r.checks[key][c.id][2] || null);
    per[c.id] = { section: c.section, severity: c.severity, severity_seen: servers.suppressed ? null : categorical(seen, min, R.hide), servers, tool_share_when_fired: servers.suppressed ? { n: null, suppressed: true } : dist(hit.map((r) => share(r.checks[key][c.id][1], r.features && r.features[key] ? r.features[key].tools : null)).filter((x) => x !== null), { min, hide: true }) };
  }
  return { n: size(R, min), enough: R.length >= min, counts_withheld: !!R.hide, per_check: per };
}

function gradesTable(R, key, min) {
  const out = {};
  for (const s of ['spec', 'anthropic', 'openai', 'security', 'quality', 'surface']) {
    const G = sub(R, (r) => r.grades[key][s] && r.grades[key][s].ready !== null && r.grades[key][s].ready !== undefined, min);
    out[s] = { grade: categorical(tally(R, (r) => (r.grades[key][s] ? r.grades[key][s].grade ?? 'none' : null)), min, R.hide), ready: cell(count(G, (r) => r.grades[key][s].ready === true), G.length, min, G.hide), score: dist(R.map((r) => (r.grades[key][s] ? r.grades[key][s].score : null)), { min, hide: R.hide }) };
  }
  return out;
}

function featureTable(R, key, min) {
  const f = (r) => r.features[key];
  const cov = (g) => dist(R.map((r) => share(g(f(r)), f(r).tools)), { min, hide: R.hide });
  const any = (g) => cell(count(R, (r) => g(f(r)) > 0), R.length, min, R.hide);
  const all = (g) => cell(count(R, (r) => g(f(r)) === f(r).tools), R.length, min, R.hide);
  const d = (vals) => dist(vals, { min, hide: R.hide });
  const hints = {};
  for (const h of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) hints[h] = { any_tool_sets_it: any((x) => x.annotations.hints[h].set), every_tool_sets_it: all((x) => x.annotations.hints[h].set), share_of_tools_setting_it: cov((x) => x.annotations.hints[h].set), share_of_tools_true: cov((x) => x.annotations.hints[h].true) };
  return {
    n: size(R, min), counts_withheld: !!R.hide,
    annotations: { any_tool: any((x) => x.annotations.any), every_tool: all((x) => x.annotations.any), share_of_tools: cov((x) => x.annotations.any), all_four_hints_every_tool: all((x) => x.annotations.all_four_hints), title_in_annotations_any: any((x) => x.annotations.title_in_annotations), unknown_keys_any: any((x) => x.annotations.unknown_keys), hints },
    title: { any_tool: any((x) => x.title), every_tool: all((x) => x.title), share_of_tools: cov((x) => x.title) },
    description: { any_missing: any((x) => x.description.missing), median_length: d(R.map((r) => (f(r).description.length ? f(r).description.length.p50 : null))) },
    output_schema: { any_tool: any((x) => x.output_schema), every_tool: all((x) => x.output_schema), share_of_tools: cov((x) => x.output_schema) },
    input_schema: { any_missing: any((x) => x.input_schema.missing), additional_properties_false_every_tool: all((x) => x.input_schema.additional_properties_false), declares_dialect_any: any((x) => x.input_schema.declares_schema_dialect), param_description_share: d(R.map((r) => share(f(r).input_schema.param_descriptions.with, f(r).input_schema.param_descriptions.total)).filter((x) => x !== null)), max_depth: d(R.map((r) => f(r).input_schema.max_depth)), median_properties: d(R.map((r) => (f(r).input_schema.properties ? f(r).input_schema.properties.p50 : null))) },
    meta_any: any((x) => x.meta), icons_any: any((x) => x.icons), execution_any: any((x) => x.execution),
    name_style: categorical(tally(R, (r) => { const e = Object.entries(f(r).name_styles).sort((x, y) => y[1] - x[1])[0]; return e ? e[0] : null; }), min, R.hide),
    mixed_name_styles: cell(count(R, (r) => Object.keys(f(r).name_styles).filter((k) => k !== 'single').length > 1), R.length, min, R.hide),
  };
}

const STAR_EDGES = [10, 100, 1000, 10000];
const AGE_EDGES = [7, 30, 90, 365];
const TOOL_EDGES = [5, 10, 20, 40, 80];
const TOKEN_EDGES = [1000, 2500, 5000, 10000, 25000, 50000];
const MS_EDGES = [250, 500, 1000, 2000, 5000, 15000];

/** Per-target diff against the previous run's state (private), and its public summary. */
export function diffStates(prev, cur) {
  const P = new Map((prev || []).map((s) => [s.id, s]));
  const out = [];
  for (const c of cur || []) {
    const p = P.get(c.id);
    if (!p) { out.push({ id: c.id, new: true }); continue; }
    const tools = diffRuns(p.tools, c.tools);
    const pc = new Set(p.checks || []); const cc = new Set(c.checks || []);
    const grades = {};
    for (const s of new Set([...Object.keys(p.grades || {}), ...Object.keys(c.grades || {})])) if ((p.grades || {})[s] !== (c.grades || {})[s]) grades[s] = [(p.grades || {})[s] ?? null, (c.grades || {})[s] ?? null];
    const d = {
      id: c.id, new: false, acquired: [p.acquired, c.acquired], acquired_changed: p.acquired !== c.acquired,
      commit_changed: p.commit !== c.commit, version_changed: p.package_version !== c.package_version,
      sdk_changed: JSON.stringify(p.sdk) !== JSON.stringify(c.sdk), protocol_changed: p.protocol_version !== c.protocol_version,
      bytes_delta: Number.isFinite(p.bytes) && Number.isFinite(c.bytes) ? c.bytes - p.bytes : null,
      tools: { added: tools.added, removed: tools.removed, changed: tools.changed, unchanged: tools.unchanged },
      checks_added: [...cc].filter((x) => !pc.has(x)).sort(), checks_removed: [...pc].filter((x) => !cc.has(x)).sort(), grades,
    };
    d.any = d.acquired_changed || tools.any || d.checks_added.length + d.checks_removed.length > 0 || Object.keys(grades).length > 0;
    out.push(d);
  }
  const gone = [...P.keys()].filter((id) => !(cur || []).some((c) => c.id === id));
  return { per_target: out, gone };
}

function diffSummary(d, min) {
  const all = d.per_target;
  const C = sub(all, (x) => !x.new, min);
  const N = C.length;
  const c = (f) => cell(count(C, f), N, min, C.hide);
  const partTally = {};
  for (const x of C) for (const part of new Set(x.tools.changed.flatMap((t) => t.parts))) partTally[part] = (partTally[part] || 0) + 1;
  const listChanged = (x) => x.tools.added.length + x.tools.removed.length + x.tools.changed.length > 0;
  return {
    compared: size(C, min), counts_withheld: !!C.hide, new_targets: cell(all.length - N, all.length, min), gone_targets: d.gone.length === 0 ? 0 : d.gone.length < min ? null : d.gone.length,
    any_change: c((x) => x.any), list_changed: c(listChanged),
    tools_added: c((x) => x.tools.added.length > 0), tools_removed: c((x) => x.tools.removed.length > 0), tools_changed: c((x) => x.tools.changed.length > 0),
    changed_parts: Object.fromEntries(Object.entries(partTally).map(([k, v]) => [k, cell(v, N, min, C.hide)])),
    commit_changed: c((x) => x.commit_changed), version_changed: c((x) => x.version_changed), sdk_changed: c((x) => x.sdk_changed), protocol_changed: c((x) => x.protocol_changed),
    acquired_changed: c((x) => x.acquired_changed), checks_changed: c((x) => x.checks_added.length + x.checks_removed.length > 0), grade_changed: c((x) => Object.keys(x.grades).length > 0),
    list_changed_without_commit_change: c((x) => !x.commit_changed && !x.version_changed && listChanged(x)),
  };
}

/**
 * rows: isokron-surface-row/1. checks: the engine's check list ({ id, section, severity }).
 * Returns the aggregate with every cell passed through the disclosure rules for `minCell`.
 */
export function aggregate(rowsIn, { checks, minCell = DEFAULT_MIN_CELL, engine = null, diff = null, example = false, now = new Date().toISOString(), shards = null } = {}) {
  const min = minCell;
  const rows = [...rowsIn];
  const N = rows.length;
  const S = (P, f) => sub(P, f, min);
  const c = (R, f) => cell(count(R, f), R.length, min, R.hide);
  const cat = (R, f) => categorical(tally(R, f), min, R.hide);
  const d = (R, f, edges = null) => dist(R.map(f), { min, edges, hide: R.hide });
  const attempted = S(rows, (r) => r.layers.live.attempted);
  const L = S(attempted, (r) => !!r.live);
  const failed = S(attempted, (r) => !r.layers.live.ok);
  const lookedUp = S(rows, (r) => r.layers.registry.looked_up);
  const inRegistry = S(lookedUp, (r) => r.layers.registry.found);
  const sized = S(rows, (r) => !!r.size);
  const both = S(L, (r) => !!r.static_vs_live);
  const bothChecks = S(both, (r) => !!r.static_vs_live.checks);
  const shared = S(both, (r) => r.static_vs_live.shared > 0);
  const withSdk = S(rows, (r) => !!r.sdk);
  const table = (key) => S(rows, (r) => !!(r.checks && r.checks[key]));
  const feat = (key) => S(rows, (r) => !!(r.features && r.features[key] && r.features[key].tools > 0));
  const cons = (m, adv) => S(L, (r) => !!r.live.consistency[m] && r.live.consistency[m].advertised === adv);
  const agg = {
    format: AGG_FORMAT, generated_at: now, example, min_cell: min,
    disclosure: 'Counts over servers only. A count of 1 to min_cell-1 servers, or one whose complement is that small, is withheld; small categories are merged into "other"; a table over all but a few servers carries rates without counts. No target is named.',
    engine, shards,
    targets: { total: size(rows, min), public_exit: cat(rows, (r) => String(r.public_exit)) },
    acquisition: {
      best_layer: cat(rows, (r) => r.acquired),
      registry_looked_up: c(rows, (r) => r.layers.registry.looked_up), registry_found: c(lookedUp, (r) => r.layers.registry.found), registry_carries_tools: c(inRegistry, (r) => r.layers.registry.tools > 0),
      live_attempted: c(rows, (r) => r.layers.live.attempted), live_ok: c(attempted, (r) => r.layers.live.ok),
      live_ok_by_launch_kind: (() => {
        // Only launch kinds with at least minCell servers get a row; the rest are left out.
        const kinds = categorical(tally(attempted, (r) => r.layers.live.kind), min, attempted.hide);
        return Object.fromEntries(Object.keys(kinds.by || {}).filter((k) => k !== 'other').map((k) => { const R = attempted.filter((r) => r.layers.live.kind === k); return [k, cell(count(R, (r) => r.layers.live.ok), R.length, min, attempted.hide)]; }));
      })(),
      live_failure: cat(failed, (r) => { const p = r.layers.live.with_env || r.layers.live.bare; return p ? p.error || 'unknown' : 'install'; }),
      static_any: c(rows, (r) => !!r.layers.static), static_fidelity: cat(rows, (r) => (r.layers.static ? r.layers.static.fidelity : 'none')), static_kind: cat(rows, (r) => (r.layers.static ? r.layers.static.kind : 'none')),
      readme_any: c(rows, (r) => !!(r.layers.readme && r.layers.readme.tools > 0)),
      static_when_live_ok: c(L, (r) => !!r.layers.static), static_when_live_failed: c(failed, (r) => !!r.layers.static),
    },
    live: {
      n: size(L, min), counts_withheld: !!L.hide,
      transport: cat(L, (r) => r.layers.live.transport), era: cat(L, (r) => r.live.era ?? 'none'), protocol_version: cat(L, (r) => r.live.protocol_version ?? 'none'),
      capabilities: Object.fromEntries(['tools', 'prompts', 'resources', 'logging', 'completions', 'experimental', 'tasks', 'other'].map((k) => [k, c(L, (r) => r.live.capabilities.includes(k))])),
      list_changed: { tools: c(L, (r) => r.live.list_changed.tools), prompts: c(L, (r) => r.live.list_changed.prompts), resources: c(L, (r) => r.live.list_changed.resources) },
      starts_without_env: c(S(L, (r) => r.live.starts_without_env !== null), (r) => r.live.starts_without_env),
      needs_env_to_start: c(S(L, (r) => r.live.starts_with_dummy_env !== null), (r) => r.live.starts_without_env === false && r.live.starts_with_dummy_env === true),
      env_changes_list: c(S(L, (r) => r.live.env_changes_list !== null), (r) => r.live.env_changes_list),
      paginated: c(L, (r) => r.live.paginated), has_prompts: c(L, (r) => r.live.prompts > 0), has_resources: c(L, (r) => r.live.resources > 0), has_resource_templates: c(L, (r) => r.live.resource_templates > 0),
      instructions: c(L, (r) => r.live.instructions_chars > 0), instructions_chars: dist(L.filter((r) => r.live.instructions_chars > 0).map((r) => r.live.instructions_chars), { min, hide: true }),
      server_info: { title: c(L, (r) => r.live.server_info.title), version: c(L, (r) => r.live.server_info.version), icons: c(L, (r) => r.live.server_info.icons) },
      writes_stderr: c(L, (r) => r.live.stderr_bytes > 0), non_json_on_stdout: c(L, (r) => r.live.non_json_lines > 0), sends_notifications: c(L, (r) => r.live.notifications > 0), asks_client: Object.fromEntries(['ping', 'roots/list', 'sampling/createMessage', 'elicitation/create'].map((m) => [m, c(L, (r) => r.live.server_requests.includes(m))])),
      advertised_but_not_answered: Object.fromEntries(['prompts/list', 'resources/list', 'resources/templates/list'].map((m) => [m, c(cons(m, true), (r) => !r.live.consistency[m].answered)])),
      answered_but_not_advertised: Object.fromEntries(['prompts/list', 'resources/list', 'resources/templates/list'].map((m) => [m, c(cons(m, false), (r) => r.live.consistency[m].answered)])),
      startup_ms: d(L, (r) => r.live.startup_ms, MS_EDGES), tools_list_ms: d(L, (r) => (Number.isFinite(r.live.tools_ms) && Number.isFinite(r.live.initialize_ms) ? r.live.tools_ms - r.live.initialize_ms : null)),
      prompts: d(L, (r) => r.live.prompts), resources: d(L, (r) => r.live.resources),
    },
    size: {
      n: size(sized, min), counts_withheld: !!sized.hide, from: cat(sized, (r) => r.size.from),
      tools: d(sized, (r) => r.size.tools, TOOL_EDGES), bytes: d(sized, (r) => r.size.bytes),
      tokens: { bytes_div_4: d(sized, (r) => r.size.tokens.bytes_div_4, TOKEN_EDGES), bpe_approx: d(sized, (r) => r.size.tokens.bpe_approx, TOKEN_EDGES), claude_approx: d(sized, (r) => r.size.tokens.claude_approx, TOKEN_EDGES) },
      bytes_per_tool: d(sized, (r) => (r.size.tools > 0 ? r.size.bytes / r.size.tools : null)),
      bpe_over_bytes_div_4: d(sized, (r) => (r.size.tokens.bytes_div_4 > 0 ? r.size.tokens.bpe_approx / r.size.tokens.bytes_div_4 : null)),
    },
    checks: { live: checksTable(table('live'), 'live', checks, min), static: checksTable(table('static'), 'static', checks, min) },
    grades: { live: gradesTable(table('live'), 'live', min), static: gradesTable(table('static'), 'static', min) },
    engine_errors: { live: categorical(tally(rows, (r) => (r.engine_error ? r.engine_error.live : null)), min), static: categorical(tally(rows, (r) => (r.engine_error ? r.engine_error.static : null)), min) },
    features: { live: featureTable(feat('live'), 'live', min), static: featureTable(feat('static'), 'static', min) },
    sdk: (() => {
      const out = { detected: c(rows, (r) => !!r.sdk), by_sdk: cat(withSdk, (r) => r.sdk.id), by_sdk_minor: cat(withSdk, (r) => (r.sdk.minor ? `${r.sdk.id}@${r.sdk.minor}` : `${r.sdk.id}@unknown`)), version_source: cat(withSdk, (r) => r.sdk.kind), by_language: cat(rows, (r) => r.language ?? 'unknown'), by_ecosystem: cat(withSdk, (r) => r.sdk.ecosystem), per_sdk: {} };
      // Per-SDK tables only for SDKs the breakdown above shows by name (at least minCell servers).
      for (const id of Object.keys(out.by_sdk.by || {}).filter((k) => k !== 'other')) {
        const R = rows.filter((r) => r.sdk && r.sdk.id === id); R.hide = withSdk.hide;
        const RA = S(R, (r) => r.layers.live.attempted);
        const RL = S(R, (r) => !!(r.checks && r.checks.live));
        const RF = S(R, (r) => !!(r.features && r.features.live));
        out.per_sdk[id] = {
          servers: size(R, min), live_ok: c(RA, (r) => r.layers.live.ok),
          tools: dist(R.filter((r) => r.size).map((r) => r.size.tools), { min, hide: true }), tokens_bpe_approx: dist(R.filter((r) => r.size).map((r) => r.size.tokens.bpe_approx), { min, hide: true }),
          startup_ms: dist(R.filter((r) => r.live).map((r) => r.live.startup_ms), { min, hide: true }),
          annotations_any_tool: c(RF, (r) => r.features.live.annotations.any > 0), output_schema_any_tool: c(RF, (r) => r.features.live.output_schema > 0),
          checks_live: Object.fromEntries(checks.map((k) => [k.id, c(RL, (r) => !!r.checks.live[k.id])])),
        };
      }
      return out;
    })(),
    repo: {
      licence: cat(rows, (r) => (r.repo ? r.repo.licence ?? 'none' : 'none')), licence_from: cat(rows, (r) => (r.repo ? r.repo.licence_from ?? 'none' : 'none')),
      stars: dist(rows.map((r) => (r.repo ? r.repo.stars : null)), { min, edges: STAR_EDGES }), commit_age_days: dist(rows.map((r) => (r.repo ? r.repo.commit_age_days : null)), { min, edges: AGE_EDGES }),
      archived: c(S(rows, (r) => !!r.repo && r.repo.archived !== null), (r) => r.repo.archived), pinned: c(rows, (r) => !!(r.repo && r.repo.pinned)), has_server_json: c(rows, (r) => !!(r.repo && r.repo.has_server_json)), has_lockfile: c(rows, (r) => !!(r.repo && r.repo.has_lockfile)),
    },
    env: {
      probe_set_env: c(rows, (r) => !!(r.env && r.env.used > 0)), credential_named: c(rows, (r) => !!(r.env && r.env.secret_named > 0)), source_reads_credential_named: c(rows, (r) => !!(r.env && r.env.source_secret_named > 0)),
      registry_declares_env: c(inRegistry, (r) => !!(r.env && r.env.registry_declared > 0)), env_names_used: dist(rows.filter((r) => r.env && r.env.used > 0).map((r) => r.env.used), { min, hide: true }), source_env_refs: d(rows, (r) => (r.env ? r.env.source : null)),
    },
    static_vs_live: {
      n: size(both, min), enough: both.length >= min, counts_withheld: !!both.hide, fidelity: cat(both, (r) => r.static_vs_live.fidelity),
      same_names: c(both, (r) => r.static_vs_live.name_jaccard === 1), name_jaccard: d(both, (r) => r.static_vs_live.name_jaccard),
      static_misses_tools: c(both, (r) => r.static_vs_live.only_live > 0), static_has_extra_tools: c(both, (r) => r.static_vs_live.only_static > 0),
      description_agreement: d(shared, (r) => r.static_vs_live.agree.description / r.static_vs_live.shared), schema_agreement: d(shared, (r) => r.static_vs_live.agree.inputSchema / r.static_vs_live.shared), param_names_agreement: d(shared, (r) => r.static_vs_live.agree.params / r.static_vs_live.shared), annotations_agreement: d(shared, (r) => r.static_vs_live.agree.annotations / r.static_vs_live.shared),
      readme_name_jaccard: dist(L.filter((r) => r.static_vs_live && r.static_vs_live.readme).map((r) => r.static_vs_live.readme.name_jaccard), { min, hide: true }),
      per_check: Object.fromEntries(checks.map((k) => {
        const n = (s) => count(bothChecks, (r) => r.static_vs_live.checks[k.id] === s);
        const cl = (x) => cell(x, bothChecks.length, min, bothChecks.hide);
        return [k.id, { agree: cl(n('both') + n('neither')), live_only: cl(n('live_only')), static_only: cl(n('static_only')) }];
      })),
    },
    diff: diff ? diffSummary(diff, min) : null,
  };
  agg.calibration = calibration(agg, checks);
  return agg;
}

/** Read off the aggregate (so it can hold nothing the aggregate withholds). */
/** The severity the findings carried when it is known and the same on every server that fired; else the check's default. */
function sevLabel(pc, k) {
  const seen = pc && pc.severity_seen && pc.severity_seen.by ? Object.keys(pc.severity_seen.by).filter((x) => x !== 'other') : [];
  const other = pc && pc.severity_seen && pc.severity_seen.other;
  if (seen.length === 1 && !other) return seen[0];
  if (seen.length) return `${k.severity} by default; seen ${seen.join(', ')}${other ? ' and others' : ''}`;
  return k.severity;
}

export function calibration(agg, checks) {
  const out = { almost_all_threshold: ALMOST_ALL, disagree_threshold: DISAGREE, live: null, static: null, never_fires_anywhere: [], static_vs_live_disagree: [], static_vs_live_withheld: 0 };
  const isZero = (s) => !s.suppressed && s.n === 0 && s.rate !== null;
  for (const key of ['live', 'static']) {
    const T = agg.checks[key];
    if (!T.enough) { out[key] = { n: T.n, enough: false }; continue; }
    const o = { n: T.n, enough: true, fires_on_almost_all: [], never_fires: [], withheld: [], fires: [] };
    for (const k of checks) {
      const s = T.per_check[k.id].servers;
      if (s.suppressed) {
        // A withheld cell that is known to be nearly everything is still "almost all" when its floor passes the threshold.
        const floor = s.bound && s.bound.startsWith('>') ? (Number(s.bound.slice(1)) + 1) / s.of : s.bound === 'nearly all' ? 1 : 0;
        if (floor >= ALMOST_ALL) o.fires_on_almost_all.push({ id: k.id, severity: sevLabel(T.per_check[k.id], k), servers: s.bound });
        else if (s.bound && (s.bound.startsWith('>') || s.bound === 'nearly all')) o.fires.push({ id: k.id, rate: null, servers: s.bound });
        else o.withheld.push(k.id);
      } else if (isZero(s)) o.never_fires.push(k.id);
      else { if (s.rate >= ALMOST_ALL) o.fires_on_almost_all.push({ id: k.id, severity: sevLabel(T.per_check[k.id], k), servers: s.n, rate: s.rate }); o.fires.push({ id: k.id, rate: s.rate }); }
    }
    o.fires.sort((a, b) => (b.rate ?? 2) - (a.rate ?? 2));
    out[key] = o;
  }
  const zero = (key, id) => !agg.checks[key].enough || isZero(agg.checks[key].per_check[id].servers);
  if (agg.checks.live.enough || agg.checks.static.enough) out.never_fires_anywhere = checks.filter((k) => zero('live', k.id) && zero('static', k.id)).map((k) => k.id);
  if (agg.static_vs_live.enough) {
    for (const k of checks) {
      const p = agg.static_vs_live.per_check[k.id];
      if (p.agree.suppressed) { if (p.agree.bound && p.agree.bound.startsWith('<')) out.static_vs_live_disagree.push({ id: k.id, disagree_rate: null, note: `agree on ${p.agree.bound}`, live_only: p.live_only.suppressed ? p.live_only.bound ?? 'withheld' : p.live_only.n ?? p.live_only.rate, static_only: p.static_only.suppressed ? p.static_only.bound ?? 'withheld' : p.static_only.n ?? p.static_only.rate }); else if (!(p.agree.bound && (p.agree.bound.startsWith('>') || p.agree.bound === 'nearly all'))) out.static_vs_live_withheld++; continue; }
      if (p.agree.rate === null) continue;
      if (1 - p.agree.rate >= DISAGREE) out.static_vs_live_disagree.push({ id: k.id, disagree_rate: Math.round((1 - p.agree.rate) * 10000) / 10000, live_only: p.live_only.suppressed ? p.live_only.bound ?? 'withheld' : p.live_only.n ?? p.live_only.rate, static_only: p.static_only.suppressed ? p.static_only.bound ?? 'withheld' : p.static_only.n ?? p.static_only.rate });
    }
    out.static_vs_live_disagree.sort((a, b) => (b.disagree_rate ?? 2) - (a.disagree_rate ?? 2));
  }
  return out;
}

const pct = (r) => `${Math.round(r * 100)}%`;
const show = (c) => (c === null || c === undefined ? 'n/a' : c.suppressed ? (c.bound ? (c.of ? `${c.bound} of ${c.of}` : c.bound) : 'withheld') : c.rate === null ? 'none to count' : c.counts_withheld ? pct(c.rate) : `${c.n} of ${c.of} (${pct(c.rate)})`);
const showDist = (d) => (!d || d.n === 0 ? 'no values' : d.suppressed ? 'withheld' : `median ${d.p50} (quartiles ${d.p25} to ${d.p75}${d.n ? `, ${d.n} servers` : ''})`);
const count1 = (n) => (n === null || n === undefined ? 'withheld' : String(n));
const servers = (n) => (n === null || n === undefined ? 'A withheld number of servers' : `${n} servers`);

/** The calibration report as Markdown, from the aggregate alone. */
export function calibrationMarkdown(agg) {
  const C = agg.calibration;
  const L = [];
  L.push('# Surface corpus: calibration report', '');
  L.push(`Generated ${agg.generated_at}. Rubric ${agg.engine ? agg.engine.rubric_version : '?'}, ${agg.engine ? agg.engine.checks : '?'} checks. ${agg.example ? 'Public example run on named reference servers: nothing is withheld.' : `Counts of fewer than ${agg.min_cell} servers are withheld.`} No server of the corpus is named.`, '');
  L.push('## What was acquired', '');
  L.push(`- Servers: ${count1(agg.targets.total)}`);
  L.push(`- Live list (server started in the sandbox), of those with a launch recipe: ${show(agg.acquisition.live_ok)}`);
  L.push(`- Static list (read from source): ${show(agg.acquisition.static_any)}`);
  L.push(`- README names: ${show(agg.acquisition.readme_any)}`);
  L.push(`- In the MCP Registry, of those looked up: ${show(agg.acquisition.registry_found)}`);
  L.push(`- Starts with no environment set: ${show(agg.live.starts_without_env)}`);
  L.push(`- Tools per server: ${showDist(agg.size.tools)}`);
  L.push(`- Estimated tokens of the list (bytes/4): ${showDist(agg.size.tokens.bytes_div_4)}`, '');
  for (const key of ['live', 'static']) {
    const o = C[key];
    L.push(`## Checks on ${key} lists`, '');
    if (!o || !o.enough) { L.push('Too few servers with such a list to report.', ''); continue; }
    L.push(`${servers(o.n)}.`, '', `### Fire on almost every server (at least ${pct(C.almost_all_threshold)})`, '');
    if (!o.fires_on_almost_all.length) L.push('None.'); else for (const x of o.fires_on_almost_all) L.push(`- \`${x.id}\` (${x.severity}): ${x.rate !== undefined ? pct(x.rate) : x.servers}`);
    L.push('', '### Never fire', '');
    L.push(o.never_fires.length ? o.never_fires.map((x) => `\`${x}\``).join(', ') : 'None.');
    // With no cell rule (the public example) nothing is withheld, so the section would only say so.
    if (agg.min_cell > 1) {
      L.push('', `### Fire on fewer than ${agg.min_cell} servers (count withheld)`, '');
      L.push(o.withheld.length ? o.withheld.map((x) => `\`${x}\``).join(', ') : 'None.');
    }
    L.push('', '### Prevalence', '', '| Check | Servers |', '|---|---|');
    for (const x of o.fires) L.push(`| \`${x.id}\` | ${x.rate === null ? x.servers : pct(x.rate)} |`);
    L.push('');
  }
  L.push('## Checks that fire on no list at all', '', C.never_fires_anywhere.length ? C.never_fires_anywhere.map((x) => `\`${x}\``).join(', ') : 'None.', '');
  L.push('## Static against live', '');
  const S = agg.static_vs_live;
  if (!S.enough) L.push('Too few servers had both a static and a live list to report.', '');
  else {
    L.push(`${servers(S.n)} had both lists. Same tool names: ${show(S.same_names)}. Static misses tools: ${show(S.static_misses_tools)}. Static has tools the server does not list: ${show(S.static_has_extra_tools)}.`, '');
    L.push(`Share of shared tools whose description is identical: ${showDist(S.description_agreement)}; input schema identical: ${showDist(S.schema_agreement)}; parameter names identical: ${showDist(S.param_names_agreement)}.`, '');
    L.push(`### Checks whose static and live results disagree on at least ${pct(C.disagree_threshold)} of servers`, '');
    if (!C.static_vs_live_disagree.length) L.push('None.'); else { L.push('| Check | Disagree | Live only | Static only |', '|---|---|---|---|'); for (const x of C.static_vs_live_disagree) L.push(`| \`${x.id}\` | ${x.disagree_rate === null ? x.note : pct(x.disagree_rate)} | ${x.live_only} | ${x.static_only} |`); }
    if (C.static_vs_live_withheld) L.push('', `${C.static_vs_live_withheld} checks have a withheld cell here.`);
    L.push('');
  }
  if (agg.diff) {
    L.push('## Against the previous run', '', `Compared: ${count1(agg.diff.compared)}. Any change: ${show(agg.diff.any_change)}. Tool list changed: ${show(agg.diff.list_changed)} (with no new commit or version: ${show(agg.diff.list_changed_without_commit_change)}). A check started or stopped firing: ${show(agg.diff.checks_changed)}. A grade changed: ${show(agg.diff.grade_changed)}.`, '');
  }
  return `${L.join('\n')}\n`;
}

/** The private companion: exact counts and target ids, for the encrypted bundle only. */
export function privateCalibration(rows, checks) {
  const out = { per_check: {}, static_vs_live: {}, live_failed: rows.filter((r) => r.layers.live.attempted && !r.layers.live.ok).map((r) => r.id), no_list: rows.filter((r) => r.acquired === 'none').map((r) => r.id) };
  for (const k of checks) {
    out.per_check[k.id] = { live: rows.filter((r) => r.checks && r.checks.live && r.checks.live[k.id]).map((r) => r.id), static: rows.filter((r) => r.checks && r.checks.static && r.checks.static[k.id]).map((r) => r.id) };
    const R = rows.filter((r) => r.static_vs_live && r.static_vs_live.checks);
    out.static_vs_live[k.id] = { live_only: R.filter((r) => r.static_vs_live.checks[k.id] === 'live_only').map((r) => r.id), static_only: R.filter((r) => r.static_vs_live.checks[k.id] === 'static_only').map((r) => r.id) };
  }
  return out;
}
