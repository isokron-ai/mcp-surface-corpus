// Surface features of a tools/list (plus prompts and resources) for calibration. Pure functions over data.
const HINTS = ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'];
const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);

function quantiles(arr) {
  if (!arr.length) return null;
  const s = [...arr].sort((a, b) => a - b);
  const q = (p) => s[Math.min(s.length - 1, Math.floor(p * (s.length - 1) + 0.5))];
  return { min: s[0], p25: q(0.25), p50: q(0.5), p75: q(0.75), max: s[s.length - 1], mean: Math.round((s.reduce((a, b) => a + b, 0) / s.length) * 100) / 100 };
}

function schemaDepth(x, d = 0) {
  if (d > 64) return d;
  if (Array.isArray(x)) return Math.max(d, ...x.map((v) => schemaDepth(v, d + 1)));
  if (isObj(x)) return Math.max(d, ...Object.values(x).map((v) => schemaDepth(v, d + 1)));
  return d;
}

export function toolFeatures(tools) {
  const T = (tools || []).filter(isObj);
  const n = T.length;
  const ann = T.map((t) => (isObj(t.annotations) ? t.annotations : null));
  const descLens = T.map((t) => (typeof t.description === 'string' ? t.description.length : 0));
  const props = T.map((t) => (isObj(t.inputSchema) && isObj(t.inputSchema.properties) ? Object.keys(t.inputSchema.properties).length : 0));
  const req = T.map((t) => (isObj(t.inputSchema) && Array.isArray(t.inputSchema.required) ? t.inputSchema.required.length : 0));
  const paramDesc = T.reduce((acc, t) => {
    const p = isObj(t.inputSchema) && isObj(t.inputSchema.properties) ? Object.values(t.inputSchema.properties) : [];
    acc.total += p.length; acc.with += p.filter((x) => isObj(x) && typeof x.description === 'string' && x.description.trim()).length;
    return acc;
  }, { total: 0, with: 0 });
  const count = (f) => T.filter(f).length;
  const hintCov = {};
  for (const h of HINTS) hintCov[h] = { set: ann.filter((a) => a && typeof a[h] === 'boolean').length, true: ann.filter((a) => a && a[h] === true).length };
  const names = T.map((t) => String(t.name || ''));
  const style = (s) => (/^[a-z0-9]+(_[a-z0-9]+)+$/.test(s) ? 'snake' : /^[a-z]+([A-Z][a-z0-9]*)+$/.test(s) ? 'camel' : /^[a-z0-9]+(-[a-z0-9]+)+$/.test(s) ? 'kebab' : /\./.test(s) ? 'dotted' : /^[a-z0-9]+$/.test(s) ? 'single' : 'other');
  const styles = {};
  names.forEach((s) => { const k = style(s); styles[k] = (styles[k] || 0) + 1; });
  return {
    tools: n,
    annotations: { any: count((t) => isObj(t.annotations) && Object.keys(t.annotations).length > 0), all_four_hints: ann.filter((a) => a && HINTS.every((h) => typeof a[h] === 'boolean')).length, title_in_annotations: ann.filter((a) => a && typeof a.title === 'string').length, hints: hintCov, unknown_keys: ann.reduce((s, a) => s + (a ? Object.keys(a).filter((k) => !HINTS.includes(k) && k !== 'title').length : 0), 0) },
    title: count((t) => typeof t.title === 'string' && t.title.trim()),
    description: { missing: count((t) => typeof t.description !== 'string' || !t.description.trim()), length: quantiles(descLens) },
    input_schema: { missing: count((t) => !isObj(t.inputSchema)), properties: quantiles(props), required: quantiles(req), param_descriptions: paramDesc, additional_properties_false: count((t) => isObj(t.inputSchema) && t.inputSchema.additionalProperties === false), declares_schema_dialect: count((t) => isObj(t.inputSchema) && typeof t.inputSchema.$schema === 'string'), max_depth: Math.max(0, ...T.map((t) => schemaDepth(t.inputSchema))) },
    output_schema: count((t) => isObj(t.outputSchema)),
    meta: count((t) => isObj(t._meta)),
    icons: count((t) => Array.isArray(t.icons) && t.icons.length > 0),
    execution: count((t) => isObj(t.execution)),
    name_styles: styles,
    name_length: quantiles(names.map((s) => s.length)),
  };
}

export function listFeatures(probe) {
  const L = (probe && probe.lists) || {};
  const f = {};
  for (const [m, x] of Object.entries(L)) f[m] = { ok: !!x.ok, items: Array.isArray(x.items) ? x.items.length : null, pages: x.pages, paginated: x.pages > 1, error_code: x.error_code ?? null, ms: x.ms };
  const caps = probe && probe.initialize && isObj(probe.initialize.capabilities) ? probe.initialize.capabilities : {};
  // Capability advertised vs list answered: calibration data for the spec checks.
  const consistency = {};
  for (const [m, cap] of [['tools/list', 'tools'], ['prompts/list', 'prompts'], ['resources/list', 'resources'], ['resources/templates/list', 'resources']]) {
    consistency[m] = { advertised: cap in caps, answered: !!(L[m] && L[m].ok) };
  }
  return { lists: f, capabilities: Object.keys(caps).sort(), list_changed: { tools: !!(isObj(caps.tools) && caps.tools.listChanged), prompts: !!(isObj(caps.prompts) && caps.prompts.listChanged), resources: !!(isObj(caps.resources) && caps.resources.listChanged) }, consistency };
}

export { quantiles };
