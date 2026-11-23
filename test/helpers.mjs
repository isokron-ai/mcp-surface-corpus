// Test helpers: an in-memory tar.gz writer (ustar, with the pax global header git archive writes),
// a fake fetch for the driver's host-side requests, and synthetic rows.
import { gzipSync } from 'node:zlib';

function header(name, size, type = '0') {
  const h = Buffer.alloc(512);
  h.write(name, 0, 100, 'utf8');
  h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
  h.write(size.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write(type, 156);
  h.write('ustar\0', 257); h.write('00', 263);
  let sum = 0; for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  return h;
}
const pad = (b) => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);

/** files: { 'path/in/repo': 'text' }. Paths get the `root/` prefix GitHub archives have. */
export function tarGz(files, { root = 'repo-abc', commit = 'a'.repeat(40) } = {}) {
  const parts = [];
  const pax = Buffer.from(`52 comment=${commit}\n`);
  parts.push(header('pax_global_header', pax.length, 'g'), pad(pax));
  for (const [p, text] of Object.entries(files)) {
    const data = Buffer.from(text);
    parts.push(header(`${root}/${p}`, data.length), pad(data));
  }
  parts.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(parts));
}

/** A fetch that answers the driver's host-side requests from memory and records what was asked. */
export function fakeFetch({ archives = {}, repo = {}, registry = { servers: [] }, commitDate = '2026-11-01T00:00:00Z' } = {}) {
  const calls = [];
  const fn = async (url, init = {}) => {
    const u = String(url);
    calls.push({ url: u, auth: !!(init.headers && init.headers.authorization) });
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'content-type': 'application/json' } });
    let m;
    if ((m = /^https:\/\/api\.github\.com\/repos\/([^/]+\/[^/]+)\/commits\/(.+)$/.exec(u))) return json({ sha: /^[0-9a-f]{40}$/.test(m[2]) ? m[2] : 'b'.repeat(40), commit: { committer: { date: commitDate }, author: { date: commitDate }, verification: { verified: false } } });
    if (/^https:\/\/api\.github\.com\/repos\/[^/]+\/[^/]+$/.test(u)) return json({ stargazers_count: 1234, forks_count: 56, open_issues_count: 7, license: { spdx_id: 'MIT' }, archived: false, fork: false, pushed_at: commitDate, created_at: '2025-01-01T00:00:00Z', default_branch: 'main', size: 100, topics: ['mcp'], language: 'TypeScript', ...repo });
    if ((m = /^https:\/\/codeload\.github\.com\/[^/]+\/[^/]+\/tar\.gz\/([0-9a-f]{40})$/.exec(u))) { const b = archives[m[1]] ?? archives['*']; return b ? new Response(b, { status: 200 }) : new Response('not found', { status: 404 }); }
    if (u.startsWith('https://registry.modelcontextprotocol.io/')) return json(registry);
    return new Response('unexpected', { status: 500 });
  };
  fn.calls = calls;
  return fn;
}

const HINT = (set, t) => ({ set, true: t });
/** A synthetic row. `o` overrides: fired (check ids), sdk, live (false for a server that did not start), tools, staticChecks. */
export function row(i, o = {}) {
  const id = `s${String(i).padStart(3, '0')}`;
  const tools = o.tools ?? 10;
  const feats = { tools, annotations: { any: o.annotated ?? tools, all_four_hints: 0, title_in_annotations: 0, unknown_keys: 0, hints: { readOnlyHint: HINT(tools, 1), destructiveHint: HINT(0, 0), idempotentHint: HINT(0, 0), openWorldHint: HINT(0, 0) } }, title: 0, description: { missing: 0, length: { p50: 40 } }, input_schema: { missing: 0, properties: { p50: 2 }, required: { p50: 1 }, param_descriptions: { total: 20, with: 10 }, additional_properties_false: 0, declares_schema_dialect: 0, max_depth: 3 }, output_schema: o.outputSchema ?? 0, meta: 0, icons: 0, execution: 0, name_styles: { snake: tools }, name_length: { p50: 12 } };
  const live = o.live !== false;
  const fired = Object.fromEntries((o.fired ?? []).map((c) => [c, [1, 1]]));
  const sfired = Object.fromEntries((o.staticFired ?? o.fired ?? []).map((c) => [c, [1, 1]]));
  const grades = Object.fromEntries(['spec', 'anthropic', 'openai', 'security', 'quality', 'surface'].map((s) => [s, { grade: 'A', score: 95, ready: true }]));
  const hasStatic = o.static !== false;
  return {
    format: 'isokron-surface-row/1', id, public_exit: 0, acquired: live ? 'live' : hasStatic ? 'static' : 'none',
    layers: { registry: { looked_up: false }, live: { attempted: true, kind: o.kind ?? 'npm', transport: 'stdio', ok: live, bare: { ok: live, era: 'legacy', error: live ? null : 'transport', tools: live ? tools : null, exit: 0 }, with_env: null, primary: live ? 'bare' : null }, static: hasStatic ? { kind: 'source', fidelity: 'derived', tools, candidates: 1 } : null, readme: null },
    live: live ? { era: 'legacy', protocol_version: '2025-11-25', capabilities: ['tools'], list_changed: { tools: false, prompts: false, resources: false }, starts_without_env: true, starts_with_dummy_env: null, env_changes_list: null, initialize_ms: 900, tools_ms: 910, total_ms: 920, baseline_ms: 600, startup_ms: 300 + i, pages: 1, paginated: false, prompts: 0, resources: 0, resource_templates: 0, consistency: { 'tools/list': { advertised: true, answered: true } }, instructions_chars: 0, server_info: { has: true, title: false, version: true, icons: false }, stderr_bytes: 0, non_json_lines: 0, notifications: 0, server_requests: [] } : null,
    env: { list: 0, registry_declared: 0, registry_required: 0, registry_secret: 0, readme: 0, source: 0, used: 0, secret_named: 0, source_secret_named: 0 },
    size: { from: live ? 'live' : 'static', tools, bytes: tools * 1000, tokens: { bytes_div_4: tools * 250, bpe_approx: tools * 300, claude_approx: tools * 303 } },
    sdk: o.sdk === null ? null : { id: o.sdk ?? 'typescript-sdk', ecosystem: 'npm', version: '1.2.3', minor: '1.2', kind: 'installed', source: 'package-lock.json', declared: true },
    language: 'typescript',
    checks: { ...(live ? { live: fired } : {}), ...(hasStatic ? { static: sfired } : {}) },
    grades: { ...(live ? { live: grades } : {}), ...(hasStatic ? { static: grades } : {}) },
    engine_error: {}, features: { ...(live ? { live: feats } : {}), ...(hasStatic ? { static: feats } : {}) },
    static_vs_live: live && hasStatic ? { kind: 'source', fidelity: 'derived', static_tools: tools, live_tools: tools, shared: tools, only_live: 0, only_static: 0, name_jaccard: 1, agree: { description: tools, inputSchema: 0, params: tools, annotations: tools, whole: 0 }, param_jaccard_mean: 1, checks: o.svl ?? {}, readme: null } : null,
    repo: { pinned: true, stars: 10 * i, forks: 1, archived: false, fork: false, licence: 'MIT', licence_from: 'github', commit_age_days: i, pushed_age_days: i, has_server_json: false, has_lockfile: true },
    timing: { total_ms: 1000 },
  };
}

/**
 * The host as install-runsc.sh and net-guard.sh leave it, for the strict preflight: `iptables -S` /
 * `ip6tables -S` of our chains and jumps (as iptables prints them) and `runsc --version`. `drop`
 * removes rules: { 'iptables INPUT': [rule, ...] } or a whole chain with true. `top` puts rules first:
 * { 'iptables DOCKER-USER': [rule, ...] }.
 */
export function fakeHostRun(cfg, { drop = {}, top = {}, version = null } = {}) {
  const v4 = {
    'ISK-SBX': ['-A ISK-SBX -s 10.213.53.0/24 -d 10.213.53.0/24 -j RETURN', '-A ISK-SBX -s 10.213.54.0/24 -d 10.213.54.0/24 -j RETURN', '-A ISK-SBX -m limit --limit 20/sec --limit-burst 200 -j LOG --log-prefix "isk-sbx-fwd: " --log-level 4', '-A ISK-SBX -j DROP'],
    'ISK-SBX-IN': ['-A ISK-SBX-IN -m limit --limit 20/sec --limit-burst 200 -j LOG --log-prefix "isk-sbx-in: "', '-A ISK-SBX-IN -j DROP'],
    'DOCKER-USER': ['-A DOCKER-USER -d 168.63.129.16/32 -j DROP', '-A DOCKER-USER -d 169.254.0.0/16 -j DROP', '-A DOCKER-USER -d 10.213.52.0/22 -j ISK-SBX', '-A DOCKER-USER -s 10.213.52.0/22 -j ISK-SBX', '-A DOCKER-USER -j RETURN'],
    INPUT: ['-A INPUT -i br-+ -j ISK-SBX-IN', '-A INPUT -i docker0 -j ISK-SBX-IN'],
    FORWARD: ['-A FORWARD -j DOCKER-USER', '-A FORWARD -j DOCKER-FORWARD'],
  };
  const v6 = {
    'ISK-SBX6': ['-A ISK-SBX6 -m limit --limit 20/sec --limit-burst 200 -j LOG --log-prefix "isk-sbx-fwd6: " --log-level 4', '-A ISK-SBX6 -j DROP'],
    'ISK-SBX6-IN': ['-A ISK-SBX6-IN -m limit --limit 20/sec --limit-burst 200 -j LOG --log-prefix "isk-sbx-in6: " --log-level 4', '-A ISK-SBX6-IN -j DROP'],
    INPUT: ['-A INPUT -i br-+ -j ISK-SBX6-IN', '-A INPUT -i docker0 -j ISK-SBX6-IN'],
    FORWARD: ['-A FORWARD -o br-+ -j ISK-SBX6', '-A FORWARD -i br-+ -j ISK-SBX6', '-A FORWARD -o docker0 -j ISK-SBX6', '-A FORWARD -i docker0 -j ISK-SBX6'],
  };
  return (cmd, argv) => {
    if (String(cmd).endsWith('/runsc')) return { status: 0, stdout: `runsc version ${version ?? `release-${cfg.release}`}\nspec: 1.1.0\n` };
    const [tool, a] = cmd === 'sudo' ? [argv[1], argv.slice(2)] : [cmd, argv];
    const t = tool === 'iptables' ? v4 : tool === 'ip6tables' ? v6 : null;
    if (!t || a[0] !== '-S' || !t[a[1]]) return { status: 1, stdout: '' };
    const gone = drop[`${tool} ${a[1]}`];
    if (gone === true) return { status: 1, stdout: '' };
    return { status: 0, stdout: [`-N ${a[1]}`, ...(top[`${tool} ${a[1]}`] || []), ...t[a[1]].filter((l) => !(gone || []).includes(l))].join('\n') };
  };
}
