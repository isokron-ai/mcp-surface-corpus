import test from 'node:test';
import assert from 'node:assert/strict';
import { analyseArchive } from '../sandbox/static.mjs';
import { readTar } from '../src/tar.mjs';
import { extractGo } from '../src/go-extract.mjs';
import { extractReadme, documentedCommands } from '../src/readme-extract.mjs';
import { envRefsFromSource, envRefsFromReadme, dummyValue, isSecretName } from '../src/env-refs.mjs';
import { tarGz } from './helpers.mjs';

const TS = `import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
const server = new McpServer({ name: "demo", version: "1.0.0" });
server.registerTool("list_items", { title: "List items", description: "Lists the items of a project.", inputSchema: { project: z.string().describe("Project id") }, annotations: { readOnlyHint: true } }, async () => ({ content: [] }));
server.tool("delete_item", "Deletes one item.", { id: z.string() }, async () => ({ content: [] }));
const key = process.env.DEMO_API_KEY;
`;
const PY = `from mcp.server.fastmcp import FastMCP
import os
mcp = FastMCP("demo")
TOKEN = os.environ["DEMO_TOKEN"]

@mcp.tool()
def get_weather(city: str, days: int = 3) -> str:
    """Returns the forecast for a city."""
    return ""
`;
const GO = `package main
import "github.com/mark3labs/mcp-go/mcp"
func tools() {
	t := mcp.NewTool("search_issues",
		mcp.WithDescription("Searches issues " + "by text."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithString("query", mcp.Required(), mcp.Description("The search text")),
		mcp.WithNumber("limit", mcp.DefaultNumber(20)),
		mcp.WithString("state", mcp.Enum("open", "closed")),
	)
	_ = t
	_ = os.Getenv("ISSUES_TOKEN")
}
`;
const README = `# Demo server

## Usage

\`\`\`json
{ "mcpServers": { "demo": { "command": "npx", "args": ["-y", "demo-mcp"], "env": { "DEMO_API_KEY": "<key>" } } } }
\`\`\`

Run it with \`npx -y demo-mcp\` or \`uvx demo-mcp\`.

## Tools

- \`list_items\` - Lists the items of a project
- **delete_item**: Deletes one item

## License

MIT
`;
const LOCK = JSON.stringify({ name: 'demo', lockfileVersion: 3, packages: { '': { name: 'demo' }, 'node_modules/@modelcontextprotocol/sdk': { version: '1.21.0' } } });

test('tar reader: files, the pinned commit from the pax header, nothing unpacked to disk', () => {
  const buf = tarGz({ 'a.txt': 'hello', 'dir/b.txt': 'world' }, { commit: 'c'.repeat(40) });
  const { entries, global } = readTar(buf, { want: () => true });
  assert.deepEqual(entries.map((e) => e.path), ['repo-abc/a.txt', 'repo-abc/dir/b.txt']);
  assert.equal(entries[1].data.toString(), 'world');
  assert.equal(global.comment, 'c'.repeat(40));
});

test('static reader: TypeScript registrations, SDK from the lock file, env names, licence, README tools', () => {
  const out = analyseArchive(tarGz({ 'src/index.ts': TS, 'package.json': JSON.stringify({ name: 'demo-mcp', version: '1.0.0', dependencies: { '@modelcontextprotocol/sdk': '^1.21.0' } }), 'package-lock.json': LOCK, 'README.md': README, LICENSE: 'MIT License\n\nPermission is hereby granted, free of charge' }));
  assert.equal(out.format, 'isokron-surface-static/1');
  assert.equal(out.archive.commit, 'a'.repeat(40));
  assert.equal(out.primary_language, 'typescript');
  assert.deepEqual(out.static.candidates[0].tools.map((t) => t.name).sort(), ['delete_item', 'list_items']);
  assert.equal(out.static.best.kind, 'source');
  assert.ok(['literal', 'derived'].includes(out.static.best.fidelity));
  const locked = out.sdk.hits.find((h) => h.kind === 'locked');
  assert.deepEqual([locked.sdk, locked.version], ['typescript-sdk', '1.21.0']);
  assert.deepEqual(out.env_refs.source, ['DEMO_API_KEY']);
  assert.deepEqual(out.env_refs.readme, ['DEMO_API_KEY']);
  assert.equal(out.license_files[0].spdx_guess, 'MIT');
  assert.deepEqual(out.readme.tools.map((t) => t.tool.name), ['list_items', 'delete_item']);
  assert.ok(out.documented_commands.includes('npx -y demo-mcp'));
});

test('static reader: a server in a subfolder still gets the root lock file and the root licence', () => {
  const out = analyseArchive(tarGz({ 'servers/demo/src/index.ts': TS, 'servers/demo/package.json': JSON.stringify({ name: 'demo-mcp', dependencies: { '@modelcontextprotocol/sdk': '^1.21.0' } }), 'servers/other/src/index.ts': TS.replace('list_items', 'other_tool'), 'package-lock.json': LOCK, LICENSE: 'Apache License, Version 2.0' }), { subdir: 'servers/demo' });
  assert.equal(out.archive.subdir_found, true);
  assert.ok(!out.static.candidates[0].tools.some((t) => t.name === 'other_tool'), 'tools of a sibling server are not read');
  assert.ok(out.sdk.hits.some((h) => h.kind === 'locked' && h.version === '1.21.0'));
  assert.deepEqual([out.license_files[0].from, out.license_files[0].spdx_guess], ['root', 'Apache-2.0']);
  assert.equal(analyseArchive(tarGz({ 'a.ts': TS }), { subdir: 'missing' }).archive.subdir_found, false);
});

test('static reader: Python FastMCP and Go mcp-go', () => {
  const py = analyseArchive(tarGz({ 'server.py': PY, 'pyproject.toml': '[project]\nname = "demo"\nversion = "0.1.0"\ndependencies = ["mcp>=1.2"]\n', 'uv.lock': '[[package]]\nname = "mcp"\nversion = "1.9.4"\n' }));
  assert.deepEqual(py.static.candidates[0].tools.map((t) => t.name), ['get_weather']);
  assert.deepEqual(py.static.candidates[0].tools[0].inputSchema.required, ['city']);
  assert.ok(py.sdk.hits.some((h) => h.sdk === 'python-sdk' && h.version === '1.9.4'));
  assert.deepEqual(py.env_refs.source, ['DEMO_TOKEN']);
  const go = analyseArchive(tarGz({ 'main.go': GO, 'go.mod': 'module example.com/demo\n\nrequire github.com/mark3labs/mcp-go v0.32.0\n' }));
  assert.equal(go.static.best.kind, 'source-go');
  assert.ok(go.sdk.hits.some((h) => h.sdk === 'mcp-go' && h.version === '0.32.0'));
  assert.deepEqual(go.env_refs.source, ['ISSUES_TOKEN']);
});

test('Go extraction: name, concatenated description, parameter types, required, enum, default, annotations', () => {
  const [t] = extractGo(GO);
  assert.equal(t.tool.name, 'search_issues');
  assert.equal(t.tool.description, 'Searches issues by text.');
  assert.deepEqual(t.tool.inputSchema.required, ['query']);
  assert.deepEqual(t.tool.inputSchema.properties.state.enum, ['open', 'closed']);
  assert.equal(t.tool.inputSchema.properties.limit.default, 20);
  assert.deepEqual(t.tool.annotations, { readOnlyHint: true });
  assert.equal(extractGo('&mcp.Tool{Name: "ping", Description: "Pings."}')[0].tool.name, 'ping');
});

test('README extraction ignores code fences and sections that are not about tools', () => {
  const md = '# X\n\n## Install\n\n- `npm` - a package manager\n\n## Available tools\n\n| Tool | What |\n|---|---|\n| `get_user` | Gets a user |\n\n```\n- `not_a_tool` - in a fence\n```\n\n## Contributing\n\n- `make_pr` - not a tool\n';
  assert.deepEqual(extractReadme(md).map((x) => x.tool.name), ['get_user']);
  assert.deepEqual(documentedCommands('run `uvx demo-mcp==1.2` or docker run -i --rm mcp/demo'), ['uvx demo-mcp==1.2', 'docker run -i --rm mcp/demo']);
});

test('env names: read from source and README, never values; dummy values are shaped and never credentials', () => {
  assert.deepEqual([...envRefsFromSource('os.getenv("A_KEY"); process.env["B_URL"]; os.Getenv("C_TOKEN"); process.env.NODE_ENV')].sort(), ['A_KEY', 'B_URL', 'C_TOKEN']);
  assert.deepEqual([...envRefsFromReadme('export GITHUB_PAT=ghp_xxx\ndocker run -e SLACK_TOKEN img')].sort(), ['GITHUB_PAT', 'SLACK_TOKEN']);
  assert.equal(dummyValue('API_BASE_URL'), 'http://127.0.0.1:9/');
  assert.equal(dummyValue('GITHUB_TOKEN'), 'surface-dummy-not-a-credential');
  assert.ok(isSecretName('GITHUB_TOKEN') && isSecretName('OPENAI_API_KEY') && !isSecretName('LOG_DIR'));
});

test('static reader: the pinned SDK decides the listed form, and a tool declaration nothing registers is left out and counted', () => {
  const lock = JSON.stringify({ name: 'demo', lockfileVersion: 3, packages: { '': { name: 'demo' }, 'node_modules/@modelcontextprotocol/sdk': { version: '1.32.2' }, 'node_modules/zod': { version: '3.25.0' } } });
  const out = analyseArchive(tarGz({ 'src/index.ts': TS, 'src/dead.ts': 'export const dead = { name: "dead_tool", description: "Never registered anywhere.", inputSchema: { type: "object", properties: { a: { type: "string" } } } };\n', 'package.json': JSON.stringify({ name: 'demo-mcp', version: '1.0.0', dependencies: { '@modelcontextprotocol/sdk': '^1.32.0', zod: '^3.25.0' } }), 'package-lock.json': lock }));
  const names = out.static.candidates[0].tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['delete_item', 'list_items']);
  assert.deepEqual(out.static.left_out, { tools: 1, reasons: ['unreferenced-declaration'] });
  const t = out.static.candidates[0].tools.find((x) => x.name === 'list_items');
  assert.equal(t.inputSchema.additionalProperties, false, 'SDK 1.x with zod 3 closes objects');
  assert.deepEqual(t.execution, { taskSupport: 'forbidden' }, 'SDK 1.24+ adds execution');
  assert.ok(out.static.sdk_read && out.static.sdk_read.kind === 'v1');
});

test('R-SBX-55 --reader: the caller\'s reader gets every regular file of the archive (not only what our reading keeps), bytes below READER_FILE_MAX, and the subject; its answer is returned as it is', async () => {
  const { readerLayer, READER_FILE_MAX } = await import('../sandbox/static.mjs');
  const { mkdtempSync, writeFileSync } = await import('node:fs');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const { spawnSync } = await import('node:child_process');
  const d = mkdtempSync(join(tmpdir(), 'surface-reader-'));
  const stub = join(d, 'static-read.cjs');
  writeFileSync(stub, 'module.exports = { readFiles: async (files, o) => ({ format: "stub/1", reader_id: "r", got: files.map((f) => [f.path, f.size, f.data ? f.data.length : null]), o }) };\n');
  const big = 'x'.repeat(READER_FILE_MAX);
  const buf = tarGz({ 'packages/server/src/index.ts': TS, 'docs/guide.md': '# Guide\n', 'data/huge.json': big, 'README.md': '# demo\n' });
  const r = await readerLayer(buf, { reader: stub, repo: 'o/n', sha: 'a'.repeat(40), subdir: 'packages/server' });
  assert.equal(r.format, 'stub/1');
  assert.deepEqual(r.o, { repo: 'o/n', sha: 'a'.repeat(40), subdir: 'packages/server' });
  assert.deepEqual(r.got.sort(), [['README.md', 7, 7], ['data/huge.json', READER_FILE_MAX, null], ['docs/guide.md', 8, 8], ['packages/server/src/index.ts', Buffer.byteLength(TS), Buffer.byteLength(TS)]].sort(), 'files our own reading never keeps are handed over too, with their sizes');
  assert.deepEqual(await readerLayer(buf, { reader: join(d, 'missing.cjs'), repo: 'o/n', sha: 'a'.repeat(40) }), { error: 'reader_missing' });
  const bad = join(d, 'throws.cjs'); writeFileSync(bad, 'module.exports = { readFiles: async () => { throw new Error("boom"); } };\n');
  assert.equal((await readerLayer(buf, { reader: bad, repo: 'o/n', sha: 'a'.repeat(40) })).error, 'reader_threw');
  // through the command line: `reader` next to an unchanged `static`
  const cli = (extra) => JSON.parse(spawnSync(process.execPath, [new URL('../sandbox/static.mjs', import.meta.url).pathname, ...extra], { input: buf, maxBuffer: 64 * 1024 * 1024 }).stdout.toString());
  const plain = cli([]); const withReader = cli(['--reader', stub, '--repo', 'o/n', '--sha', 'a'.repeat(40)]);
  assert.equal(plain.reader, undefined);
  assert.equal(withReader.reader.format, 'stub/1');
  delete withReader.reader;
  assert.deepEqual(withReader, plain, 'our own reading is the same with or without a caller\'s reader');
});

test('R-SBX-55 engine/VENDORED.json names the mcp-check commit the vendored engine was copied from, and the files match it', async () => {
  const { readFileSync } = await import('node:fs');
  const { createHash } = await import('node:crypto');
  const root = new URL('..', import.meta.url);
  const m = JSON.parse(readFileSync(new URL('engine/VENDORED.json', root), 'utf8'));
  assert.match(m.commit, /^[0-9a-f]{40}$/, 'a vendored copy says which commit it is');
  for (const f of m.files) assert.equal(createHash('sha256').update(readFileSync(new URL(f.path, root))).digest('hex'), f.sha256, f.path);
});
