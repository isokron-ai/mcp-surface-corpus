#!/usr/bin/env node
/**
 * A minimal MCP server over stdio, ours. Two uses: the driver probes it once per shard in the same
 * sandbox to measure what `docker run` itself costs (the baseline taken off every target's start-up
 * time), and the tests use it as a server whose behaviour is known.
 *
 *   node null-server.mjs [--tools N] [--page N] [--need-env NAME] [--http PORT] [--modern] [--noise]
 *
 * --need-env NAME   exits 1 unless NAME is set (a server that needs a credential to start)
 * --page N          tools/list in pages of N
 * --modern          refuses initialize; answers lists that carry the protocol version in _meta
 * --noise           prints a non-JSON banner line on stdout first
 * --http PORT       streamable HTTP on PORT at /mcp instead of stdio
 */
import { createServer } from 'node:http';

const arg = (n, d = null) => { const i = process.argv.indexOf(n); return i < 0 ? d : process.argv[i + 1] ?? d; };
const has = (n) => process.argv.includes(n);
const N = Number(arg('--tools', '2'));
const PAGE = Number(arg('--page', '0'));
const need = arg('--need-env');
if (need && !process.env[need]) { process.stderr.write(`${need} is required\n`); process.exit(1); }

const tools = Array.from({ length: N }, (_, i) => ({
  name: `tool_${i + 1}`, title: `Tool ${i + 1}`, description: `Reads item ${i + 1}. Use it to look one item up by id.`,
  inputSchema: { type: 'object', properties: { id: { type: 'string', description: 'The item id.' } }, required: ['id'], additionalProperties: false },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}));

export function answer(m) {
  if (!m || typeof m !== 'object' || typeof m.method !== 'string') return null;
  if (m.id === undefined) return null;
  const ok = (result) => ({ jsonrpc: '2.0', id: m.id, result });
  const err = (code, message) => ({ jsonrpc: '2.0', id: m.id, error: { code, message } });
  if (m.method === 'initialize') {
    if (has('--modern')) return err(-32601, 'Method not found');
    return ok({ protocolVersion: (m.params && m.params.protocolVersion) || '2025-11-25', capabilities: { tools: { listChanged: false }, prompts: {} }, serverInfo: { name: 'null-server', version: '1.0.0' } });
  }
  if (m.method === 'ping') return ok({});
  if (m.method === 'tools/list') {
    if (has('--modern') && !(m.params && m.params._meta && m.params._meta['io.modelcontextprotocol/protocolVersion'])) return err(-32602, 'protocol version missing');
    if (!(PAGE > 0)) return ok({ tools });
    const start = m.params && m.params.cursor ? Number(m.params.cursor) : 0;
    const page = tools.slice(start, start + PAGE);
    return ok({ tools: page, ...(start + PAGE < tools.length ? { nextCursor: String(start + PAGE) } : {}) });
  }
  if (m.method === 'prompts/list') return ok({ prompts: [{ name: 'summarise', description: 'Summarises an item.' }] });
  return err(-32601, 'Method not found');
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const port = Number(arg('--http', '0'));
  if (port > 0) {
    createServer((req, res) => {
      if (req.method !== 'POST' || req.url !== '/mcp') { res.writeHead(404).end(); return; }
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        let m; try { m = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { res.writeHead(400).end(); return; }
        const a = answer(m);
        if (!a) { res.writeHead(202).end(); return; }
        res.writeHead(200, { 'content-type': 'application/json', ...(m.method === 'initialize' ? { 'mcp-session-id': 'null-session' } : {}) });
        res.end(JSON.stringify(a));
      });
    }).listen(port, '0.0.0.0');
  } else {
    if (has('--noise')) process.stdout.write('null-server starting\n');
    let buf = '';
    process.stdin.on('data', (c) => {
      buf += c;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        let m; try { m = JSON.parse(line); } catch { continue; }
        const a = answer(m);
        if (a) process.stdout.write(`${JSON.stringify(a)}\n`);
      }
    });
    process.stdin.on('end', () => process.exit(0));
  }
}
