#!/usr/bin/env node
/**
 * The install step's only way out. An HTTP CONNECT proxy that tunnels to port 443 of the host names
 * given on the command line and refuses everything else (other hosts, other ports, plain HTTP, IP
 * literals). It runs in its own container (our code, not a target's), attached to the target's
 * --internal install network and to one network with egress; the install container itself is on
 * the internal network only and reaches the package registry through HTTPS_PROXY.
 *
 *   node egress-proxy.mjs <port> <host> [<host>...]
 *
 * One JSON line per request on stdout ({ t, host, port, allowed, up, down, ms, error }): the hosts an
 * install tried to reach are part of the record. TLS is end to end between the client and the
 * registry; the proxy sees host names and byte counts only.
 */
import { createServer } from 'node:http';
import { connect, isIP } from 'node:net';

const MAX_OPEN = 64;

export function decide(target, allowed) {
  const m = /^([A-Za-z0-9.-]{1,253}):([0-9]{1,5})$/.exec(String(target));
  if (!m) return { ok: false, why: 'not host:port' };
  const host = m[1].toLowerCase().replace(/\.$/, '');
  if (isIP(host)) return { ok: false, host, port: Number(m[2]), why: 'IP literal' };
  if (Number(m[2]) !== 443) return { ok: false, host, port: Number(m[2]), why: 'port' };
  if (!allowed.has(host)) return { ok: false, host, port: 443, why: 'host not on the allowlist' };
  return { ok: true, host, port: 443 };
}

export function makeProxy(allow, log) {
  let open = 0;
  const server = createServer((req, res) => {
    log({ host: String(req.headers.host || '').slice(0, 253), method: String(req.method).slice(0, 16), allowed: false, error: 'plain HTTP refused' });
    res.writeHead(403, { 'content-type': 'text/plain', connection: 'close' });
    res.end('surface corpus: only CONNECT to allowlisted hosts on port 443\n');
  });
  server.on('connect', (req, client, head) => {
    const d = decide(req.url, allow);
    const t0 = Date.now();
    client.on('error', () => {});
    if (!d.ok || open >= MAX_OPEN) {
      log({ host: d.host ?? String(req.url).slice(0, 253), port: d.port ?? null, allowed: false, error: d.ok ? 'too many connections' : d.why });
      client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return;
    }
    open++;
    let up = 0; let down = 0; let done = false;
    const finish = (error) => {
      if (done) return;
      done = true; open--;
      log({ host: d.host, port: 443, allowed: true, up, down, ms: Date.now() - t0, ...(error ? { error: String(error.code || error.message).slice(0, 80) } : {}) });
      upstream.destroy(); client.destroy();
    };
    const upstream = connect({ host: d.host, port: 443, timeout: 30_000 });
    upstream.on('connect', () => {
      upstream.setTimeout(0);
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) { up += head.length; upstream.write(head); }
      client.on('data', (c) => { up += c.length; });
      upstream.on('data', (c) => { down += c.length; });
      client.pipe(upstream); upstream.pipe(client);
    });
    upstream.on('timeout', () => { if (!done) client.end('HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n'); finish(new Error('connect timeout')); });
    upstream.on('error', (e) => { if (!done && !up && !down) client.end('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n'); finish(e); });
    upstream.on('close', () => finish());
    client.on('close', () => finish());
  });
  return server;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [port, ...hosts] = process.argv.slice(2);
  if (!(Number(port) > 0) || !hosts.length) { process.stderr.write('usage: egress-proxy.mjs <port> <host>...\n'); process.exit(2); }
  const allow = new Set(hosts.map((h) => h.toLowerCase()));
  const log = (o) => process.stdout.write(`${JSON.stringify({ t: new Date().toISOString(), ...o })}\n`);
  makeProxy(allow, log).listen(Number(port), '0.0.0.0', () => log({ listening: Number(port), hosts: [...allow] }));
  for (const s of ['SIGTERM', 'SIGINT']) process.on(s, () => process.exit(0));
}
