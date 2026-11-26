#!/usr/bin/env node
/**
 * Fetches and unpacks an MCP Bundle (.mcpb, a zip archive with manifest.json at its root) for src/targets.mjs
 * launchPlan, kind mcpb. Ours, from the read-only tools volume; it runs in an install container (the node image, gVisor,
 * user 65534, no capabilities, read-only root) whose only way out is the allowlist proxy. The bundle is untrusted data:
 * nothing in it is executed here.
 *
 *   node mcpb-fetch.mjs <url> <sha256> <dest> [--exec <path in the bundle>]
 *
 * 1. GET <url> through HTTPS_PROXY (a CONNECT tunnel; TLS end to end with the host's certificate checked), following
 *    at most 5 redirects, each to https on MCPB_HOSTS only; at most MAX_BYTES, read as a stream and stopped there.
 * 2. Its sha256 must be <sha256> (the registry's fileSha256, or the digest the planner read).
 * 3. Unpacked into <dest> (which must not exist yet): only the central directory's entries, each name checked (no
 *    absolute path, no . or .. segment, no backslash, colon, NUL or control character, at most 64 segments, no name
 *    twice), stored or deflated only, never encrypted, each entry's inflated size exactly the size it declares (and so
 *    at most MAX_UNPACKED in all) with its CRC-32 checked, at most MAX_FILES entries. Symbolic links are left out (and
 *    counted), never created; every file is created new (O_EXCL), so nothing is written through a link. A file is
 *    executable only when the archive says so (Unix mode) or it is the --exec path.
 *
 * Prints one line and exits 0: { ok: true, bytes, sha256, files, dirs, links_skipped, unpacked }; or exits 1 with
 * { error, ... }:
 *   not_found         the host answered 404 (the asset is not at that URL)
 *   http_<n>          another HTTP status
 *   fetch_failed      the proxy refused, or a connection, TLS or time-out problem
 *   redirect_refused  a redirect to another host or scheme, or too many
 *   too_large         over MAX_BYTES
 *   sha256_mismatch   the bytes are not the ones named
 *   not_a_zip         no zip record anywhere in the file (it is no archive at all)
 *   zip_unreadable    an archive this does not read: zip64, encryption, another method, bad offsets, CRC or size
 *   unsafe_path       an entry name refused above, or two entries for one path
 *   too_many_files, too_big_unpacked   our caps
 *   no_manifest       no manifest.json at the root
 *   exec_missing      the --exec path is not a file of the bundle
 */
import { createHash } from 'node:crypto';
import { closeSync, chmodSync, existsSync, lstatSync, mkdirSync, openSync, writeSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { connect as tlsConnect } from 'node:tls';
import { crc32, inflateRawSync } from 'node:zlib';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const MCPB_HOSTS = Object.freeze(['github.com', 'release-assets.githubusercontent.com', 'objects.githubusercontent.com']);
export const MAX_BYTES = 200 * 1024 * 1024;
export const MAX_UNPACKED = 1024 * 1024 * 1024;
export const MAX_FILES = 50_000;
const MAX_REDIRECTS = 5;
const TIMEOUT_MS = 240_000;

export class Refusal extends Error { constructor(code, extra = {}) { super(code); this.code = code; this.extra = extra; } }

/** A URL this may fetch: https, one of MCPB_HOSTS, the default port, no credentials. */
export function allowedUrl(u) {
  try { const x = new URL(u); return x.protocol === 'https:' && MCPB_HOSTS.includes(x.hostname) && !x.port && !x.username && !x.password ? x : null; } catch { return null; }
}

/** A TLS socket to host:443 through the CONNECT proxy, or directly when there is none (the tests). */
function tunnel(proxy, host) {
  return new Promise((resolve, reject) => {
    if (!proxy) { resolve(null); return; }
    const req = httpRequest({ host: proxy.hostname, port: proxy.port || 80, method: 'CONNECT', path: `${host}:443`, headers: { host: `${host}:443` }, timeout: 30_000 });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) { socket.destroy(); reject(new Refusal('fetch_failed', { proxy_status: res.statusCode })); return; }
      resolve(tlsConnect({ socket, servername: host }));
    });
    req.on('timeout', () => req.destroy(new Refusal('fetch_failed', { why: 'proxy timeout' })));
    req.on('error', (e) => reject(e instanceof Refusal ? e : new Refusal('fetch_failed', { why: String(e.code || e.message).slice(0, 60) })));
    req.end();
  });
}

/**
 * The GET's options: over the tunnel's TLS socket when there is a proxy. No `agent` key at all: with one (even
 * `agent: false`) Node hands the request to an Agent, which ignores createConnection and opens a direct connection of
 * its own, looked up by name: past the proxy (R-SBX-45; in the sandbox the name lookup gives the network logger, which
 * resets it).
 */
export function requestOptions(url, sock) {
  // Port and Host stated: with no agent Node knows no default port and would write `Host: <name>:80`.
  return { host: url.hostname, port: 443, defaultPort: 443, path: url.pathname + url.search, method: 'GET', headers: { host: url.hostname, 'user-agent': 'isokron-surface-corpus', accept: 'application/octet-stream' }, timeout: TIMEOUT_MS, ...(sock ? { createConnection: () => sock } : {}) };
}

/** One GET: { status, location } for a redirect, else the body (at most cap bytes) and its sha256. */
async function getOnce(url, { proxy, cap }) {
  const sock = await tunnel(proxy, url.hostname);
  return new Promise((resolve, reject) => {
    const req = httpsRequest(requestOptions(url, sock));
    req.on('response', (res) => {
      const status = res.statusCode;
      if (status >= 300 && status < 400) { res.resume(); resolve({ status, location: String(res.headers.location || '') }); return; }
      if (status !== 200) { res.resume(); reject(new Refusal(status === 404 ? 'not_found' : `http_${status}`, { host: url.hostname })); return; }
      const len = Number(res.headers['content-length']);
      if (Number.isFinite(len) && len > cap) { res.destroy(); reject(new Refusal('too_large', { declared: len })); return; }
      const parts = []; let total = 0; const h = createHash('sha256');
      res.on('data', (b) => {
        total += b.length;
        if (total > cap) { res.destroy(); reject(new Refusal('too_large')); return; }
        h.update(b); parts.push(b);
      });
      res.on('end', () => resolve({ status, body: Buffer.concat(parts, total), sha256: h.digest('hex') }));
      res.on('error', (e) => reject(new Refusal('fetch_failed', { why: String(e.code || e.message).slice(0, 60) })));
    });
    req.on('timeout', () => req.destroy(new Refusal('fetch_failed', { why: 'timeout' })));
    req.on('error', (e) => reject(e instanceof Refusal ? e : new Refusal('fetch_failed', { why: String(e.code || e.message).slice(0, 60) })));
    req.end();
  });
}

/** The bundle's bytes, following redirects on the allowed hosts only. */
export async function fetchBundle(start, { proxy = null, cap = MAX_BYTES, get = getOnce } = {}) {
  let url = allowedUrl(start);
  if (!url) throw new Refusal('redirect_refused', { why: 'the first URL is not on the list' });
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const r = await get(url, { proxy, cap });
    if (!r.location && r.status !== undefined && r.status >= 300 && r.status < 400) throw new Refusal('redirect_refused', { why: 'a redirect with no location' });
    if (r.location === undefined) return r;
    let next;
    try { next = new URL(r.location, url); } catch { throw new Refusal('redirect_refused', { why: 'a bad location' }); }
    url = allowedUrl(next.href);
    if (!url) throw new Refusal('redirect_refused', { host: next.hostname.slice(0, 80) });
  }
  throw new Refusal('redirect_refused', { why: 'too many redirects' });
}

/** A path inside the bundle that may be written, or null. */
export function safeEntryName(name) {
  if (typeof name !== 'string' || !name || name.length > 1024) return null;
  if (/[\u0000-\u001f\u007f\\:]/.test(name) || name.startsWith('/')) return null;
  const dir = name.endsWith('/');
  const segs = (dir ? name.slice(0, -1) : name).split('/');
  if (!segs.length || segs.length > 64 || segs.some((s) => s === '' || s === '.' || s === '..' || s.length > 255)) return null;
  return { path: segs.join('/'), dir };
}

/**
 * The entries of a zip archive from its central directory, every offset bounds-checked: [{ name, method, flags, csize,
 * usize, crc, offset, mode, unix }]. Throws a Refusal.
 */
export function zipEntries(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 22) throw new Refusal('not_a_zip');
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 0xffff); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) throw new Refusal(buf.indexOf(Buffer.from([0x50, 0x4b, 0x03, 0x04])) < 0 ? 'not_a_zip' : 'zip_unreadable', { why: 'no end record' });
  const disk = buf.readUInt16LE(eocd + 4); const cdDisk = buf.readUInt16LE(eocd + 6);
  const count = buf.readUInt16LE(eocd + 10); const cdSize = buf.readUInt32LE(eocd + 12); const cdOff = buf.readUInt32LE(eocd + 16);
  if (disk !== 0 || cdDisk !== 0) throw new Refusal('zip_unreadable', { why: 'a multi-part archive' });
  if (count === 0xffff || cdOff === 0xffffffff || cdSize === 0xffffffff) throw new Refusal('zip_unreadable', { why: 'zip64' });
  if (count > MAX_FILES) throw new Refusal('too_many_files', { entries: count });
  if (cdOff + cdSize > eocd) throw new Refusal('zip_unreadable', { why: 'the central directory is outside the file' });
  const out = [];
  let p = cdOff;
  for (let n = 0; n < count; n++) {
    if (p + 46 > cdOff + cdSize || buf.readUInt32LE(p) !== 0x02014b50) throw new Refusal('zip_unreadable', { why: 'a bad central directory entry' });
    const madeBy = buf.readUInt16LE(p + 4) >> 8;
    const flags = buf.readUInt16LE(p + 8); const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16); const csize = buf.readUInt32LE(p + 20); const usize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28); const extraLen = buf.readUInt16LE(p + 30); const commentLen = buf.readUInt16LE(p + 32);
    const ext = buf.readUInt32LE(p + 38); const offset = buf.readUInt32LE(p + 42);
    if (p + 46 + nameLen + extraLen + commentLen > cdOff + cdSize) throw new Refusal('zip_unreadable', { why: 'an entry runs past the central directory' });
    if (csize === 0xffffffff || usize === 0xffffffff || offset === 0xffffffff) throw new Refusal('zip_unreadable', { why: 'zip64' });
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    out.push({ name, method, flags, csize, usize, crc, offset, unix: madeBy === 3, mode: madeBy === 3 ? (ext >>> 16) & 0xffff : 0 });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

/** One entry's bytes: stored or deflated, exactly its declared size, its CRC-32 checked. Throws a Refusal. */
export function entryBytes(buf, e) {
  if (e.flags & 0x1) throw new Refusal('zip_unreadable', { why: 'an encrypted entry' });
  if (e.offset + 30 > buf.length || buf.readUInt32LE(e.offset) !== 0x04034b50) throw new Refusal('zip_unreadable', { why: 'a bad local header' });
  const start = e.offset + 30 + buf.readUInt16LE(e.offset + 26) + buf.readUInt16LE(e.offset + 28);
  if (start + e.csize > buf.length) throw new Refusal('zip_unreadable', { why: 'an entry runs past the file' });
  const data = buf.subarray(start, start + e.csize);
  let b;
  if (e.method === 0) b = data;
  else if (e.method === 8) {
    try { b = e.usize === 0 ? Buffer.alloc(0) : inflateRawSync(data, { maxOutputLength: e.usize }); } catch { throw new Refusal('zip_unreadable', { why: 'an entry inflates past its declared size, or not at all' }); }
  } else throw new Refusal('zip_unreadable', { why: `compression method ${e.method}` });
  if (b.length !== e.usize) throw new Refusal('zip_unreadable', { why: 'an entry is not its declared size' });
  if ((crc32(b) >>> 0) !== e.crc) throw new Refusal('zip_unreadable', { why: 'a CRC-32 mismatch' });
  return b;
}

const S_IFMT = 0o170000; const S_IFLNK = 0o120000; const S_IFDIR = 0o040000;

/** Unpacks the archive into dest (which must not exist). Returns { files, dirs, links_skipped, unpacked }. Throws a Refusal. */
export function unpack(buf, dest, { exec = null, maxUnpacked = MAX_UNPACKED, maxFiles = MAX_FILES } = {}) {
  const entries = zipEntries(buf);
  if (entries.length > maxFiles) throw new Refusal('too_many_files', { entries: entries.length });
  const plan = []; const seen = new Set(); let total = 0; let links = 0;
  for (const e of entries) {
    const n = safeEntryName(e.name);
    if (!n) throw new Refusal('unsafe_path');
    const key = n.path;
    const kind = e.unix && (e.mode & S_IFMT) === S_IFLNK ? 'link' : n.dir || (e.unix && (e.mode & S_IFMT) === S_IFDIR) ? 'dir' : 'file';
    if (kind === 'link') { links++; continue; }
    if (seen.has(`${kind}:${key}`)) throw new Refusal('unsafe_path', { why: 'two entries for one path' });
    seen.add(`${kind}:${key}`);
    if (kind === 'file') { total += e.usize; if (total > maxUnpacked) throw new Refusal('too_big_unpacked'); }
    plan.push({ e, path: n.path, kind });
  }
  if (!plan.some((x) => x.kind === 'file' && x.path === 'manifest.json')) throw new Refusal('no_manifest');
  if (exec !== null && !plan.some((x) => x.kind === 'file' && x.path === exec)) throw new Refusal('exec_missing');
  if (existsSync(dest)) throw new Refusal('zip_unreadable', { why: 'the destination exists already' });
  mkdirSync(dest, { mode: 0o755 });
  let files = 0; let dirs = 0;
  const mkdirs = (rel) => {
    if (!rel) return;
    try { mkdirSync(join(dest, rel), { recursive: true, mode: 0o755 }); } catch { throw new Refusal('unsafe_path', { why: 'a folder where the archive has a file' }); }
  };
  for (const x of plan) {
    const target = join(dest, x.path);
    if (x.kind === 'dir') { mkdirs(x.path); dirs++; continue; }
    mkdirs(x.path.split('/').slice(0, -1).join('/'));
    const b = entryBytes(buf, x.e);
    const execBit = (x.e.unix && (x.e.mode & 0o111) !== 0) || x.path === exec;
    let fd;
    try { fd = openSync(target, 'wx', execBit ? 0o755 : 0o644); } catch { throw new Refusal('unsafe_path', { why: 'a file and a folder of one name, or a repeated path' }); }
    try { let off = 0; while (off < b.length) off += writeSync(fd, b, off, b.length - off); } finally { closeSync(fd); }
    if (execBit) chmodSync(target, 0o755);
    files++;
  }
  if (exec !== null && !lstatSync(join(dest, exec)).isFile()) throw new Refusal('exec_missing');
  return { files, dirs, links_skipped: links, unpacked: total };
}

export async function main(argv = process.argv.slice(2), env = process.env, { get = undefined, say: sayTo = null } = {}) {
  const [url, sha, dest, flag, execPath] = argv;
  const say = sayTo || ((o) => process.stdout.write(`${JSON.stringify(o)}\n`));
  if (!url || !allowedUrl(url) || !/^[0-9a-f]{64}$/.test(sha ?? '') || !/^\/[A-Za-z0-9._/-]{1,200}$/.test(dest ?? '') || (flag !== undefined && (flag !== '--exec' || !safeEntryName(execPath ?? '')))) { say({ error: 'usage' }); return 2; }
  let proxy = null;
  const p = env.HTTPS_PROXY || env.https_proxy || '';
  if (p) { try { proxy = new URL(p); } catch { say({ error: 'fetch_failed', why: 'bad proxy' }); return 1; } }
  try {
    const r = await fetchBundle(url, { proxy, ...(get ? { get } : {}) });
    if (r.sha256 !== sha) throw new Refusal('sha256_mismatch', { bytes: r.body.length });
    const u = unpack(r.body, dest, { exec: flag === '--exec' ? safeEntryName(execPath).path : null });
    say({ ok: true, bytes: r.body.length, sha256: r.sha256, ...u });
    return 0;
  } catch (e) {
    if (e instanceof Refusal) { say({ error: e.code, ...e.extra }); return 1; }
    say({ error: 'fetch_failed', why: String(e && (e.code || e.message)).slice(0, 80) });
    return 1;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) main().then((rc) => process.exit(rc));
