// A minimal, read-only tar reader (ustar, GNU long names, pax headers) over a gzip buffer.
// Nothing is written to disk: entries are returned as { path, size, type, data? } with data kept
// only for files the caller wants (`want(path, size)`). Links and special files are listed, never followed.
import { gunzipSync } from 'node:zlib';

export const MAX_UNPACKED = 512 * 1024 * 1024;

function str(buf, off, len) {
  const s = buf.subarray(off, off + len);
  const z = s.indexOf(0);
  return (z >= 0 ? s.subarray(0, z) : s).toString('utf8');
}
function num(buf, off, len) {
  if (buf[off] & 0x80) { // base-256
    let v = 0;
    for (let i = 1; i < len; i++) v = v * 256 + buf[off + i];
    return v;
  }
  const s = str(buf, off, len).trim();
  return s ? parseInt(s, 8) : 0;
}
function parsePax(text) {
  const o = {};
  let i = 0;
  while (i < text.length) {
    const sp = text.indexOf(' ', i);
    if (sp < 0) break;
    const len = parseInt(text.slice(i, sp), 10);
    if (!(len > 0)) break;
    const rec = text.slice(sp + 1, i + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0) o[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return o;
}

/** Reads a .tar.gz (or plain .tar) buffer. Returns { entries, global, truncated }. */
export function readTar(input, { want = () => false, maxUnpacked = MAX_UNPACKED } = {}) {
  let buf = input;
  if (buf[0] === 0x1f && buf[1] === 0x8b) buf = gunzipSync(buf, { maxOutputLength: maxUnpacked });
  const entries = [];
  let global = {};
  let pax = null;
  let longName = null;
  let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const size = num(h, 124, 12);
    const flag = String.fromCharCode(h[156] || 48);
    const magic = str(h, 257, 6);
    let name = str(h, 0, 100);
    const prefix = magic.startsWith('ustar') ? str(h, 345, 155) : '';
    if (prefix) name = `${prefix}/${name}`;
    const dataOff = off + 512;
    const data = buf.subarray(dataOff, dataOff + size);
    off = dataOff + Math.ceil(size / 512) * 512;
    if (flag === 'g') { global = { ...global, ...parsePax(data.toString('utf8')) }; continue; }
    if (flag === 'x') { pax = parsePax(data.toString('utf8')); continue; }
    if (flag === 'L') { longName = str(data, 0, data.length); continue; }
    if (longName) { name = longName; longName = null; }
    if (pax && pax.path) name = pax.path;
    pax = null;
    const type = flag === '0' || flag === '\0' || flag === '7' ? 'file' : flag === '5' ? 'dir' : flag === '2' ? 'symlink' : flag === '1' ? 'link' : 'other';
    const e = { path: name, size, type };
    if (type === 'file' && want(name, size)) e.data = Buffer.from(data);
    entries.push(e);
  }
  return { entries, global };
}
