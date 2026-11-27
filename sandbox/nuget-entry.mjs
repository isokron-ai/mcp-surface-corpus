#!/usr/bin/env node
/**
 * The command of a .NET tool installed with `dotnet tool install --tool-path <root>` (src/targets.mjs launchPlan, kind
 * nuget). Ours, from the read-only tools volume; it runs in an install container (the node image) after the install,
 * reads the package's own DotnetToolSettings.xml under <root>/.store (data, never executed) and checks the command's
 * launcher in <root>. Links are never followed.
 *
 *   node nuget-entry.mjs <root> <package id>
 *
 * Prints one line, { script, runner, command, version, tfm, rid } and exits 0, where script is the file the settings
 * name as the entry point (runner "dotnet": `dotnet <script>`; runner "executable": the file itself); or { error } and
 * exits 1:
 *   not_installed      no store folder for <package id>
 *   no_tool_settings   no DotnetToolSettings.xml in it (the package is not a .NET tool)
 *   no_linux_build     settings only for runtimes other than any or linux-x64
 *   no_command         no command whose launcher the install created, or whose entry point is a file of the package
 *   several_commands   more than one such command (we would have to guess)
 *   runtime_too_new    built only for a newer .NET than the image's (net10.0)
 */
import { lstatSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { join, sep } from 'node:path';

const [root, id] = process.argv.slice(2);
const out = (o, code) => { process.stdout.write(`${JSON.stringify(o)}\n`); process.exit(code); };
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,80}$/;
const SEG = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,120}$/;
if (!root || !/^\/[A-Za-z0-9._/-]{1,200}$/.test(root) || !/^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,98}[A-Za-z0-9_])?$/.test(id ?? '')) out({ error: 'usage' }, 2);

const isDir = (p) => { try { return lstatSync(p).isDirectory(); } catch { return false; } };
const isFile = (p) => { try { return lstatSync(p).isFile(); } catch { return false; } };
const dirs = (p) => { try { return readdirSync(p).filter((n) => SEG.test(n) && isDir(join(p, n))).sort(); } catch { return []; } };

/** One attribute of an XML start tag, unescaped for the five predefined entities only. */
function attr(tag, name) {
  const m = new RegExp(`\\s${name}\\s*=\\s*"([^"<>]{0,200})"`).exec(tag) || new RegExp(`\\s${name}\\s*=\\s*'([^'<>]{0,200})'`).exec(tag);
  return m ? m[1].replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&') : null;
}

/** The <Command> entries of one DotnetToolSettings.xml (at most 64 KiB read). */
function commandsOf(xml) {
  return [...String(xml).slice(0, 64 * 1024).matchAll(/<Command\b[^>]{0,600}>/g)].map((m) => ({ name: attr(m[0], 'Name'), entry: attr(m[0], 'EntryPoint'), runner: attr(m[0], 'Runner') })).slice(0, 16);
}

// <root>/.store/<id lower>/<version>/<package lower>/<version>/tools/<tfm>/<rid>/DotnetToolSettings.xml; a RID-specific
// tool also has its runtime package (<id>.<rid>) beside the pointer package in the same version folder.
const store = join(root, '.store', id.toLowerCase());
if (!isDir(store)) out({ error: 'not_installed' }, 1);
const found = [];
let otherRid = false;
for (const ver of dirs(store).slice(0, 8)) {
  for (const pkg of dirs(join(store, ver)).slice(0, 16)) {
    for (const ver2 of dirs(join(store, ver, pkg)).slice(0, 8)) {
      const tools = join(store, ver, pkg, ver2, 'tools');
      for (const tfm of dirs(tools).slice(0, 16)) {
        for (const rid of dirs(join(tools, tfm)).slice(0, 32)) {
          const dir = join(tools, tfm, rid);
          const f = join(dir, 'DotnetToolSettings.xml');
          if (!isFile(f)) continue;
          if (!['any', 'linux-x64'].includes(rid)) { otherRid = true; continue; }
          let xml;
          try { xml = readFileSync(f, 'utf8'); } catch { continue; }
          for (const c of commandsOf(xml)) found.push({ ...c, dir, version: ver, tfm, rid });
        }
      }
    }
  }
}
if (!found.length) out({ error: otherRid ? 'no_linux_build' : 'no_tool_settings' }, 1);
// The command's launcher in <root>: a regular file (the apphost of a framework-dependent tool) or, for a RID-specific
// tool, a link the install made to the executable in the store; a link counts only when it resolves to a regular file
// inside <root>/.store, and then it names the very file that runs.
const storeReal = (() => { try { return realpathSync(join(root, '.store')); } catch { return null; } })();
function launcher(name) {
  const p = join(root, name);
  let st;
  try { st = lstatSync(p); } catch { return null; }
  if (st.isFile()) return { kind: 'file' };
  if (!st.isSymbolicLink() || !storeReal) return null;
  try {
    const real = realpathSync(p);
    return real.startsWith(storeReal + sep) && statSync(real).isFile() ? { kind: 'link', real } : null;
  } catch { return null; }
}
// A command counts when its name and entry point are plain, its runner is one we start, the entry point is a regular
// file of the package (no link, no path out of its folder) and the install created its launcher in <root>.
const ok = found.filter((c) => c.name && NAME.test(c.name) && c.entry && /^[A-Za-z0-9][A-Za-z0-9._/+-]{0,200}$/.test(c.entry) && !c.entry.split('/').some((s) => s === '..' || s === '.' || s === '')
  && ['dotnet', 'executable'].includes(c.runner) && isFile(join(c.dir, c.entry)) && launcher(c.name));
if (!ok.length) out({ error: 'no_command', commands: found.filter((c) => c.name && NAME.test(c.name)).map((c) => c.name).slice(0, 8) }, 1);
// One command name only: a package that declares two commands would make us guess.
const names = [...new Set(ok.map((c) => c.name))];
if (names.length > 1) out({ error: 'several_commands', commands: names.slice(0, 8) }, 1);
// The build of that command that runs here, as the .NET host picks it: the file a link launcher points at; else the
// linux-x64 build of a RID-specific tool; else, of a package built for several target frameworks, the newest one this
// runtime (MAX_TFM) runs. A package built only for a newer runtime cannot run here.
const tfmOf = (t) => { const m = /^net([0-9]{1,2})\.([0-9])$/.exec(t); return m ? Number(m[1]) * 10 + Number(m[2]) : null; };
const MAX_TFM = 100; // net10.0, the runtime of the pinned SDK image
const link = launcher(names[0]);
let pool = ok;
if (link.kind === 'link') pool = ok.filter((c) => { try { return realpathSync(join(c.dir, c.entry)) === link.real; } catch { return false; } });
if (pool.some((c) => c.rid === 'linux-x64')) pool = pool.filter((c) => c.rid === 'linux-x64');
const runnable = pool.filter((c) => tfmOf(c.tfm) === null || tfmOf(c.tfm) <= MAX_TFM);
if (!runnable.length) out({ error: 'runtime_too_new', tfms: [...new Set(pool.map((c) => c.tfm))].slice(0, 8) }, 1);
const best = Math.max(...runnable.map((c) => tfmOf(c.tfm) ?? -1));
const pick = runnable.filter((c) => (tfmOf(c.tfm) ?? -1) === best);
if (pick.length !== 1) out({ error: 'several_commands', commands: names }, 1);
const c = pick[0];
out({ script: join(c.dir, c.entry), runner: c.runner, command: c.name, version: /^[0-9A-Za-z.+-]{1,64}$/.test(c.version) ? c.version : null, tfm: c.tfm, rid: c.rid }, 0);
