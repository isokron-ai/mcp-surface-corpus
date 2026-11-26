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
 */
import { lstatSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

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
// A command counts when its name and entry point are plain, its runner is one we start, the entry point is a regular
// file of the package (no link, no path out of its folder) and the install created its launcher in <root>.
const ok = found.filter((c) => c.name && NAME.test(c.name) && c.entry && /^[A-Za-z0-9][A-Za-z0-9._/+-]{0,200}$/.test(c.entry) && !c.entry.split('/').some((s) => s === '..' || s === '.' || s === '')
  && ['dotnet', 'executable'].includes(c.runner) && isFile(join(c.dir, c.entry)) && isFile(join(root, c.name)));
const distinct = [...new Map(ok.map((c) => [`${c.name}\u0000${c.dir}\u0000${c.entry}`, c])).values()];
if (!distinct.length) out({ error: 'no_command', commands: found.filter((c) => c.name && NAME.test(c.name)).map((c) => c.name).slice(0, 8) }, 1);
// A RID-specific tool: its linux-x64 build is the one that runs, not the pointer package's.
const pick = distinct.length === 1 ? distinct[0] : distinct.filter((c) => c.rid === 'linux-x64').length === 1 ? distinct.find((c) => c.rid === 'linux-x64') : null;
if (!pick) out({ error: 'several_commands', commands: distinct.map((c) => c.name).slice(0, 8) }, 1);
out({ script: join(pick.dir, pick.entry), runner: pick.runner, command: pick.name, version: /^[0-9A-Za-z.+-]{1,64}$/.test(pick.version) ? pick.version : null, tfm: pick.tfm, rid: pick.rid }, 0);
