#!/usr/bin/env node
// What the sandbox self test ran on: the runner image, the kernel, Docker, and the gVisor release
// installed. Read after scripts/install-runsc.sh, so drift in any of them shows next to the verdict.
//
//   node scripts/runner-facts.mjs --out FILE.json [--github-output FILE]
//
// Writes FILE.json and, with --github-output, the step outputs runner-image, kernel, docker,
// gvisor-release and runsc-version. Every value is a short plain token or "unknown": nothing a
// command printed reaches an output unchecked.
import { readFileSync, appendFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const FACTS_FORMAT = 'isokron-sandbox-runner/1';
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._+/:-]{0,79}$/;

/** A value as a short plain token, or "unknown". */
export const plain = (v) => {
  const s = String(v ?? '').trim().split('\n')[0].trim();
  return TOKEN.test(s) ? s : 'unknown';
};

/** The facts, from the environment and the commands given (spawnSync by default). */
export function runnerFacts({ env = process.env, run = spawnSync, gvisor = join(root, 'gvisor.json') } = {}) {
  const out = (cmd, argv) => {
    try {
      const r = run(cmd, argv, { encoding: 'utf8', timeout: 30_000 });
      return r.status === 0 ? String(r.stdout) : '';
    } catch { return ''; }
  };
  let pinned = 'unknown';
  try { pinned = plain(JSON.parse(readFileSync(gvisor, 'utf8')).release); } catch { /* stays unknown */ }
  // runsc prints "runsc version release-20261116.0" on its first line.
  const runsc = /^runsc version (\S+)/m.exec(out('runsc', ['--version']));
  return {
    format: FACTS_FORMAT,
    runner_image: env.ImageOS && env.ImageVersion ? plain(`${env.ImageOS}/${env.ImageVersion}`) : 'unknown',
    runner_os: plain(env.RUNNER_OS),
    runner_arch: plain(env.RUNNER_ARCH),
    kernel: plain(out('uname', ['-r'])),
    docker: plain(out('docker', ['version', '--format', '{{.Server.Version}}'])),
    gvisor_release: pinned,
    runsc_version: plain(runsc?.[1]),
  };
}

function main(argv) {
  let file = null; let gh = null;
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--out' && i + 1 < argv.length) file = argv[++i];
    else if (argv[i] === '--github-output' && i + 1 < argv.length) gh = argv[++i];
    else { process.stderr.write('usage: runner-facts.mjs --out FILE.json [--github-output FILE]\n'); return 2; }
  }
  if (!file) { process.stderr.write('usage: runner-facts.mjs --out FILE.json [--github-output FILE]\n'); return 2; }
  const f = runnerFacts();
  writeFileSync(file, `${JSON.stringify(f, null, 2)}\n`);
  if (gh) appendFileSync(gh, `runner-image=${f.runner_image}\nkernel=${f.kernel}\ndocker=${f.docker}\ngvisor-release=${f.gvisor_release}\nrunsc-version=${f.runsc_version}\n`);
  process.stdout.write(`runner ${f.runner_image}, kernel ${f.kernel}, docker ${f.docker}, gVisor ${f.gvisor_release} (runsc ${f.runsc_version})\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) process.exitCode = main(process.argv.slice(2));
