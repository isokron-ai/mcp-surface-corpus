#!/usr/bin/env node
// Prints what scripts/install-runsc.sh installs, from gvisor.json, one "key=value" per line:
//
//   node scripts/runsc-plan.mjs [--arch x86_64|aarch64] [--config gvisor.json]
//
//   release=20261116.0
//   runtime=runsc
//   url=https://storage.googleapis.com/gvisor/releases/release/20261116.0/x86_64/gvisor.tar.bz2
//   sha512=<128 hex>
//   install_dir=/usr/local/lib/isokron-gvisor
//   log_dir=/var/log/isokron-runsc
//   trace_fs_mb=2048                 (the size of the trace folder's own filesystem)
//   docker_root=/var/lib/isokron-docker  (Docker's data-root, a filesystem of its own)
//   docker_fs_mb=20480 docker_fs_inodes=2097152  (one line each: its size and inode count)
//   volume_fs_mb=6144                (the size of the filesystem Docker's volumes get)
//   volume_fs_inodes=1048576         (and its inode count)
//   log_driver=local log_max_size=16m log_max_file=2  (one line each: every container's log limits)
//   flag=--network=sandbox          (one line per runsc flag, in the order src/runsc.mjs gives)
//
// The flags are exactly runscFlags(): the runtime the install registers and the flags the harness
// expects to find on the daemon come from the same function. The arch defaults to this machine's.
//
//   node scripts/runsc-plan.mjs --verify-runtimes [--arch ...] [--config ...] < runtimes.json
//
// reads the daemon's runtimes (`info --format '{{json .Runtimes}}'`) on stdin and exits 0 only when
// the runtime is there with exactly those flags; the install checks its own work with it.
// A config that does not validate, an arch with no bundle, or a daemon without the runtime prints
// "harness error: ..." and exits 1.
import { readFileSync } from 'node:fs';
import { arch as hostArch } from 'node:os';
import { pathToFileURL } from 'node:url';
import { loadRunscConfig, normArch, runscFlags, runtimeArgs, runtimeAvailable, GVISOR_FILE } from '../src/runsc.mjs';

export function plan(cfg, arch) {
  const a = normArch(arch);
  const b = cfg.bundles[a];
  return [
    `release=${cfg.release}`,
    `runtime=${cfg.runtime}`,
    `url=${b.url}`,
    `sha512=${b.sha512}`,
    `install_dir=${cfg.install_dir}`,
    `log_dir=${cfg.log_dir}`,
    `trace_fs_mb=${cfg.trace_fs_mb}`,
    `docker_root=${cfg.docker_root}`,
    `docker_fs_mb=${cfg.docker_fs_mb}`,
    `docker_fs_inodes=${cfg.docker_fs_inodes}`,
    `volume_fs_mb=${cfg.volume_fs_mb}`,
    `volume_fs_inodes=${cfg.volume_fs_inodes}`,
    `log_driver=${cfg.container_logs.driver}`,
    `log_max_size=${cfg.container_logs.max_size_mb}m`,
    `log_max_file=${cfg.container_logs.max_file}`,
    ...runscFlags(cfg, a).map((f) => `flag=${f}`),
  ];
}

/** Null when the daemon has the runtime with exactly runscFlags(), else what is wrong. */
export function verifyRuntimes(cfg, arch, runtimesJson) {
  if (!runtimeAvailable(runtimesJson, cfg.runtime)) return `the daemon has no runtime ${cfg.runtime}`;
  const want = runscFlags(cfg, arch);
  const got = runtimeArgs(runtimesJson, cfg.runtime);
  if (got.length !== want.length || got.some((f, i) => f !== want[i])) return `the daemon's ${cfg.runtime} flags are not the ones in gvisor.json`;
  return null;
}

function main(argv) {
  let arch = hostArch();
  let file = GVISOR_FILE;
  let verify = false;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if ((a === '--arch' || a === '--config') && i + 1 < argv.length) {
      if (a === '--arch') arch = argv[++i]; else file = argv[++i];
    } else if (a === '--verify-runtimes') verify = true;
    else throw new Error(`unknown option ${a}; usage: runsc-plan.mjs [--verify-runtimes] [--arch ARCH] [--config FILE]`);
  }
  const cfg = loadRunscConfig(file);
  if (verify) {
    const why = verifyRuntimes(cfg, arch, readFileSync(0, 'utf8'));
    if (why) throw new Error(why);
    process.stdout.write(`runtime ${cfg.runtime} registered with the pinned flags\n`);
    return;
  }
  process.stdout.write(`${plan(cfg, arch).join('\n')}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(process.argv.slice(2)); } catch (e) {
    process.stdout.write(`harness error: ${e.message}\n`);
    process.exit(1);
  }
}
