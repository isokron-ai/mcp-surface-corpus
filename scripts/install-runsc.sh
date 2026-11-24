#!/usr/bin/env bash
# Installs gVisor (runsc) exactly as gvisor.json pins it, and registers it with Docker as the
# runtime "runsc" with exactly the flags src/runsc.mjs gives (syscall tracing included). Run as root
# before any target (the workflows use sudo); the node binary to use is the first argument:
#
#   sudo scripts/install-runsc.sh "$(command -v node)"
#
# Order, and nothing is written before the bundle has passed both checks:
#   1. the plan (release, url, sha512, folders, flags) comes from scripts/runsc-plan.mjs, which reads
#      and validates gvisor.json; the arch is this machine's;
#   2. the release bundle is downloaded from its pinned url (or read from RUNSC_BUNDLE) into a
#      temporary folder, and its sha512 must equal the pinned one;
#   3. the bundle may hold runsc, containerd-shim-runsc-v1 and plain files directly in gvisor-bin/,
#      as regular files, and nothing else: no other name, no sub-folder, no link, no device;
#   4. it unpacks under <install_dir>/<release> (owned by root, writable by root only), with
#      <install_dir>/current pointing at it and /usr/local/bin/runsc and
#      /usr/local/bin/containerd-shim-runsc-v1 pointing into it;
#   5. the trace folder <log_dir> is made, mode 0750 (setgid, group of the user who ran sudo, so the
#      harness can read the traces and nobody else can), as a filesystem of its own: an ext4 file of
#      trace_fs_mb, loop-mounted nosuid,nodev,noexec, so a target's trace can never fill the
#      runner's disk (not under RUNSC_PREFIX, which is for the tests);
#   5b. Docker's volumes folder (<DockerRootDir>/volumes) becomes a filesystem of its own too: an
#      ext4 file of volume_fs_mb with volume_fs_inodes inodes, loop-mounted nosuid,nodev while the
#      daemon is stopped, before any volume exists. Every work volume a target writes lives there,
#      so an install or server that writes without end (an archive bomb, a fill) meets ENOSPC at
#      that size instead of filling the runner's disk, and cannot run it out of inodes (not under
#      RUNSC_PREFIX or RUNSC_SKIP_DAEMON, which are for the tests);
#   6. /etc/docker/daemon.json gets the runtime (other settings kept), the daemon restarts, and
#      `docker info` must then show runsc with exactly the pinned flags (runsc-plan.mjs
#      --verify-runtimes). A mismatch is a harness error: the harness never falls back to runc.
#
# Any failure prints "harness error: ..." and exits 1. Running it again gives the same result.
# Switches for the tests only (never set on CI): RUNSC_BUNDLE (a local bundle, never downloaded),
# RUNSC_CONFIG (another gvisor.json), RUNSC_PREFIX (a scratch root), RUNSC_SKIP_DAEMON (no Docker).
set -euo pipefail
umask 022

node_bin="${1:-}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fail() { echo "harness error: $*" >&2; exit 1; }
nothing() { echo "harness error: $*; nothing installed" >&2; exit 1; }

[ -n "$node_bin" ] && [ -x "$node_bin" ] || fail "usage: scripts/install-runsc.sh /path/to/node"
for c in tar bzip2 curl; do command -v "$c" >/dev/null || fail "$c not found"; done

plan_args=(--arch "$(uname -m)")
[ -z "${RUNSC_CONFIG:-}" ] || plan_args+=(--config "$RUNSC_CONFIG")
plan_out="$("$node_bin" "$here/runsc-plan.mjs" "${plan_args[@]}")" || { echo "$plan_out" >&2; nothing "no install plan"; }

release='' url='' sha512='' install_dir='' log_dir='' runtime='' trace_fs_mb='' volume_fs_mb='' volume_fs_inodes=''
flags=()
while IFS= read -r line; do
  key="${line%%=*}" val="${line#*=}"
  case "$key" in
    release) release="$val" ;;
    runtime) runtime="$val" ;;
    url) url="$val" ;;
    sha512) sha512="$val" ;;
    install_dir) install_dir="$val" ;;
    log_dir) log_dir="$val" ;;
    trace_fs_mb) trace_fs_mb="$val" ;;
    volume_fs_mb) volume_fs_mb="$val" ;;
    volume_fs_inodes) volume_fs_inodes="$val" ;;
    flag) flags+=("$val") ;;
    *) nothing "unexpected plan line" ;;
  esac
done <<<"$plan_out"
[[ "$release" =~ ^[0-9]{8}\.[0-9]+$ && "$sha512" =~ ^[0-9a-f]{128}$ && "$runtime" = runsc ]] || nothing "the plan is incomplete"
[[ "$install_dir" =~ ^/[A-Za-z0-9/_.-]+$ && "$log_dir" =~ ^/[A-Za-z0-9/_.-]+$ ]] || nothing "the plan's folders are not plain absolute paths"
[ "${#flags[@]}" -gt 0 ] || nothing "the plan has no runsc flags"
[[ "$trace_fs_mb" =~ ^[0-9]{3,5}$ ]] || nothing "the plan has no trace filesystem size"
[[ "$volume_fs_mb" =~ ^[0-9]{4,5}$ && "$volume_fs_inodes" =~ ^[0-9]{5,8}$ ]] || nothing "the plan has no volume filesystem size"

prefix="${RUNSC_PREFIX:-}"
dest_root="$prefix$install_dir"
dest="$dest_root/$release"
bin_dir="$prefix/usr/local/bin"

tmp="$(mktemp -d)"
stage=''
cleanup() { rm -rf "$tmp"; [ -z "$stage" ] || rm -rf "$stage"; }
trap cleanup EXIT

# 2. The bundle, and its checksum.
bundle="$tmp/gvisor.tar.bz2"
if [ -n "${RUNSC_BUNDLE:-}" ]; then
  cp "$RUNSC_BUNDLE" "$bundle" || nothing "the local bundle could not be read"
else
  curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --max-time 600 -o "$bundle" "$url" || nothing "the gVisor download failed"
fi
if command -v sha512sum >/dev/null; then got="$(sha512sum "$bundle")"; else got="$(shasum -a 512 "$bundle")"; fi
got="${got%% *}"
[ "$got" = "$sha512" ] || nothing "gVisor bundle checksum mismatch (want the sha512 pinned in gvisor.json for $release)"

# 3. Only the expected names, as listed, and then as unpacked.
names="$(tar -tjf "$bundle")" || nothing "the bundle is not a readable tar.bz2"
while IFS= read -r n; do
  n="${n#./}"
  [ -z "$n" ] && continue
  [[ "$n" =~ ^(runsc|containerd-shim-runsc-v1|gvisor-bin/?|gvisor-bin/[A-Za-z0-9_.-]+)$ ]] && [[ "$n" != *..* ]] \
    || nothing "unexpected entry in the gVisor bundle"
done <<<"$names"
mkdir "$tmp/x"
tar -xjf "$bundle" -C "$tmp/x" --no-same-owner --no-same-permissions || nothing "the bundle did not unpack"
odd="$(cd "$tmp/x" && find . -mindepth 1 \( -type d ! -path ./gvisor-bin \) -o \( ! -type d ! -type f \) -o \( -type f ! -path ./runsc ! -path ./containerd-shim-runsc-v1 ! -path './gvisor-bin/*' \))"
[ -z "$odd" ] || nothing "unexpected entry in the gVisor bundle after unpacking"
for f in runsc containerd-shim-runsc-v1; do
  [ -f "$tmp/x/$f" ] && [ ! -L "$tmp/x/$f" ] || nothing "the bundle has no $f"
done
chmod -R u=rwX,go=rX "$tmp/x"
chmod 0755 "$tmp/x/runsc" "$tmp/x/containerd-shim-runsc-v1"
[ ! -d "$tmp/x/gvisor-bin" ] || find "$tmp/x/gvisor-bin" -type f -exec chmod 0755 {} +

# 4. Unpacked under its release, swapped in whole.
mkdir -p "$dest_root" "$bin_dir"
chmod 0755 "$dest_root"
stage="$(mktemp -d "$dest_root/.stage.XXXXXX")"
cp -R "$tmp/x/." "$stage/"
chmod 0755 "$stage"
rm -rf "$dest"
mv "$stage" "$dest"
stage=''
ln -sfn "$release" "$dest_root/current"
ln -sfn "$install_dir/$release/runsc" "$bin_dir/runsc"
ln -sfn "$install_dir/$release/containerd-shim-runsc-v1" "$bin_dir/containerd-shim-runsc-v1"

# 5. The trace folder, on a filesystem of its own of a fixed size.
mkdir -p "$prefix$log_dir"
if [ -z "$prefix" ]; then
  for c in fallocate mkfs.ext4 mount mountpoint; do command -v "$c" >/dev/null || fail "$c not found"; done
  img="$install_dir/trace-fs.img"
  if ! mountpoint -q "$log_dir"; then
    rm -f "$img"
    fallocate -l "${trace_fs_mb}M" "$img" || fail "the trace filesystem could not be made"
    chmod 0600 "$img"
    mkfs.ext4 -q -F -m 0 "$img" >/dev/null || fail "the trace filesystem could not be formatted"
    mount -o loop,nosuid,nodev,noexec "$img" "$log_dir" || fail "the trace filesystem could not be mounted"
  fi
  mountpoint -q "$log_dir" || fail "the trace folder is not its own filesystem"
fi
chmod 0750 "$prefix$log_dir"
if [ -n "${SUDO_GID:-}" ] && [[ "$SUDO_GID" =~ ^[0-9]+$ ]]; then
  chgrp "$SUDO_GID" "$prefix$log_dir"
  chmod g+s "$prefix$log_dir"
fi

echo "gVisor $release installed: $install_dir/$release, traces in $log_dir (${trace_fs_mb} MB of their own)"

# 6. The Docker runtime.
if [ -n "${RUNSC_SKIP_DAEMON:-}" ]; then
  echo "runtime not registered (RUNSC_SKIP_DAEMON)"
  exit 0
fi
[ -z "$prefix" ] || fail "RUNSC_PREFIX is for the tests; it cannot register a runtime"
command -v docker >/dev/null || fail "docker not found"

# 5b. Docker's volumes, on a filesystem of their own of a fixed size and inode count. Mounted while
# the daemon is stopped (it keeps its volume database in that folder), and only before any volume
# exists: the step 6 restart below brings the daemon back on it.
docker_root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null)" || docker_root=''
[[ "$docker_root" =~ ^/[A-Za-z0-9/_.-]+$ && "$docker_root" != *..* ]] || fail "the Docker root folder could not be read"
volumes_dir="$docker_root/volumes"
if ! mountpoint -q "$volumes_dir"; then
  [ -z "$(docker volume ls -q)" ] || fail "Docker already has volumes: the volume filesystem goes in before any volume exists"
  vimg="$install_dir/volume-fs.img"
  systemctl stop docker.socket 2>/dev/null || true
  systemctl stop docker || fail "the Docker daemon did not stop"
  rm -f "$vimg"
  fallocate -l "${volume_fs_mb}M" "$vimg" || fail "the volume filesystem could not be made"
  chmod 0600 "$vimg"
  mkfs.ext4 -q -F -m 0 -N "$volume_fs_inodes" "$vimg" >/dev/null || fail "the volume filesystem could not be formatted"
  mkdir -p "$volumes_dir"
  mount -o loop,nosuid,nodev "$vimg" "$volumes_dir" || fail "the volume filesystem could not be mounted"
  chmod 0701 "$volumes_dir"
fi
mountpoint -q "$volumes_dir" || fail "Docker's volumes folder is not its own filesystem"
echo "Docker volumes in $volumes_dir: ${volume_fs_mb} MB and ${volume_fs_inodes} inodes of their own"
daemon_json=/etc/docker/daemon.json
mkdir -p /etc/docker
RUNSC_PATH="$install_dir/current/runsc" "$node_bin" -e '
  const fs = require("node:fs");
  const [file, ...flags] = process.argv.slice(1);
  let c = {};
  if (fs.existsSync(file)) c = JSON.parse(fs.readFileSync(file, "utf8") || "{}");
  if (!c || typeof c !== "object" || Array.isArray(c)) throw new Error("daemon.json is not an object");
  c.runtimes = { ...(c.runtimes || {}), runsc: { path: process.env.RUNSC_PATH, runtimeArgs: flags } };
  fs.writeFileSync(`${file}.isk-tmp`, `${JSON.stringify(c, null, 2)}\n`, { mode: 0o644 });
  fs.renameSync(`${file}.isk-tmp`, file);
' "$daemon_json" "${flags[@]}" || fail "daemon.json could not be updated"
systemctl restart docker || fail "the Docker daemon did not restart"
for _ in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker info --format '{{json .Runtimes}}' | "$node_bin" "$here/runsc-plan.mjs" --verify-runtimes "${plan_args[@]}" \
  || fail "the daemon does not have runsc with the pinned flags"
"$install_dir/current/runsc" --version | head -n 1
