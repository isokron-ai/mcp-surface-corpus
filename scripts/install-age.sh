#!/usr/bin/env bash
# Installs age from its release tarball, checked against the pinned sha256. The pin lives here, in
# these two lines, so pin-drift.yml can propose a new one (its token cannot change workflow files).
set -euo pipefail
# age v1.3.2, linux-amd64 release tarball (sha256 recorded 16 Nov 2026).
AGE_URL=https://github.com/FiloSottile/age/releases/download/v1.3.2/age-v1.3.2-linux-amd64.tar.gz
AGE_SHA256=cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10
d="$RUNNER_TEMP/age-dl"
mkdir -p "$d"
curl -fsSL --retry 3 -o "$d/age.tgz" "$AGE_URL"
echo "$AGE_SHA256  $d/age.tgz" | sha256sum -c --quiet -
tar -xzf "$d/age.tgz" -C "$d"
echo "$d/age" >> "$GITHUB_PATH"
"$d/age/age" --version >/dev/null
