#!/usr/bin/env bash
# Publishes the nightly conformance status (scripts/conformance-status.mjs) as the asset
# conformance-status.json of the release tagged `conformance` in this repository, replacing the last
# one. The release is made on first use: a pre-release, never "latest", so it is not mistaken for a
# version of anything. Readers fetch it without a token:
#
#   https://github.com/<repo>/releases/download/conformance/conformance-status.json
#
#   GH_TOKEN=<job token, contents: write> scripts/publish-conformance.sh STATUS.json
#
# The file must be a well-formed status (checked again here); nothing else is uploaded.
set -euo pipefail
file="${1:-}"
tag=conformance
asset=conformance-status.json
[ -n "$file" ] && [ -f "$file" ] || { echo "usage: publish-conformance.sh STATUS.json" >&2; exit 2; }
[ "$(basename "$file")" = "$asset" ] || { echo "the status file must be named $asset" >&2; exit 2; }
[[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "GITHUB_REPOSITORY is required" >&2; exit 2; }
[ "$(wc -c <"$file")" -le 4096 ] || { echo "the status file is larger than 4 KiB" >&2; exit 1; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
node --input-type=module -e '
  import { readFileSync } from "node:fs";
  const { statusProblems } = await import(process.argv[1]);
  const bad = statusProblems(JSON.parse(readFileSync(process.argv[2], "utf8")));
  if (bad.length) { console.error(`not a well-formed status: ${bad.join(", ")}`); process.exit(1); }
' "file://$here/conformance-status.mjs" "$file"

if ! gh release view "$tag" --repo "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  gh release create "$tag" --repo "$GITHUB_REPOSITORY" --target "${GITHUB_SHA:-main}" --prerelease --latest=false \
    --title "Sandbox conformance status" \
    --notes "The latest nightly sandbox conformance result (conformance-nightly.yml), as $asset. Rewritten every night; the tag itself means nothing. No secrets, no target output."
fi
gh release upload "$tag" "$file" --repo "$GITHUB_REPOSITORY" --clobber
echo "published $asset on the $tag release of $GITHUB_REPOSITORY"
