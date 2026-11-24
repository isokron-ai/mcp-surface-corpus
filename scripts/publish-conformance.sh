#!/usr/bin/env bash
# Publishes the nightly conformance status (scripts/conformance-status.mjs) as the asset
# conformance-status.json of the release tagged `conformance` in this repository. The release is
# made on first use: a pre-release, never "latest", so it is not mistaken for a version of anything.
# Readers fetch it without a token:
#
#   https://github.com/<repo>/releases/download/conformance/conformance-status.json
#
#   GH_TOKEN=<job token, contents: write> scripts/publish-conformance.sh STATUS.json
#
# Before replacing anything it refuses (exit 1, nothing uploaded):
#   - a file that is not a well-formed status;
#   - a status that does not supersede the one published (conformance-status.mjs supersedes: a
#     later run, or a later attempt of the same run, with evidence no older), so a re-run of an
#     older night never puts its green back over a newer red.
# A green status whose sandbox_sha is not main's head now (main moved during the run, or a re-run of
# an old night tested an old commit) is published as not ok, result `main_moved`
# (conformance-status.mjs forMain): it says nothing about main, and publishing nothing would leave
# an older green up. A red status is published whatever main's head.
set -euo pipefail
file="${1:-}"
tag=conformance
asset=conformance-status.json
[ -n "$file" ] && [ -f "$file" ] || { echo "usage: publish-conformance.sh STATUS.json" >&2; exit 2; }
[ "$(basename "$file")" = "$asset" ] || { echo "the status file must be named $asset" >&2; exit 2; }
[[ "${GITHUB_REPOSITORY:-}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo "GITHUB_REPOSITORY is required" >&2; exit 2; }
[ "$(wc -c <"$file")" -le 4096 ] || { echo "the status file is larger than 4 KiB" >&2; exit 1; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Well formed, before anything is asked of GitHub.
node --input-type=module -e '
  import { readFileSync } from "node:fs";
  const { statusProblems } = await import(process.argv[1]);
  let s = null;
  try { s = JSON.parse(readFileSync(process.argv[2], "utf8")); } catch { /* reported below */ }
  const bad = statusProblems(s);
  if (bad.length) { console.error(`not a well-formed status: ${bad.join(", ")}`); process.exit(1); }
' "file://$here/conformance-status.mjs" "$file"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Main's head now, and the published status if there is one.
head="$(gh api "repos/$GITHUB_REPOSITORY/commits/main" --jq .sha)"
[[ "$head" =~ ^[0-9a-f]{40}$ ]] || { echo "could not read main's head" >&2; exit 1; }
release=false
if gh release view "$tag" --repo "$GITHUB_REPOSITORY" --json assets --jq '.assets[].name' >"$work/assets" 2>/dev/null; then
  release=true
  if grep -qx "$asset" "$work/assets"; then
    mkdir "$work/prev"
    gh release download "$tag" --repo "$GITHUB_REPOSITORY" --pattern "$asset" --dir "$work/prev"
  fi
fi

node --input-type=module -e '
  import { readFileSync, existsSync, writeFileSync } from "node:fs";
  const { forMain, supersedes } = await import(process.argv[1]);
  const [, , file, prevFile, head] = process.argv;
  const m = forMain(JSON.parse(readFileSync(file, "utf8")), head);
  const next = m.status;
  console.log(m.why);
  writeFileSync(file, `${JSON.stringify(next, null, 2)}\n`);
  let prev = null;
  if (existsSync(prevFile)) { try { prev = JSON.parse(readFileSync(prevFile, "utf8")); } catch { prev = null; } }
  const s = supersedes(next, prev);
  if (!s.ok) { console.error(`refused: ${s.why}`); process.exit(1); }
  console.log(`publishing: ${s.why}`);
' "file://$here/conformance-status.mjs" "$file" "$work/prev/$asset" "$head"

if [ "$release" != true ]; then
  gh release create "$tag" --repo "$GITHUB_REPOSITORY" --target "$head" --prerelease --latest=false \
    --title "Sandbox conformance status" \
    --notes "The latest nightly sandbox conformance result (conformance-nightly.yml), as $asset. Rewritten every night; the tag itself means nothing. No secrets, no target output."
fi
gh release upload "$tag" "$file" --repo "$GITHUB_REPOSITORY" --clobber
echo "published $asset on the $tag release of $GITHUB_REPOSITORY"
