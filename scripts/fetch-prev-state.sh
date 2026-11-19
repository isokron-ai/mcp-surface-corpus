#!/usr/bin/env bash
# Finds the newest unexpired `surface-state` artifact of an earlier run of this repository's main
# branch and puts its one file at $RUNNER_TEMP/prev/surface-state.tgz.age. No artifact is not an
# error: the first run has nothing to compare with. Needs GH_TOKEN with actions: read; reads no
# other secret. The file is ciphertext; only the next step, which holds the key, can read it.
set -euo pipefail
d="$RUNNER_TEMP/prev"
rm -rf "$d"
mkdir -p "$d"
id=$(gh api "repos/${GITHUB_REPOSITORY:?}/actions/artifacts?name=surface-state&per_page=30" \
  --jq "[.artifacts[] | select(.expired == false and .workflow_run.head_branch == \"main\" and .workflow_run.head_repository_id == .workflow_run.repository_id and (.workflow_run.id | tostring) != \"${GITHUB_RUN_ID:?}\")] | sort_by(.created_at) | last | .id // empty" 2>/dev/null || true)
if ! [[ "$id" =~ ^[0-9]+$ ]]; then
  echo "no previous state"
  exit 0
fi
gh api "repos/$GITHUB_REPOSITORY/actions/artifacts/$id/zip" > "$d/prev.zip" 2>/dev/null || { echo "no previous state"; rm -f "$d/prev.zip"; exit 0; }
# One member, by its fixed name, at most 256 MiB; anything else is ignored.
if unzip -p "$d/prev.zip" surface-state.tgz.age 2>/dev/null | head -c 268435456 > "$d/surface-state.tgz.age" && [ "$(head -c 21 "$d/surface-state.tgz.age")" = "age-encryption.org/v1" ]; then
  echo "previous state found"
else
  rm -f "$d/surface-state.tgz.age"
  echo "no previous state"
fi
rm -f "$d/prev.zip"
