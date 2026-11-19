#!/usr/bin/env bash
# Decrypts targets/targets.json.age with the CORPUS_TARGETS_KEY secret (an age identity, the whole
# AGE-SECRET-KEY-1... line), and writes that identity's PUBLIC key to ci-recipient.txt so later steps
# can encrypt the per-target summary rows for the aggregate job. The identity lives in a 0600 file
# for the length of this step only. Prints nothing about the list.
set -euo pipefail
umask 077
if [ -z "${CORPUS_TARGETS_KEY:-}" ]; then
  echo "harness error: the CORPUS_TARGETS_KEY secret is not set"
  exit 1
fi
c="$RUNNER_TEMP/corpus"
mkdir -p "$c"
k="$c/.id"
trap 'rm -f "$k"' EXIT
printf '%s\n' "$CORPUS_TARGETS_KEY" > "$k"
age-keygen -y "$k" > "$c/ci-recipient.txt" 2>/dev/null || { echo "harness error: CORPUS_TARGETS_KEY is not an age identity"; exit 1; }
[[ "$(cat "$c/ci-recipient.txt")" =~ ^age1[a-z0-9]{58}$ ]] || { echo "harness error: no public key could be derived"; exit 1; }
if [ ! -f targets/targets.json.age ]; then
  echo "harness error: targets/targets.json.age is not in the repository yet (targets/FORMAT.md)"
  exit 1
fi
age -d -i "$k" -o "$c/targets.json" targets/targets.json.age 2>/dev/null || { echo "harness error: the target list could not be decrypted"; exit 1; }
