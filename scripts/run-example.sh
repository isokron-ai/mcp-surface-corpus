#!/usr/bin/env bash
# The whole pipeline on the public example list (targets/example.targets.json), with no secret:
# the driver in real containers, the encryption step, and the aggregate. Where the corpus workflow
# uses CORPUS_TARGETS_KEY, this uses an age identity made on the spot and thrown away, so the same
# scripts run and the encrypt-then-decrypt round trip is exercised. The example's targets are named
# in the repository, so its aggregate is public as it is (--example: cells are not withheld).
#
#   RUNNER_TEMP=/some/empty/dir scripts/run-example.sh
#
# Leaves $RUNNER_TEMP/example/public/{aggregate.json,calibration.md} and, encrypted,
# $RUNNER_TEMP/corpus-upload/. Fails if a server did not give a live tool list (s004's needs its
# native module built in the sandbox).
set -euo pipefail
umask 077
: "${RUNNER_TEMP:?set RUNNER_TEMP to an empty working folder}"
c="$RUNNER_TEMP/corpus"
e="$RUNNER_TEMP/example"
rm -rf "$c" "$e" "$RUNNER_TEMP/corpus-upload"
mkdir -p "$c" "$e/rows"
export GITHUB_OUTPUT="${GITHUB_OUTPUT:-$e/github-output.txt}"
cp targets/example.targets.json "$c/targets.json"
age-keygen -o "$e/ephemeral.key" 2>/dev/null
age-keygen -y "$e/ephemeral.key" > "$c/ci-recipient.txt"
SHARD=1 SURFACE_SHARDS=1 scripts/run-ci-shard.sh
SHARD=1 scripts/encrypt-results.sh
age -d -i "$e/ephemeral.key" "$RUNNER_TEMP/corpus-upload/surface-shard-1-rows.tgz.age" | tar -xzf - -C "$e/rows" rows.jsonl state.jsonl
rm -f "$e/ephemeral.key"
node bin/aggregate.mjs --rows "$e/rows/rows.jsonl" --state "$e/rows/state.jsonl" --shards 1 \
  --public "$e/public" --private "$e/private" --min-cell 1 --example >/dev/null
node scripts/check-example.mjs "$e/rows/rows.jsonl" "$e/public/aggregate.json"
