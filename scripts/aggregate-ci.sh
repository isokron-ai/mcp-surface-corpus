#!/usr/bin/env bash
# The aggregate job's one step with the key. Reads the shards' row bundles (downloaded into
# $RUNNER_TEMP/shards), decrypts them with CORPUS_TARGETS_KEY, adds them up with bin/aggregate.mjs,
# and leaves:
#   $RUNNER_TEMP/aggregate-public/    aggregate.json, calibration.md   (public: disclosure rules applied)
#   $RUNNER_TEMP/aggregate-private/   surface-aggregate-private.tgz.age  (archive key only)
#   $RUNNER_TEMP/aggregate-state/     surface-state.tgz.age             (archive key + CI key: the next run's diff)
# Every clear-text row is removed before the step ends. Prints nothing about targets.
set -euo pipefail
umask 077
if [ -z "${CORPUS_TARGETS_KEY:-}" ]; then
  echo "harness error: the CORPUS_TARGETS_KEY secret is not set"
  exit 1
fi
w="$RUNNER_TEMP/aggregate-work"
pub="$RUNNER_TEMP/aggregate-public"
priv="$RUNNER_TEMP/aggregate-private"
st="$RUNNER_TEMP/aggregate-state"
rm -rf "$w" "$pub" "$priv" "$st"
mkdir -p "$w/rows" "$w/private" "$pub" "$priv" "$st"
k="$w/.id"
trap 'rm -rf "$w"' EXIT
printf '%s\n' "$CORPUS_TARGETS_KEY" > "$k"
age-keygen -y "$k" > "$w/ci-recipient.txt" 2>/dev/null || { echo "harness error: CORPUS_TARGETS_KEY is not an age identity"; exit 1; }

args=()
found=0
while IFS= read -r f; do
  n=$(basename "$f" -rows.tgz.age)
  [[ "$n" =~ ^surface-shard-[0-9]{1,2}$ ]] || continue
  mkdir -p "$w/rows/$n"
  if age -d -i "$k" "$f" 2>/dev/null | tar -xzf - -C "$w/rows/$n" rows.jsonl state.jsonl 2>/dev/null; then
    args+=(--rows "$w/rows/$n/rows.jsonl" --state "$w/rows/$n/state.jsonl")
    found=$((found + 1))
  else
    echo "harness error: a shard's rows could not be read"
  fi
done < <(find "$RUNNER_TEMP/shards" -name 'surface-shard-*-rows.tgz.age' -type f | sort)
if [ "$found" -eq 0 ]; then
  echo "harness error: no shard rows to aggregate"
  exit 1
fi
prev=()
if [ -f "$RUNNER_TEMP/prev/surface-state.tgz.age" ]; then
  mkdir -p "$w/prev"
  if age -d -i "$k" "$RUNNER_TEMP/prev/surface-state.tgz.age" 2>/dev/null | tar -xzf - -C "$w/prev" state.jsonl 2>/dev/null; then
    prev=(--prev-state "$w/prev/state.jsonl")
  fi
fi
rm -f "$k"
partial=()
if [ -n "${ONLY_IN:-}" ]; then partial=(--partial); fi
node bin/aggregate.mjs "${args[@]}" "${prev[@]}" "${partial[@]}" --shards "$found" --public "$pub" --private "$w/private" >/dev/null
tar -C "$w/private" -czf - . | age -R recipients.txt -o "$priv/surface-aggregate-private.tgz.age"
tar -C "$w/private" -czf - state.jsonl | age -R recipients.txt -R "$w/ci-recipient.txt" -o "$st/surface-state.tgz.age"
for f in "$priv/surface-aggregate-private.tgz.age" "$st/surface-state.tgz.age"; do
  [ "$(head -c 21 "$f")" = "age-encryption.org/v1" ] || { echo "harness error: an output is not age ciphertext"; rm -rf "$priv" "$st"; exit 1; }
done
# The public folder holds exactly the two public files.
[ "$(find "$pub" -mindepth 1 | wc -l)" -eq 2 ] && [ -f "$pub/aggregate.json" ] && [ -f "$pub/calibration.md" ] || { echo "harness error: unexpected public output"; rm -rf "$pub"; exit 1; }
echo "aggregated $found shard(s)"
