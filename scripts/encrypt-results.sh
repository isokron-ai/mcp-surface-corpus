#!/usr/bin/env bash
# Packs this shard's results and encrypts them. Two files leave the job:
#   surface-shard-N.tgz.age        everything (raw transcripts, records, logs), to the archive key
#                                  in recipients.txt only: CI cannot read it back.
#   surface-shard-N-rows.tgz.age   the per-target summary rows and fingerprints (no names, no tool
#                                  text beyond tool names in the fingerprints), to the archive key AND
#                                  the public half of CORPUS_TARGETS_KEY, so the aggregate job can
#                                  add the shards up. Skipped when that public key is not there.
# Removes every clear-text file the job wrote afterwards, and checks what is left is age ciphertext.
set -euo pipefail
umask 077
c="$RUNNER_TEMP/corpus"
up="$RUNNER_TEMP/corpus-upload"
n="${SHARD:?}"
mkdir -p "$up" "$c/out/_shard"
rm -f "$c/targets.json" "$c/.id"
if [ -f "$c/public.txt" ]; then cp "$c/public.txt" "$c/out/_shard/public.txt"; fi
want=1
if [ -f "$c/ci-recipient.txt" ] && [ -f "$c/out/_shard/rows.jsonl" ]; then
  [ -f "$c/out/_shard/state.jsonl" ] || : > "$c/out/_shard/state.jsonl"
  tar -C "$c/out/_shard" -czf - rows.jsonl state.jsonl \
    | age -R recipients.txt -R "$c/ci-recipient.txt" -o "$up/surface-shard-$n-rows.tgz.age"
  want=2
fi
tar -C "$c/out" -czf - . | age -R recipients.txt -o "$up/surface-shard-$n.tgz.age"
rm -rf "$c/out" "$c/work"
# A clear-text leftover would be a leak; there must be none (the public key file and public.txt are not secrets).
[ -z "$(find "$c" -mindepth 1 ! -name public.txt ! -name ci-recipient.txt -print -quit 2>/dev/null)" ] || { echo "harness error: clear-text files left"; exit 1; }
# The upload folder holds exactly the expected files, each age ciphertext with the expected number of recipients.
ok=1
[ "$(find "$up" -mindepth 1 | wc -l)" -eq "$want" ] || ok=0
for f in "$up"/*.age; do
  [ "$(head -c 21 "$f")" = "age-encryption.org/v1" ] || ok=0
  stanzas=$(head -c 4096 "$f" | grep -ac '^-> X25519 ' || true)
  case "$f" in
    *-rows.tgz.age) [ "$stanzas" -eq 2 ] || ok=0 ;;
    *) [ "$stanzas" -eq 1 ] || ok=0 ;;
  esac
done
[ "$ok" -eq 1 ] || { echo "harness error: the upload is not the expected age ciphertext"; rm -rf "$up"; exit 1; }
