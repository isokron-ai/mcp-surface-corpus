#!/usr/bin/env bash
# seal-targets.sh: on IsoKron's own machine, checks a clear-text target list and encrypts it for the
# repository. The list is encrypted to two public keys: the archive key in recipients.txt, and the
# public half of the CI key (the CORPUS_TARGETS_KEY secret), given as a file holding one age1... line.
# No private key is read or needed.
#
#   bin/seal-targets.sh <targets.json> <ci-recipient-file> [--out targets/targets.json.age]
#
# The public half of the CI key: `age-keygen -y <CI identity file>` prints it. Keep the clear-text
# list out of the repository (.gitignore refuses targets/*.json except the example).
set -euo pipefail
umask 077
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
src="${1:-}"; ci="${2:-}"; out="$here/targets/targets.json.age"
if [ "${3:-}" = "--out" ]; then out="${4:?--out needs a path}"; fi
[ -f "$src" ] && [ -f "$ci" ] || { echo "usage: seal-targets.sh <targets.json> <ci-recipient-file> [--out FILE]" >&2; exit 2; }
grep -Eq '^age1[a-z0-9]{58}$' "$ci" || { echo "seal-targets: $ci holds no age1... public key" >&2; exit 1; }
if grep -q 'AGE-SECRET-KEY' "$ci" "$src"; then echo "seal-targets: a private key is in one of the files; refusing" >&2; exit 1; fi
node --input-type=module -e '
import { readFileSync } from "node:fs";
import { validateList } from "'"$here"'/src/targets.mjs";
const l = validateList(JSON.parse(readFileSync(process.argv[1], "utf8")));
const k = {}; for (const t of l.targets) { const x = t.launch ? t.launch.kind : "static only"; k[x] = (k[x] || 0) + 1; }
console.log(`seal-targets: ${l.targets.length} target(s) valid: ${Object.entries(k).map(([a, b]) => `${b} ${a}`).join(", ")}`);
' "$src"
tmp="$out.tmp.$$"
age -R "$here/recipients.txt" -R "$ci" -o "$tmp" "$src"
[ "$(head -c 4096 "$tmp" | grep -ac '^-> X25519 ')" -eq 2 ] || { rm -f "$tmp"; echo "seal-targets: expected two recipients" >&2; exit 1; }
mv "$tmp" "$out"
echo "seal-targets: wrote $out ($(wc -c < "$out" | tr -d ' ') bytes). Commit that file; never the clear-text list."
