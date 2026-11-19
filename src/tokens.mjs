// Token estimates for a tools/list payload. None of these is an exact tokenizer; each is labelled.
//   bytes_div_4      the checker engine's own estimate (weight.approxTokens)
//   bpe_approx       a cl100k/o200k-style pre-tokenizer split, each piece costed by length
//                    (letters: 1 token per ~4 chars after the first 6; digits: 1 per 3; punctuation runs: 1 per 2)
//   claude_approx    characters / 3.3, a rough Claude-family rate for JSON-heavy text
// Exact counts (tiktoken o200k_base, Anthropic count_tokens) can be added offline on the Mac from the
// raw transcripts in the bundle; the record keeps the exact bytes they would be computed from.
const PRE = /'(?:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+/gu;

export function bpeApprox(text) {
  let n = 0;
  for (const m of text.matchAll(PRE)) {
    const p = m[0];
    if (/\p{L}/u.test(p)) n += p.length <= 7 ? 1 : 1 + Math.ceil((p.length - 7) / 4);
    else if (/\p{N}/u.test(p)) n += 1;
    else if (/^\s+$/.test(p)) n += 1;
    else n += Math.ceil(p.trim().length / 2) || 1;
  }
  return n;
}

export function estimate(text) {
  const bytes = Buffer.byteLength(text);
  return { bytes, chars: text.length, bytes_div_4: Math.round(bytes / 4), bpe_approx: bpeApprox(text), claude_approx: Math.round(text.length / 3.3) };
}
