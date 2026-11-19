// Layer (d): tool names (and a one-line description) from a README. Fidelity "names": no schema.
const TOOLISH = /^[A-Za-z_][A-Za-z0-9_.-]{1,63}$/;
const HEAD = /^(#{1,6})\s+(.*)$/;
const SECTION = /\b(tools?|available tools|tool list|functions|commands|capabilities|features|api)\b/i;
const looksLikeTool = (n) => TOOLISH.test(n) && (/[_.-]/.test(n) || /[a-z][A-Z]/.test(n) || /^[a-z]+$/.test(n));

export function extractReadme(md) {
  const lines = String(md).split(/\r?\n/);
  const out = [];
  const seen = new Set();
  let inSection = false; let level = 0; let fence = false;
  const add = (name, description, line) => {
    name = name.replace(/\(\)$/, '');
    if (!looksLikeTool(name) || seen.has(name)) return;
    seen.add(name);
    const t = { name };
    if (description) t.description = description.replace(/\s+/g, ' ').trim().slice(0, 1000);
    out.push({ tool: t, fidelity: 'names', line });
  };
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    if (/^\s*(```|~~~)/.test(l)) { fence = !fence; continue; }
    if (fence) continue;
    const h = HEAD.exec(l);
    if (h) {
      const lv = h[1].length;
      const text = h[2].trim();
      if (inSection && lv > level) {
        const m = /^`([^`]+)`\s*(?:[-:–—]\s*(.*))?$/.exec(text) || /^\*{0,2}([A-Za-z_][\w.-]+)\*{0,2}\s*(?:[-:–—]\s*(.*))?$/.exec(text);
        if (m) {
          let desc = m[2] || '';
          for (let j = i + 1; !desc && j < lines.length && j < i + 6; j++) { const t = lines[j].trim(); if (t && !HEAD.test(t) && !/^[-*|`]/.test(t)) desc = t; }
          add(m[1], desc, i + 1);
        }
        continue;
      }
      if (inSection && lv <= level) inSection = false;
      if (SECTION.test(text)) { inSection = true; level = lv; }
      continue;
    }
    if (!inSection) continue;
    let m = /^\s*[-*+]\s+(?:\*\*|`)+([^*`]+?)(?:\*\*|`)+\s*(?:\([^)]*\))?\s*[-:–—]?\s*(.*)$/.exec(l);
    if (m) { add(m[1].trim(), m[2], i + 1); continue; }
    m = /^\s*\|\s*`?([A-Za-z_][\w.-]+)`?\s*\|\s*([^|]*)\|/.exec(l);
    if (m && !/^-+$/.test(m[1]) && !/^(name|tool|function|command)$/i.test(m[1])) { add(m[1], m[2], i + 1); continue; }
  }
  return out;
}

/** Commands a README documents for starting the server (npx/uvx/docker/go run), for target discovery. */
export function documentedCommands(md) {
  const out = new Set();
  const re = /\b(npx\s+(?:-y\s+)?@?[\w./-]+(?:@[\w.-]+)?|uvx\s+[\w.-]+(?:==[\w.]+)?|docker\s+run\s+[^\n`"]{0,200}|go\s+run\s+[\w./@-]+)/g;
  for (const m of String(md).matchAll(re)) out.add(m[1].replace(/\s+/g, ' ').trim().slice(0, 240));
  return [...out].slice(0, 20);
}
