// MCP SDK detection from lockfiles, manifests and installed dependency trees.
// Every SDK name reported comes from the fixed table below, never from target text, so the public
// aggregate can carry SDK names without carrying anything a target wrote.

export const SDKS = [
  // [sdk id, ecosystem, package name]
  ['typescript-sdk', 'npm', '@modelcontextprotocol/sdk'],
  ['typescript-sdk-server', 'npm', '@modelcontextprotocol/server'],
  ['fastmcp-ts', 'npm', 'fastmcp'],
  ['mcp-framework', 'npm', 'mcp-framework'],
  ['mastra-mcp', 'npm', '@mastra/mcp'],
  ['xmcp', 'npm', 'xmcp'],
  ['mcp-handler', 'npm', 'mcp-handler'],
  ['vercel-mcp-adapter', 'npm', '@vercel/mcp-adapter'],
  ['hono-mcp', 'npm', '@hono/mcp'],
  ['mcp-lite', 'npm', 'mcp-lite'],
  ['tmcp', 'npm', 'tmcp'],
  ['mcp-nest', 'npm', '@rekog/mcp-nest'],
  ['python-sdk', 'pypi', 'mcp'],
  ['fastmcp-py', 'pypi', 'fastmcp'],
  ['fastapi-mcp', 'pypi', 'fastapi-mcp'],
  ['mcp-go', 'go', 'github.com/mark3labs/mcp-go'],
  ['go-sdk', 'go', 'github.com/modelcontextprotocol/go-sdk'],
  ['mcp-golang', 'go', 'github.com/metoro-io/mcp-golang'],
  ['rmcp', 'cargo', 'rmcp'],
  ['rust-mcp-sdk', 'cargo', 'rust-mcp-sdk'],
  ['java-sdk', 'maven', 'io.modelcontextprotocol.sdk:mcp'],
  ['csharp-sdk', 'nuget', 'ModelContextProtocol'],
];

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
const VERSION = /^v?\d+(\.\d+){0,3}([-+][\w.+-]{0,40})?$/;
const cleanVersion = (v) => (typeof v === 'string' && VERSION.test(v.trim()) ? v.trim().replace(/^v/, '') : null);

function hit(sdk, eco, pkg, version, source, kind) {
  return { sdk, ecosystem: eco, package: pkg, version: cleanVersion(version), source, kind };
}

/** Parses one file by its base name. Returns hits for every known SDK found in it. */
export function sdkFromFile(name, text) {
  const base = String(name).split('/').pop();
  const out = [];
  if (typeof text !== 'string' || !text) return out;
  const npm = SDKS.filter((s) => s[1] === 'npm');
  const py = SDKS.filter((s) => s[1] === 'pypi');
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') {
    let j; try { j = JSON.parse(text); } catch { return out; }
    for (const [sdk, eco, pkg] of npm) {
      const p = j.packages && j.packages[`node_modules/${pkg}`];
      const d = j.dependencies && j.dependencies[pkg];
      const v = (p && p.version) || (d && d.version);
      if (v) out.push(hit(sdk, eco, pkg, v, base, 'locked'));
    }
  } else if (base === 'package.json') {
    let j; try { j = JSON.parse(text); } catch { return out; }
    for (const [sdk, eco, pkg] of npm) {
      const v = (j.dependencies || {})[pkg] || (j.peerDependencies || {})[pkg] || (j.devDependencies || {})[pkg];
      if (typeof v === 'string') out.push({ ...hit(sdk, eco, pkg, null, base, 'declared'), spec: v.slice(0, 64) });
    }
  } else if (base === 'pnpm-lock.yaml' || base === 'bun.lock' || base === 'yarn.lock') {
    for (const [sdk, eco, pkg] of npm) {
      let v = null;
      if (base === 'yarn.lock') {
        const m = new RegExp(`^"?${esc(pkg)}@[^\\n]*\\n\\s+version:?\\s+"?([^"\\s]+)`, 'm').exec(text);
        if (m) v = m[1];
      } else {
        const m = new RegExp(`(?:^|[\\s'"/])${esc(pkg)}@(\\d[\\w.+-]*)`, 'm').exec(text);
        if (m) v = m[1];
      }
      if (v) out.push(hit(sdk, eco, pkg, v, base, 'locked'));
    }
  } else if (base === 'uv.lock' || base === 'poetry.lock' || base === 'pdm.lock' || base === 'Cargo.lock') {
    const list = base === 'Cargo.lock' ? SDKS.filter((s) => s[1] === 'cargo') : py;
    for (const [sdk, eco, pkg] of list) {
      const m = new RegExp(`\\[\\[package\\]\\]\\s*\\nname = "${esc(pkg)}"\\s*\\nversion = "([^"]+)"`, 'i').exec(text);
      if (m) out.push(hit(sdk, eco, pkg, m[1], base, 'locked'));
    }
  } else if (base === 'Pipfile.lock') {
    let j; try { j = JSON.parse(text); } catch { return out; }
    for (const [sdk, eco, pkg] of py) {
      const e = (j.default || {})[pkg];
      if (e && typeof e.version === 'string') out.push(hit(sdk, eco, pkg, e.version.replace(/^==/, ''), base, 'locked'));
    }
  } else if (/^requirements.*\.txt$/.test(base) || base === 'freeze.txt') {
    for (const [sdk, eco, pkg] of py) {
      const m = new RegExp(`^${esc(pkg)}(?:\\[[^\\]]*\\])?\\s*(==|>=|~=|<=|>|<)?\\s*([\\w.+-]*)`, 'mi').exec(text);
      if (m) out.push(m[1] === '==' ? hit(sdk, eco, pkg, m[2], base, 'locked') : { ...hit(sdk, eco, pkg, null, base, 'declared'), spec: `${m[1] || ''}${m[2] || ''}`.slice(0, 64) });
    }
  } else if (base === 'pyproject.toml' || base === 'setup.py' || base === 'setup.cfg') {
    for (const [sdk, eco, pkg] of py) {
      const m = new RegExp(`["'\\s]${esc(pkg)}(?:\\[[^\\]]*\\])?\\s*((?:==|>=|~=|<=|>|<)[^"',\\]\\n]*)?["',]`, 'i').exec(text);
      if (m) out.push({ ...hit(sdk, eco, pkg, null, base, 'declared'), spec: (m[1] || '').trim().slice(0, 64) });
    }
  } else if (base === 'go.mod') {
    for (const [sdk, eco, pkg] of SDKS.filter((s) => s[1] === 'go')) {
      const m = new RegExp(`(?:^|\\s)${esc(pkg)}(?:/v\\d+)?\\s+(v[\\w.+-]+)`, 'm').exec(text);
      if (m) out.push(hit(sdk, eco, pkg, m[1], base, 'locked'));
    }
  } else if (base === 'go-version-m.txt') {
    for (const [sdk, eco, pkg] of SDKS.filter((s) => s[1] === 'go')) {
      const m = new RegExp(`^\\s*(?:dep|mod)\\s+${esc(pkg)}(?:/v\\d+)?\\s+(v[\\w.+-]+)`, 'm').exec(text);
      if (m) out.push(hit(sdk, eco, pkg, m[1], base, 'installed'));
    }
  } else if (base === 'Cargo.toml') {
    for (const [sdk, eco, pkg] of SDKS.filter((s) => s[1] === 'cargo')) {
      if (new RegExp(`^\\s*${esc(pkg)}\\s*=`, 'm').test(text)) out.push(hit(sdk, eco, pkg, null, base, 'declared'));
    }
  } else if (base === 'pom.xml' || /\.gradle(\.kts)?$/.test(base)) {
    if (/io\.modelcontextprotocol\.sdk/.test(text)) out.push(hit('java-sdk', 'maven', 'io.modelcontextprotocol.sdk:mcp', null, base, 'declared'));
  } else if (/\.csproj$/.test(base)) {
    const m = /PackageReference\s+Include="ModelContextProtocol(?:\.AspNetCore)?"\s+Version="([^"]+)"/.exec(text);
    if (m) out.push(hit('csharp-sdk', 'nuget', 'ModelContextProtocol', m[1], base, 'declared'));
  }
  return out;
}

const RANK = { installed: 0, locked: 1, declared: 2 };
/** The SDK the server most likely runs on: installed > locked > declared, nearest file first (paths given in order). */
export function primarySdk(hits) {
  if (!hits.length) return null;
  const sorted = [...hits].sort((a, b) => RANK[a.kind] - RANK[b.kind] || (a.depth ?? 0) - (b.depth ?? 0));
  return sorted[0];
}

/** Major.minor of a version for public breakdowns. */
export function minor(v) {
  const m = /^(\d+)\.(\d+)/.exec(v || '');
  return m ? `${m[1]}.${m[2]}` : null;
}
