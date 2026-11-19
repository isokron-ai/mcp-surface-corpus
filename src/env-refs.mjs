// Environment variable names a server reads, from its source and README. Names only, never values.
const NAME = '[A-Z][A-Z0-9_]{1,63}';
const SOURCE_PATTERNS = [
  new RegExp(`process\\.env\\.(${NAME})\\b`, 'g'),
  new RegExp(`process\\.env\\[\\s*['"\`](${NAME})['"\`]\\s*\\]`, 'g'),
  new RegExp(`os\\.environ(?:\\.get)?\\s*[\\[(]\\s*['"](${NAME})['"]`, 'g'),
  new RegExp(`os\\.getenv\\(\\s*['"](${NAME})['"]`, 'g'),
  new RegExp(`os\\.(?:Getenv|LookupEnv)\\(\\s*"(${NAME})"`, 'g'),
  new RegExp(`env::var(?:_os)?\\(\\s*"(${NAME})"`, 'g'),
  new RegExp(`Deno\\.env\\.get\\(\\s*['"](${NAME})['"]`, 'g'),
  new RegExp(`(?:env|getEnv|requireEnv|getRequiredEnv)\\(\\s*['"](${NAME})['"]`, 'g'),
];
const IGNORE = new Set(['NODE_ENV', 'HOME', 'PATH', 'PWD', 'USER', 'SHELL', 'TERM', 'TMPDIR', 'DEBUG', 'CI', 'LANG', 'TZ', 'PORT', 'HOST', 'LOG_LEVEL', 'NODE_OPTIONS', 'PYTHONPATH', 'VIRTUAL_ENV', 'XDG_CONFIG_HOME', 'APPDATA', 'USERPROFILE']);

export function envRefsFromSource(text) {
  const out = new Set();
  for (const re of SOURCE_PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text))) if (!IGNORE.has(m[1])) out.add(m[1]);
  }
  return out;
}

/** From a README: names inside an "env": { ... } JSON block, `export NAME=`, `-e NAME=` / `--env NAME`. */
export function envRefsFromReadme(text) {
  const out = new Set();
  const blocks = text.match(/"env"\s*:\s*\{[^}]{0,4000}\}/g) || [];
  for (const b of blocks) for (const m of b.matchAll(new RegExp(`"(${NAME})"\\s*:`, 'g'))) out.add(m[1]);
  for (const m of text.matchAll(new RegExp(`(?:^|\\s)export\\s+(${NAME})=`, 'gm'))) out.add(m[1]);
  for (const m of text.matchAll(new RegExp(`(?:-e|--env)\\s+(${NAME})(?:=|\\b)`, 'g'))) out.add(m[1]);
  for (const n of IGNORE) out.delete(n);
  return out;
}

/** Names that look like credentials (for "starts without credentials" analysis). */
export const SECRET_NAME = /(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH|_PAT$|_KEY$)/;
export const isSecretName = (n) => SECRET_NAME.test(n);

/** A dummy value that never is a real credential, shaped for the name. */
export function dummyValue(name) {
  if (/(_URL|_URI|_ENDPOINT|_HOST|_BASE)$/.test(name)) return 'http://127.0.0.1:9/';
  if (/(_PORT)$/.test(name)) return '9';
  if (/(_PATH|_DIR|_FILE|_ROOT)$/.test(name)) return '/tmp/surface-dummy';
  if (/(_ENABLED|_DEBUG|_VERBOSE)$/.test(name)) return 'false';
  if (/(_EMAIL|_USER(NAME)?)$/.test(name)) return 'dummy@example.invalid';
  return 'surface-dummy-not-a-credential';
}
