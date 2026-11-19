// IsoKron MCP check, version 2: pure logic. No DOM, no network, no storage.
// Runs in the browser (global McpCheck) and in Node (require('./core.js')), so the same engine can back a CLI or a CI action.
//
// What it judges, from a pasted tools/list answer only:
//   spec      MCP specification 2026-07-28 rules a tool list can decide
//   anthropic Anthropic connector pre-submission checklist
//   openai    OpenAI plugin guidelines (MCP tool rules)
//   security  hidden characters and poisoning patterns, over every string in each tool
//   quality   schema and description quality (design advice, not directory rules)
//   surface   write-surface design (what the list offers a caller for safe writes)
//   mws       MWS-ANN-4 records only, with no total and no grade (MWS 0.9, section 5.2)
// The rubric is in RUBRIC.md; RUBRIC_VERSION below must match it.

(function (root, factory) {
  const api = factory(root);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.McpCheck = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
  'use strict';

  const RUBRIC_VERSION = '2.1.0';
  const REPORT_SCHEMA = 'isokron-mcp-check-report/2';
  const SPEC_VERSION = '2026-07-28';
  const SOURCES_READ = '2026-11-18';
  const DOCS_BASE = 'https://isokron.ai/mcp-check/checks/';

  // ---------------------------------------------------------------- sources

  const SRC = {
    specTools: { title: 'MCP specification 2026-07-28: Tools', url: 'https://modelcontextprotocol.io/specification/2026-07-28/server/tools' },
    specBasic: { title: 'MCP specification 2026-07-28: Overview (JSON Schema usage, _meta, icons)', url: 'https://modelcontextprotocol.io/specification/2026-07-28/basic/index' },
    specSchema: { title: 'MCP schema.ts, revision 2026-07-28', url: 'https://github.com/modelcontextprotocol/modelcontextprotocol/blob/main/schema/2026-07-28/schema.ts' },
    specHttp: { title: 'MCP specification 2026-07-28: Streamable HTTP transport', url: 'https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http' },
    specChangelog: { title: 'MCP specification 2026-07-28: Key changes', url: 'https://modelcontextprotocol.io/specification/2026-07-28/changelog' },
    anthropic: { title: 'Anthropic connector pre-submission checklist', url: 'https://claude.com/docs/connectors/building/review-criteria' },
    openai: { title: 'OpenAI plugin guidelines', url: 'https://developers.openai.com/plugins/plugin-guidelines' },
    openaiMeta: { title: 'OpenAI: Optimize metadata', url: 'https://developers.openai.com/plugins/guides/optimize-metadata' },
    owasp: { title: 'OWASP MCP Security Cheat Sheet', url: 'https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html' },
    anthropicTools: { title: 'Anthropic: Writing effective tools for agents', url: 'https://www.anthropic.com/engineering/writing-tools-for-agents' },
    mws: { title: 'MCP Write-Safety Requirements 0.9', url: 'https://isokron.ai/mws' },
  };

  // ---------------------------------------------------------------- check registry
  // Each check: id (stable, kebab-case, also the docs slug), section, affects (graded sections it counts in),
  // severity (default; a finding may carry a different one, noted in `severities`), title, src, anchor, quote (verbatim,
  // one sentence), explain (plain language), fix (what to do), example {bad, good} where useful.

  const C = [];
  const def = (o) => { C.push(o); return o; };

  // --- MCP specification 2026-07-28
  def({ id: 'spec-tool-shape', section: 'spec', affects: ['spec'], severity: 'blocking', title: 'Every list entry is a tool object with a name', src: 'specTools', anchor: '',
    quote: 'Each tool is uniquely identified by a name and includes metadata describing its schema.',
    explain: 'An entry that is not an object, or has no string name, cannot be called. Clients drop it or fail on the whole list.',
    fix: 'Give every entry a string "name", or remove the entry.' });
  def({ id: 'spec-input-schema-missing', section: 'spec', affects: ['spec'], severity: 'blocking', title: 'inputSchema is present', src: 'specTools', anchor: '#tool',
    quote: 'MUST be a valid JSON Schema object (not `null`)',
    explain: 'inputSchema is a required field of a tool. Without it, clients cannot build or validate the arguments.',
    fix: 'Add an inputSchema. A tool with no arguments uses {"type": "object", "additionalProperties": false}.',
    example: { bad: '{ "name": "get_time", "description": "Returns the server time." }', good: '{ "name": "get_time", "description": "Returns the server time.", "inputSchema": { "type": "object", "additionalProperties": false } }' } });
  def({ id: 'spec-input-schema-field-name', section: 'spec', affects: ['spec'], severity: 'attention', title: 'The schema field is named inputSchema', src: 'specTools', anchor: '#tool',
    quote: 'MUST be a valid JSON Schema object (not `null`)',
    explain: 'The tool uses input_schema, the spelling of some model APIs. MCP clients read inputSchema, so they see no schema. If you pasted a converted list, ignore this item.',
    fix: 'Rename input_schema to inputSchema in what the server returns from tools/list.' });
  def({ id: 'spec-input-schema-root-object', section: 'spec', affects: ['spec'], severity: 'blocking', title: 'inputSchema has type "object" at the root', src: 'specSchema', anchor: '',
    quote: 'Tool arguments are always JSON objects, so `type: "object"` is required at the root.',
    explain: 'Tool arguments are always one JSON object. A schema whose root is not type "object" does not match the protocol type and clients may reject the tool.',
    fix: 'Set "type": "object" at the root of inputSchema and declare arguments under "properties".',
    example: { bad: '"inputSchema": { "properties": { "id": { "type": "string" } } }', good: '"inputSchema": { "type": "object", "properties": { "id": { "type": "string" } } }' } });
  def({ id: 'spec-schema-valid', section: 'spec', affects: ['spec'], severity: 'blocking', title: 'inputSchema and outputSchema are valid JSON Schema', src: 'specBasic', anchor: '#schema-validation',
    quote: 'Schemas MUST be valid according to their declared or default dialect',
    explain: 'The schema is checked against the JSON Schema 2020-12 meta-schema, and every local $ref and every regular expression in "pattern" must resolve or compile. An invalid schema makes argument validation fail or behave unpredictably.',
    fix: 'Correct the keyword named in the message. Common causes: a misspelled type name, "required" that is not an array of strings, a broken $ref pointer, or a regular expression that does not compile.' });
  def({ id: 'spec-schema-dialect', section: 'spec', affects: ['spec'], severity: 'attention', title: 'Schemas use JSON Schema 2020-12', src: 'specBasic', anchor: '#schema-dialect',
    quote: 'Implementations MUST support at least 2020-12 and SHOULD document which additional dialects they support',
    explain: 'The schema declares another dialect with $schema. Clients only have to support 2020-12, so a client may answer that the dialect is not supported. This check validated the schema structurally only.',
    fix: 'Remove $schema (2020-12 is the default) or set it to https://json-schema.org/draft/2020-12/schema, and adjust keywords that changed (for example items arrays become prefixItems).' });
  def({ id: 'spec-ref-remote', section: 'spec', affects: ['spec'], severity: 'attention', title: 'No $ref to a network or external URI', src: 'specBasic', anchor: '#ref-resolution',
    quote: 'Implementations MUST NOT automatically dereference `$ref` values that resolve to a network URI.',
    explain: 'Clients will not fetch the referenced schema, and the specification says schemas that fail on an unresolved external $ref SHOULD be rejected. The tool may be dropped or its arguments left unchecked.',
    fix: 'Inline the referenced schema under $defs and point the $ref at "#/$defs/<name>".' });
  def({ id: 'spec-composition-bounds', section: 'spec', affects: ['spec'], severity: 'attention', title: 'Schema depth and size stay within common validator bounds', src: 'specBasic', anchor: '#composition-keyword-resource-use',
    quote: 'Implementations SHOULD apply reasonable bounds, such as a maximum schema depth, a cap on the total number of subschemas, or a per-validation time budget, to prevent a malicious schema from acting as a Denial-of-Service vector against the validator.',
    explain: 'Clients are told to cap schema depth and subschema count, so a very deep or very large schema risks being refused. The thresholds used here (depth over 10, more than 500 subschemas) are IsoKron\'s, since the specification sets no numbers.',
    fix: 'Flatten nested composition, move repeated parts into $defs, or split the tool.' });
  def({ id: 'spec-name-length', section: 'spec', affects: ['spec'], severity: 'attention', title: 'Tool name is 1 to 128 characters', src: 'specTools', anchor: '#tool-names',
    quote: 'Tool names SHOULD be between 1 and 128 characters in length (inclusive).',
    explain: 'Names outside this range may be refused or cut by clients.',
    fix: 'Shorten the name. The Anthropic directory also requires 64 characters or fewer.' });
  def({ id: 'spec-name-charset', section: 'spec', affects: ['spec'], severity: 'attention', title: 'Tool name uses only A-Z, a-z, 0-9, _, - and .', src: 'specTools', anchor: '#tool-names',
    quote: 'The following SHOULD be the only allowed characters: uppercase and lowercase ASCII letters (A-Z, a-z), digits (0-9), underscore (_), hyphen (-), and dot (.)',
    explain: 'Spaces, commas, slashes and non-ASCII letters break clients that build identifiers from tool names, and non-ASCII letters can imitate other names.',
    fix: 'Replace other characters with underscores, for example "create issue" becomes "create_issue".' });
  def({ id: 'spec-name-unique', section: 'spec', affects: ['spec'], severity: 'attention', title: 'Tool names are unique within the server', src: 'specTools', anchor: '#tool-names',
    quote: 'Tool names SHOULD be unique within a server.',
    explain: 'With two tools of the same name, a call can reach either one. Clients keep one and drop the other.',
    fix: 'Rename one of the tools, or remove the duplicate.' });
  def({ id: 'spec-x-mcp-header', section: 'spec', affects: ['spec'], severity: 'blocking', title: 'x-mcp-header values follow the rules', src: 'specTools', anchor: '#x-mcp-header',
    quote: 'Clients using the Streamable HTTP transport MUST reject tool definitions where any `x-mcp-header` value violates these constraints.',
    explain: 'A tool with an invalid x-mcp-header is left out of tools/list by every conforming HTTP client, with at most a log line, so the tool silently disappears. Values must be non-empty RFC 9110 tokens, unique ignoring case, on string, integer or boolean properties (not number) reached from the root through "properties" only.',
    fix: 'Fix the value named in the message: use a token such as "Region", put it on a string, integer or boolean property directly under "properties", and give each header a different name.',
    example: { bad: '"amount": { "type": "number", "x-mcp-header": "Amount" }', good: '"region": { "type": "string", "x-mcp-header": "Region" }' } });
  def({ id: 'spec-x-mcp-header-sensitive', section: 'spec', affects: ['spec', 'security'], severity: 'attention', title: 'No x-mcp-header on secrets or personal data', src: 'specTools', anchor: '#x-mcp-header',
    quote: 'Server developers SHOULD NOT mark sensitive parameters (passwords, API keys, tokens, PII) with `x-mcp-header`, as header values are visible to network intermediaries.',
    explain: 'Header values are seen and often logged by load balancers, proxies and firewalls.',
    fix: 'Remove x-mcp-header from this property. Mirror only routing values such as a region or tenant.' });
  def({ id: 'spec-field-types', section: 'spec', affects: ['spec'], severity: 'blocking', title: 'Tool fields have the types the schema defines', src: 'specSchema', anchor: '',
    quote: 'readOnlyHint?: boolean;',
    explain: 'schema.ts defines the type of every tool field: name, title and description are strings, annotations is an object of boolean hints plus a string title, outputSchema and _meta are objects, icons is an array. A string "true" is not a boolean, and clients that check types drop or misread the field.',
    fix: 'Use the type named in the message, for example "readOnlyHint": true, not "readOnlyHint": "true".' });
  def({ id: 'spec-annotation-key-case', section: 'spec', affects: ['spec'], severity: 'attention', title: 'Annotation hints use the spec\'s key names', src: 'specSchema', anchor: '',
    quote: 'destructiveHint?: boolean;',
    explain: 'ToolAnnotations defines readOnlyHint, destructiveHint, idempotentHint and openWorldHint, in camelCase. A key such as destructive_hint is not one of them: clients ignore it and apply the default instead (readOnlyHint false, destructiveHint true, idempotentHint false, openWorldHint true), so the hint the author meant never reaches them. The Python SDK (mcp 1.x) produces exactly this when ToolAnnotations is given snake_case arguments, because it keeps unknown fields as extras.',
    fix: 'Use the spec\'s key name, for example ToolAnnotations(destructiveHint=True) in the Python SDK, so the list carries "destructiveHint": true.',
    example: { bad: '"annotations": { "destructive_hint": true, "read_only_hint": false }', good: '"annotations": { "destructiveHint": true, "readOnlyHint": false }' } });
  def({ id: 'spec-icon-scheme', section: 'spec', affects: ['spec'], severity: 'attention', title: 'Icon sources are https: or data: URIs', src: 'specBasic', anchor: '#icons',
    quote: 'Clients MUST reject icon URIs that use unsafe schemes and redirects, such as `javascript:`, `file:`, `ftp:`, `ws:`, or local app URI schemes.',
    explain: 'Icons with other schemes are rejected, so the tool shows without its icon. The same section asks consumers to ensure the URI is either HTTPS or data:.',
    fix: 'Serve the icon over https from the server\'s own origin, or inline it as a data: URI.' });
  def({ id: 'spec-meta-key', section: 'spec', affects: ['spec'], severity: 'attention', title: '_meta keys follow the key-name grammar', src: 'specBasic', anchor: '#_meta',
    quote: 'Labels MUST start with a letter and end with a letter or digit; interior characters can be letters, digits, or hyphens (`-`).',
    explain: 'A _meta key is an optional prefix (dot-separated labels, then a slash) and a name that begins and ends with a letter or digit. Keys outside the grammar may be ignored or rejected.',
    fix: 'Rename the key, for example "com.example/feature-flag".' });
  def({ id: 'spec-meta-reserved', section: 'spec', affects: ['spec'], severity: 'advice', title: '_meta keys avoid prefixes reserved for MCP', src: 'specBasic', anchor: '#_meta',
    quote: 'Any prefix where the second label is `modelcontextprotocol` or `mcp` is **reserved** for MCP use.',
    explain: 'Keys under a reserved prefix are only for the specification and official extensions. If this key is not defined by one of them, it collides with the protocol\'s own namespace.',
    fix: 'Use your own reverse-DNS prefix, for example "com.example/".' });
  def({ id: 'spec-envelope-result-type', section: 'spec', affects: ['spec'], severity: 'attention', severities: ['blocking', 'advice'], title: 'The tools/list result carries resultType', src: 'specSchema', anchor: '',
    quote: 'Servers implementing this protocol version MUST include this field.',
    explain: 'Revision 2026-07-28 adds a required resultType to every result ("complete" for tools/list). Clients treat a missing value as "complete" from older servers. It is attention when the answer otherwise looks like 2026-07-28, advice when it looks older, and blocking when the value is not "complete".',
    fix: 'Add "resultType": "complete" to the tools/list result.' });
  def({ id: 'spec-envelope-cache', section: 'spec', affects: ['spec'], severity: 'attention', severities: ['blocking', 'advice'], title: 'The tools/list result carries ttlMs and cacheScope', src: 'specChangelog', anchor: '',
    quote: 'Require `ttlMs` and `cacheScope` fields on results returned by `tools/list`, `prompts/list`, `resources/list`, `resources/read`, and `resources/templates/list` via a new `CacheableResult` interface.',
    explain: 'ttlMs (a number of at least 0) says how long a client may cache the list; cacheScope ("public" or "private") says whether shared caches may reuse it. A missing pair is a gap for a 2026-07-28 server; a wrong value is an error for any server that sends it.',
    fix: 'Add "ttlMs": 300000 and "cacheScope": "private" (use "public" only if the list is the same for every user).' });
  def({ id: 'spec-pagination-partial', section: 'spec', affects: ['spec'], severity: 'advice', title: 'The paste holds the whole tool list', src: 'specTools', anchor: '#listing-tools',
    quote: 'This operation supports pagination and caching.',
    explain: 'The answer carries a nextCursor, so it is one page. Tools on later pages were not checked, and the duplicate-name checks only see this page.',
    fix: 'Fetch every page and paste them together as a JSON array of the answers; the checker merges them.' });
  def({ id: 'spec-execution-legacy', section: 'spec', affects: ['spec'], severity: 'advice', title: 'No tool-level execution field from 2025-11-25', src: 'specChangelog', anchor: '',
    quote: 'Move experimental tasks out of the core protocol and into an official extension (`io.modelcontextprotocol/tasks`).',
    explain: 'The tool carries the 2025-11-25 "execution" field (task support). In 2026-07-28 tasks are an extension, so clients on the new revision ignore this field.',
    fix: 'Keep the field while you serve 2025-11-25 clients; for 2026-07-28 declare task support through the io.modelcontextprotocol/tasks extension.' });

  // --- Anthropic connector checklist
  const A_HINT_QUOTE = 'Every tool must include a `title` and the applicable hint: `readOnlyHint: true` for read-only tools, and `destructiveHint: true` for tools that modify or delete data.';
  def({ id: 'anthropic-title', section: 'anthropic', affects: ['anthropic'], severity: 'blocking', title: 'Every tool has a title', src: 'anthropic', anchor: '#provide-tool-annotations', quote: A_HINT_QUOTE,
    explain: 'The title is the name people see in Claude. Either the top-level "title" or "annotations.title" counts.',
    fix: 'Add a short, human-readable "title", for example "Create issue".',
    example: { bad: '{ "name": "create_issue", ... }', good: '{ "name": "create_issue", "title": "Create issue", ... }' } });
  def({ id: 'anthropic-hint', section: 'anthropic', affects: ['anthropic'], severity: 'blocking', title: 'Every tool carries the applicable hint', src: 'anthropic', anchor: '#provide-tool-annotations', quote: A_HINT_QUOTE,
    explain: 'The tool sets neither readOnlyHint: true nor destructiveHint at all. These hints decide auto-permissions in Claude: read-only tools run without per-call confirmation and destructive tools always prompt. If destructiveHint is absent the specification\'s default is true, but the checklist asks for the hint to be stated.',
    fix: 'Set "readOnlyHint": true on tools that only read. On tools that change data set "readOnlyHint": false and an explicit "destructiveHint".',
    example: { bad: '"annotations": { "openWorldHint": false }', good: '"annotations": { "readOnlyHint": false, "destructiveHint": true, "openWorldHint": false }' } });
  def({ id: 'anthropic-hint-platforms-differ', section: 'anthropic', affects: ['anthropic'], severity: 'attention', title: 'destructiveHint: false on a write: the platforms word this differently', src: 'anthropic', anchor: '#provide-tool-annotations', quote: A_HINT_QUOTE,
    explain: 'This write tool sets destructiveHint: false. OpenAI says false is right for "additive writes without destructive or irreversible effects". Anthropic\'s checklist asks for destructiveHint: true on "tools that modify or delete data", and does not say whether a pure create counts as modifying. Neither text settles it, so this is not graded as blocking. If the tool can overwrite, cancel, revoke or send something irreversible, it is destructive on both platforms.',
    fix: 'Keep destructiveHint: false only if the tool purely adds (a new record, a new comment) and cannot overwrite or delete. Otherwise set it to true. If a reviewer asks, the OpenAI wording supports false for additive writes.' });
  def({ id: 'anthropic-name-length', section: 'anthropic', affects: ['anthropic'], severity: 'blocking', title: 'Tool name is 64 characters or fewer', src: 'anthropic', anchor: '#keep-tool-names-short',
    quote: 'Tool names must be 64 characters or fewer.',
    explain: 'The Anthropic directory limit is half the specification\'s 128.',
    fix: 'Shorten the name to 64 characters or fewer.' });
  def({ id: 'anthropic-read-write-split', section: 'anthropic', affects: ['anthropic'], severity: 'blocking', title: 'Reads and writes are separate tools', src: 'anthropic', anchor: '#separate-read-and-write-tools',
    quote: 'A single tool that accepts both safe HTTP methods, such as GET, HEAD, and OPTIONS, and unsafe methods, such as POST, PUT, PATCH, and DELETE, is rejected.',
    explain: 'A tool that takes the HTTP method as an argument can both read and write, so neither hint can be true for it. The checklist rejects a catch-all api_request tool with a method parameter; documenting safe and unsafe uses in the description does not satisfy it.',
    fix: 'Split it into a read-only tool (GET) and write tools, ideally one per action: create, update, delete.',
    example: { bad: '{ "name": "api_request", "inputSchema": { "type": "object", "properties": { "method": { "enum": ["GET", "POST", "DELETE"] }, "path": { "type": "string" } } } }', good: '{ "name": "api_get", ... "readOnlyHint": true }  { "name": "api_create", ... }  { "name": "api_delete", ... "destructiveHint": true }' } });
  def({ id: 'anthropic-api-docs', section: 'anthropic', affects: ['anthropic'], severity: 'blocking', title: 'Custom query tools name or link the target API', src: 'anthropic', anchor: '#reference-api-docs-in-custom-query-tools',
    quote: 'If a tool accepts freeform endpoint paths, query strings, or request bodies that the caller constructs, its description must include a link to or the explicit name of the target API.',
    explain: 'The tool takes a free-form path, endpoint, request body or query language (SQL, GraphQL and similar), and its description neither links nor names the API. The checklist gives "Makes a request to the API" as a description that fails.',
    fix: 'Name and link the API in the description, for example "Queries the Slack Web API, see https://api.slack.com/methods".' });
  def({ id: 'anthropic-description', section: 'anthropic', affects: ['anthropic'], severity: 'blocking', severities: ['attention'], title: 'Description says what the tool does and when to use it', src: 'anthropic', anchor: '#write-narrow-accurate-descriptions',
    quote: 'Each tool description should state precisely what the tool does and when to invoke it.',
    explain: 'A missing description is blocking. A very short one (under 40 characters) rarely says both what the tool does and when to call it, and is marked for attention.',
    fix: 'Write one or two sentences: what the tool does, what it returns, and when to call it.' });
  def({ id: 'anthropic-conversation-data', section: 'anthropic', affects: ['anthropic'], severity: 'blocking', title: 'No inputs for memory, chat history or conversation data', src: 'anthropic', anchor: '#functional-quality',
    quote: 'Don’t query Claude’s memory, chat history, conversation summaries, or user files',
    explain: 'An argument named for conversation history, transcripts, memory or conversation summaries asks Claude to hand over context the tool does not need.',
    fix: 'Remove the argument. If the tool needs the user\'s intent, take a short task-specific field instead.' });
  def({ id: 'anthropic-unsupported-use', section: 'anthropic', affects: ['anthropic'], severity: 'attention', title: 'Not an unsupported use case (money transfer, AI media generation)', src: 'anthropic', anchor: '#unsupported-use-cases',
    quote: 'Connectors that do the following aren’t accepted: Transfer money, cryptocurrency, or other financial assets; Generate images, video, or audio through AI models',
    explain: 'The name or description suggests moving money or crypto, or generating images, video or audio with AI. The directory does not accept these use cases at all. Diagrams, charts and UI mockups are allowed. This is a word match, so check it.',
    fix: 'If the tool does this, it cannot be listed in the Anthropic directory. If it does not, reword the description so it is not mistaken for it.' });

  // --- OpenAI plugin guidelines
  def({ id: 'openai-hints-explicit', section: 'openai', affects: ['openai'], severity: 'blocking', title: 'readOnlyHint, destructiveHint and openWorldHint are explicit booleans', src: 'openai', anchor: '',
    quote: 'Set readOnlyHint, destructiveHint, and openWorldHint to the appropriate explicit boolean values (true or false) in each tool’s annotations object.',
    explain: 'OpenAI requires all three hints on every tool, even where the specification has a default.',
    fix: 'Add every missing hint with an explicit true or false.',
    example: { bad: '"annotations": { "readOnlyHint": true }', good: '"annotations": { "readOnlyHint": true, "destructiveHint": false, "openWorldHint": false }' } });
  def({ id: 'openai-description', section: 'openai', affects: ['openai'], severity: 'blocking', title: 'Every tool has a non-empty description', src: 'openai', anchor: '',
    quote: 'Each tool must have a nonempty description that explicitly and accurately explains its purpose and behavior, when to use it, and any relevant limitations or side effects.',
    explain: 'A tool with no description gives the model nothing to choose it by, and reviewers reject it.',
    fix: 'Describe the purpose, behavior, when to use it, and limitations or side effects.' });
  def({ id: 'openai-name-unique', section: 'openai', affects: ['openai'], severity: 'blocking', title: 'Tool names are unique within the server', src: 'openai', anchor: '',
    quote: 'Tool names must be unique within your MCP server.',
    explain: 'OpenAI makes uniqueness a requirement (the MCP specification says SHOULD).',
    fix: 'Rename or remove the duplicate tools.' });
  def({ id: 'openai-name-promotional', section: 'openai', affects: ['openai'], severity: 'attention', title: 'Tool name has no promotional or comparative words', src: 'openai', anchor: '',
    quote: 'Avoid misleading, overly promotional, or comparative language (for example, pick_me, best, official).',
    explain: 'Words such as best, official or recommended in a tool name try to win selection instead of describing the action.',
    fix: 'Name the action plainly, ideally as a verb, for example get_order_status.' });
  def({ id: 'openai-name-opaque', section: 'openai', affects: ['openai'], severity: 'advice', title: 'Tool name is not an opaque identifier', src: 'openai', anchor: '',
    quote: 'Avoid internal jargon, unexplained acronyms, and opaque identifiers.',
    explain: 'Names like op_17, fn2 or a hex id tell neither the model nor a reviewer what the tool does.',
    fix: 'Use a plain verb and object, for example list_invoices.' });
  def({ id: 'openai-retry', section: 'openai', affects: ['openai'], severity: 'attention', title: 'Write tools say whether a retry repeats the effect', src: 'openai', anchor: '',
    quote: 'Tools should be safe to retry where possible, or explicitly indicate when retries may cause repeated effects.',
    explain: 'The write tool neither declares idempotentHint: true nor mentions retries, duplicates or idempotency in its description. A model that loses the answer will often call again.',
    fix: 'Make the tool safe to repeat (for example with an idempotency key) and say so, or state in the description that a repeated call repeats the effect.' });
  def({ id: 'openai-conversation-input', section: 'openai', affects: ['openai'], severity: 'blocking', severities: ['attention'], title: 'No conversation history or "just in case" context inputs', src: 'openai', anchor: '',
    quote: 'Do not request or reconstruct full conversation histories or collect broad context “just in case.”',
    explain: 'Arguments named for conversation history, transcripts or prior turns are blocking. Generic "messages", "history" or "context" arguments are marked for attention, since they may be legitimate task data.',
    fix: 'Remove the field. Use only chat context the client or model supplies explicitly, and keep any free-text input specific to the task.' });
  def({ id: 'openai-restricted-input', section: 'openai', affects: ['openai', 'security'], severity: 'blocking', severities: ['attention'], title: 'No credential, payment card or government ID inputs', src: 'openai', anchor: '',
    quote: 'Access credentials and authentication secrets (such as API keys, MFA/OTP codes, or passwords).',
    explain: 'OpenAI lists these under Restricted Data that plugins must not collect, solicit or process, next to payment card data and government identifiers. An argument named password, api_key, otp, card_number or ssn asks the model to pass one through the chat. Boolean flags such as hide_secret or withCredentials are not inputs of this kind. A bare "token" argument is marked for attention, since it may be a pagination token.',
    fix: 'Take credentials through the server\'s own authorization (OAuth) instead of tool arguments, and remove the field.' });
  def({ id: 'openai-precise-location', section: 'openai', affects: ['openai'], severity: 'blocking', severities: ['attention'], title: 'No precise location inputs', src: 'openai', anchor: '',
    quote: 'When location is needed, rely on system-shared coarse location. Do not request precise user location.',
    explain: 'Coordinate fields (latitude, longitude, gps) carry a precise location and are blocking. Street address, postal code and location fields are marked for attention: a user\'s own address is a precise location, but a field that is not the user\'s location (a shipping destination, a store) may be fine if the description says so. City-level fields are coarse and are not flagged.',
    fix: 'Use the coarse location the platform shares. If an address is task data, not the user\'s location, say that in the field\'s description.' });
  def({ id: 'openai-generic-executor', section: 'openai', affects: ['openai'], severity: 'blocking', title: 'No generic executor or operation dispatcher', src: 'openai', anchor: '',
    quote: 'Do not use discovery, operation selection, or schema fetching with a generic executor to enable operations not individually exposed for review.',
    explain: 'A tool that runs an operation, tool or command named in an argument hides those operations from review and from the hints.',
    fix: 'Expose each operation as its own tool with its own schema and annotations.' });
  def({ id: 'openai-readonly-starts-job', section: 'openai', affects: ['openai'], severity: 'attention', title: 'Tools that start jobs or queue work are not read-only', src: 'openai', anchor: '',
    quote: 'Use false for external-state changes, persisting artifacts, starting stateful jobs or workflows, queuing work, or write-style outbound actions such as posting messages, sending emails, or uploading files.',
    explain: 'The name reads as starting, running, scheduling or queueing something, but the tool sets readOnlyHint: true.',
    fix: 'Set "readOnlyHint": false and choose destructiveHint for what the job does.' });
  def({ id: 'openai-readonly-destructive', section: 'openai', affects: ['openai'], severity: 'attention', title: 'Read-only tools set destructiveHint: false', src: 'openai', anchor: '',
    quote: 'destructiveHint: Use false for read-only tools.',
    explain: 'The tool sets both readOnlyHint: true and destructiveHint: true, which contradict each other. The specification ignores destructiveHint on read-only tools, but OpenAI asks for false.',
    fix: 'Set "destructiveHint": false, or set readOnlyHint to false if the tool does change data.' });
  def({ id: 'annot-delete-marked-safe', section: 'annotations', affects: ['anthropic', 'openai'], severity: 'blocking', title: 'Deleting tools are not marked non-destructive', src: 'openai', anchor: '',
    quote: 'For writes, use true for potentially destructive or irreversible effects, such as deletion, overwriting, cancellation, access revocation, or irreversible sends or transactions.',
    explain: 'The name reads as deleting, overwriting, cancelling, revoking or resetting, but the tool sets destructiveHint: false, so Claude would not prompt before calling it. Both platforms ask for true here; OpenAI adds that being able to undo the action does not justify false. The name match is a heuristic.',
    fix: 'Set "destructiveHint": true.',
    example: { bad: '{ "name": "delete_issue", "annotations": { "readOnlyHint": false, "destructiveHint": false } }', good: '{ "name": "delete_issue", "annotations": { "readOnlyHint": false, "destructiveHint": true } }' } });
  def({ id: 'annot-write-marked-readonly', section: 'annotations', affects: ['anthropic', 'openai'], severity: 'attention', title: 'Tools named as writes are not marked read-only', src: 'openai', anchor: '',
    quote: 'readOnlyHint: Use true for retrieval, computation, or previews that do not modify the environment.',
    explain: 'The name reads as a create, update or delete, but the tool sets readOnlyHint: true, so Claude would run it without asking. Reviewers check that hints match behavior; MWS-ANN-1 tests it against a live server.',
    fix: 'Set "readOnlyHint": false and an explicit destructiveHint, unless the tool only previews.' });

  // --- Security: hidden characters and poisoning, over every string in the tool
  const A_INJ = 'anthropic';
  def({ id: 'sec-invisible-encoding', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'blocking', title: 'No invisible Unicode tag or variation-selector characters', src: A_INJ, anchor: '#avoid-prompt-injection-patterns',
    quote: 'Contain hidden, obfuscated, or encoded instructions',
    explain: 'Unicode tag characters (U+E0000 to U+E007F) and supplementary variation selectors (U+E0100 to U+E01EF) do not render, yet models read them. They are the standard way to smuggle hidden instructions into a description. The message shows the hidden text where it decodes to ASCII.',
    fix: 'Remove the characters. "Copy fixed tool list" strips them.' });
  def({ id: 'sec-bidi-controls', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'blocking', title: 'No bidirectional override characters', src: 'openai', anchor: '',
    quote: 'Encoded or obfuscated instructions do not exempt a plugin from these requirements.',
    explain: 'Bidirectional embedding, override and isolate controls (U+202A to U+202E, U+2066 to U+2069) make text display in a different order than a model reads it, so a reviewer sees one thing and the model another.',
    fix: 'Remove the characters. "Copy fixed tool list" strips them.' });
  def({ id: 'sec-zero-width', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'attention', title: 'No zero-width or other invisible characters', src: 'owasp', anchor: '',
    quote: 'Treat the entire tool schema as a potential injection surface — not just the description field.',
    explain: 'Zero-width spaces and joiners, soft hyphens, word joiners and direction marks are invisible. Often they come from copy and paste, but they can also split keywords to slip past filters.',
    fix: 'Remove the characters. "Copy fixed tool list" strips them.' });
  def({ id: 'sec-control-chars', section: 'security', affects: ['security'], severity: 'attention', title: 'No control characters in metadata', src: 'owasp', anchor: '',
    quote: 'Treat the entire tool schema as a potential injection surface — not just the description field.',
    explain: 'Control characters other than tab, line feed and carriage return have no place in tool metadata and can hide or reorder text in logs and terminals.',
    fix: 'Remove the characters. "Copy fixed tool list" strips them.' });
  def({ id: 'sec-homoglyph', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'blocking', severities: ['attention'], title: 'No look-alike letters from other scripts', src: 'openai', anchor: '',
    quote: 'Plugin and tool metadata must not seek secrets or protected context, direct unauthorized data transfers or actions, override platform instructions or safeguards, conceal behavior, or impersonate another party.',
    explain: 'A tool name with non-ASCII letters (for example a Cyrillic "а" in "reаd_file") can impersonate another tool. In a name this is blocking; a word that mixes Latin with Cyrillic or Greek letters in a title or description is marked for attention.',
    fix: 'Use plain ASCII letters in names, and one script per word elsewhere.' });
  def({ id: 'sec-html-comment', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'blocking', title: 'No HTML comments in metadata', src: A_INJ, anchor: '#avoid-prompt-injection-patterns',
    quote: 'Contain hidden, obfuscated, or encoded instructions',
    explain: 'An HTML comment is hidden wherever the description is rendered as HTML or Markdown, but the model reads it.',
    fix: 'Remove the comment. Anything the model should know belongs in visible text.' });
  def({ id: 'sec-instruction-markup', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'blocking', title: 'No prompt markup such as <IMPORTANT> or <system>', src: A_INJ, anchor: '#avoid-prompt-injection-patterns',
    quote: 'Describe what the tool does, and don’t tell Claude how to behave.',
    explain: 'Tags such as <IMPORTANT>, <system> or <instructions>, and chat-template tokens such as [INST] or <|im_start|>, are how published tool-poisoning attacks address the model directly.',
    fix: 'Remove the markup and describe only what the tool does.' });
  def({ id: 'sec-instruction-phrases', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'blocking', title: 'No wording that overrides instructions or hides actions from the user', src: A_INJ, anchor: '#avoid-prompt-injection-patterns',
    quote: 'Tell Claude to behave in ways unrelated to the tool’s function, attempt to override system instructions, or promote products and services',
    explain: 'Phrases such as "ignore previous instructions", "do not tell the user" or "without asking the user" are instructions to the model, not a description of the tool.',
    fix: 'Rewrite the text to describe what the tool does and returns.' });
  def({ id: 'sec-cross-tool-steering', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'attention', severities: ['blocking'], title: 'No steering of when other tools are used', src: 'openai', anchor: '',
    quote: 'Plugins must not manipulate how the model selects or uses other plugins or their tools (for example, instructing the model to prefer one plugin over others), interfere with fair discovery, or otherwise negatively impact ChatGPT or our users.',
    explain: 'Wording such as "always call this tool first", "before using any other tool" or "never use other tools" interferes with other tools and is blocking; Anthropic also rejects descriptions that "interfere with Claude calling other tools". Softer wording such as "use this instead of X" is marked for attention. Routing between tools of the same server ("call get_issue first", "prefer this tool over search_issues" when search_issues is in the same list) and ordering inside the server ("call this first to get the instance name") are fine.',
    fix: 'Say what this tool is for and what it is not for, without directing the model away from other tools.' });
  def({ id: 'sec-encoded-blob', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'attention', severities: ['blocking'], title: 'No encoded text blocks in metadata', src: 'openai', anchor: '',
    quote: 'Encoded or obfuscated instructions do not exempt a plugin from these requirements.',
    explain: 'A long base64 or hex run in a description is unreadable to a reviewer but not to a model. If it decodes to readable text it is blocking, and the message shows the decoded start.',
    fix: 'Remove the encoded block. Put examples in plain text.' });
  def({ id: 'sec-external-instructions', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'blocking', title: 'No instructions fetched from outside sources', src: A_INJ, anchor: '#avoid-prompt-injection-patterns',
    quote: 'Direct Claude to pull behavioral instructions from external sources',
    explain: 'The text tells the model to fetch or follow instructions or rules from a URL or another outside source, which lets their author change the model\'s behavior after review.',
    fix: 'Put everything the model needs in the description itself.' });
  def({ id: 'sec-secret-seeking', section: 'security', affects: ['security', 'anthropic', 'openai'], severity: 'blocking', title: 'Metadata does not seek secrets or local files', src: 'openai', anchor: '',
    quote: 'Plugin and tool metadata must not seek secrets or protected context, direct unauthorized data transfers or actions, override platform instructions or safeguards, conceal behavior, or impersonate another party.',
    explain: 'The text names SSH keys, .env files, cloud credential files, MCP client configuration, or asks the model to send credentials or conversation content somewhere.',
    fix: 'Remove the wording. A tool should never ask the model for secrets it holds or can reach.' });

  // --- Schema and description quality (design grade only)
  def({ id: 'schema-param-description', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Every argument has a description', src: 'openaiMeta', anchor: '',
    quote: 'Parameter docs: describe each argument, include examples, and use allowed values for constrained inputs.',
    explain: 'Without a description the model guesses an argument\'s meaning and format from its name.',
    fix: 'Add a "description" to each argument, with an example value where the format matters.' });
  def({ id: 'schema-enum-missing', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Constrained arguments list their allowed values', src: 'openaiMeta', anchor: '',
    quote: 'Parameter docs: describe each argument, include examples, and use allowed values for constrained inputs.',
    explain: 'Arguments such as state, status, type, sort or order almost always take a fixed set of values. Without an enum the model invents values the server then rejects.',
    fix: 'Add "enum" with the allowed values.',
    example: { bad: '"state": { "type": "string" }', good: '"state": { "type": "string", "enum": ["open", "closed"] }' } });
  def({ id: 'schema-required-unknown', section: 'quality', affects: ['quality'], severity: 'attention', severities: ['blocking'], title: 'Every required argument is declared', src: 'anthropicTools', anchor: '',
    quote: 'Avoid ambiguity by clearly describing (and enforcing with strict data models) expected inputs and outputs.',
    explain: 'A name listed in "required" is missing from "properties", so the model has no type or description for it. With "additionalProperties": false the tool cannot be called at all, which is blocking.',
    fix: 'Declare the argument under "properties", or remove it from "required".' });
  def({ id: 'schema-additional-properties', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Unknown arguments are rejected', src: 'owasp', anchor: '',
    quote: 'Use strict JSON Schema for tool parameters: set additionalProperties: false and use pattern (or similar) on string fields so only declared parameters and valid formats are accepted.',
    explain: 'Without additionalProperties: false a misspelled argument is silently ignored, and the call may succeed doing something other than intended (MWS-IN tests this against a server).',
    fix: 'Add "additionalProperties": false at the root of inputSchema, and make the server reject unknown arguments.' });
  def({ id: 'schema-vague-param', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Argument names are specific', src: 'anthropicTools', anchor: '',
    quote: 'In particular, input parameters should be unambiguously named: instead of a parameter named user, try a parameter named user_id.',
    explain: 'Names such as id, user, data, value or payload leave the model to guess which object or format is meant, especially across tools.',
    fix: 'Rename to say what it is, for example issue_id or user_email.' });
  def({ id: 'schema-pagination', section: 'quality', affects: ['quality'], severity: 'advice', title: 'List and search tools take a limit or cursor', src: 'anthropicTools', anchor: '',
    quote: 'We suggest implementing some combination of pagination, range selection, filtering, and/or truncation with sensible default parameter values for any tool responses that could use up lots of context.',
    explain: 'A list or search tool with no limit, page size or cursor can return more than fits in the model\'s context.',
    fix: 'Add "limit" (with a default and a maximum) and "cursor" arguments, and return a next cursor.' });
  def({ id: 'schema-response-format', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Search tools can return a concise answer', src: 'anthropicTools', anchor: '',
    quote: 'You can enable both by exposing a simple response_format enum parameter in your tool, allowing your agent to control whether tools return “concise” or “detailed” responses',
    explain: 'Search results are often large. A response_format (or fields) argument lets the model ask for less.',
    fix: 'Add "response_format": { "type": "string", "enum": ["concise", "detailed"], "default": "concise" }.' });
  def({ id: 'schema-output-schema', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Read tools declare an outputSchema', src: 'specTools', anchor: '#output-schema',
    quote: 'Tools may also provide an output schema for validation of structured results.',
    explain: 'An outputSchema lets clients validate results and tells the model which fields come back, for example the version an update needs.',
    fix: 'Add an "outputSchema" and return matching "structuredContent".' });
  def({ id: 'schema-oneof-branch-types', section: 'quality', affects: ['quality'], severity: 'attention', title: 'Composition branches carry presence rules, not types', src: 'specSchema', anchor: '',
    quote: 'A subschema that fails on a type error is indistinguishable from one that does not apply, so type constraints placed inside `oneOf` branches are not enforced for whichever branch does not match.',
    explain: 'A oneOf or anyOf branch at the root declares property types. The specification advises declaring "properties" at the root and keeping branches to "required" lists.',
    fix: 'Move the property definitions to the root "properties" and leave only "required" in each branch.' });
  def({ id: 'schema-open-object', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Object arguments declare their fields', src: 'anthropicTools', anchor: '',
    quote: 'Avoid ambiguity by clearly describing (and enforcing with strict data models) expected inputs and outputs.',
    explain: 'An argument of type object with no "properties" accepts anything, so the model must guess the shape.',
    fix: 'Declare the object\'s "properties" (and "required"), or split it into named arguments.' });
  def({ id: 'design-use-when', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Description says when to use the tool', src: 'openaiMeta', anchor: '',
    quote: 'Description: start with “Use this when…” and call out disallowed cases (“Do not use for reminders”).',
    explain: 'The description says what the tool does but not when to choose it over its siblings.',
    fix: 'Add a sentence such as "Use this when ... Do not use for ...".' });
  def({ id: 'design-near-duplicate', section: 'quality', affects: ['quality'], severity: 'attention', title: 'Sibling tools have distinguishable descriptions', src: 'anthropic', anchor: '#write-narrow-accurate-descriptions',
    quote: 'Each tool description should state precisely what the tool does and when to invoke it.',
    explain: 'Two tools have nearly the same description (word overlap of 85% or more), so the model cannot tell when to pick which.',
    fix: 'Say in each description what sets it apart from the other.' });
  def({ id: 'design-namespace', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Larger catalogs use a naming prefix', src: 'anthropicTools', anchor: '',
    quote: 'Namespacing (grouping related tools under common prefixes) can help delineate boundaries between lots of tools; MCP clients sometimes do this by default.',
    explain: 'The catalog has 10 or more tools and no shared service or resource word in their names, so they are easy to confuse with other servers\' tools.',
    fix: 'Prefix names by service or resource, for example asana_search and asana_projects_search.' });
  def({ id: 'design-handle-lifetime', section: 'quality', affects: ['quality'], severity: 'advice', title: 'Tools that create state say how long it lasts', src: 'specTools', anchor: '#stateful-tools',
    quote: 'Because handles outlive any single connection, the server\'s retention policy should be stated in the creation tool\'s description (e.g., "baskets expire after 24 hours of inactivity") so the model can see it when deciding to create state.',
    explain: 'The tool creates a session, cart, context or similar handle, but its description does not say when it expires.',
    fix: 'Add the lifetime, for example "Sessions expire after 30 minutes without a call."' });

  // --- Write-surface design (findings feed the surface table; the surface grade comes from the tallies)
  def({ id: 'surface-retry-key', section: 'surface', affects: ['surface'], severity: 'attention', title: 'Create and send tools take a retry key', src: 'mws', anchor: '#mws-retry-1',
    quote: 'A create tool whose repeated call would create a second object SHOULD accept an idempotency key from the caller.',
    explain: 'If the answer to a create is lost, the model retries and creates a duplicate. An idempotency key lets the server recognise the repeat. idempotentHint: true is counted as declared, not shown: only a test (MWS-RETRY) can confirm it.',
    fix: 'Add an "idempotency_key" string argument and have the server return the first result for a repeated key.',
    example: { bad: '"properties": { "project": {...}, "title": {...} }', good: '"properties": { "project": {...}, "title": {...}, "idempotency_key": { "type": "string", "description": "Client-chosen key; a repeat call with the same key returns the first result instead of creating a duplicate." } }' } });
  def({ id: 'surface-version-guard', section: 'surface', affects: ['surface'], severity: 'attention', title: 'Update and delete tools take a version or precondition', src: 'mws', anchor: '#mws-conc-2',
    quote: 'A tool that replaces a whole object, deletes an object or accepts a version MUST refuse the write with a conflict when the object has changed since the state the caller read, wherever the backend can detect the change.',
    explain: 'Without an expected version (an ETag, revision or updated_at), a write based on stale data replaces another writer\'s change. An x-mcp-header named If-Match counts as a version argument.',
    fix: 'Add an "expected_version" argument (or if_match), refuse with a conflict when it no longer matches, and return the version from read tools.' });
  def({ id: 'surface-delete-guard', section: 'surface', affects: ['surface'], severity: 'advice', title: 'Delete tools take a confirm or dry-run argument', src: 'openai', anchor: '',
    quote: 'Annotations inform client safeguards; they do not grant permission or replace authentication, authorization and scope checks, input validation, or human confirmation for irreversible operations.',
    explain: 'A dry_run or confirm argument lets the model preview what a delete will remove before it is irreversible. This is a design prompt from the tool list, not a test.',
    fix: 'Add "dry_run": { "type": "boolean", "default": true } and return what would be deleted.' });
  def({ id: 'surface-full-replace', section: 'surface', affects: ['surface'], severity: 'advice', title: 'Updates send the change, not the whole object', src: 'mws', anchor: '#mws-conc-2',
    quote: 'A tool that replaces a whole object, deletes an object or accepts a version MUST refuse the write with a conflict when the object has changed since the state the caller read, wherever the backend can detect the change.',
    explain: 'The tool reads as a full replacement (replace, overwrite or put) and takes no field mask, so every field the caller sends overwrites what is stored, including fields it did not mean to change.',
    fix: 'Offer a field-patch update that changes only the fields named, or take an update_mask, and require a version on full replacements.' });
  def({ id: 'surface-bulk-delete', section: 'surface', affects: ['surface'], severity: 'attention', title: 'Bulk deletes have a guard', src: 'mws', anchor: '#mws-tgt-2',
    quote: 'A tool that deletes or bulk-updates MUST NOT treat an empty, missing or match-all selector, or the path of a container, as selecting every object in the container or collection unless the caller sets an explicit argument that opts in.',
    explain: 'The delete tool takes an array or filter of targets and has no dry-run or confirm argument, so one wrong selector removes many objects.',
    fix: 'Add a dry-run argument, refuse an empty or match-all selector unless an explicit opt-in is set, and cap the number of items per call.' });

  // OpenAI numbered its guidelines on 18 November 2026; each OpenAI-sourced check names the section its quote is in.
  const OPENAI_SECTION = {
    'openai-hints-explicit': '6.3', 'openai-description': '6.1', 'openai-name-unique': '6.1', 'openai-name-promotional': '6.1', 'openai-name-opaque': '6.1',
    'openai-retry': '1.2', 'openai-conversation-input': '6.4', 'openai-restricted-input': '4.2', 'openai-precise-location': '6.4', 'openai-generic-executor': '6.2',
    'openai-readonly-starts-job': '6.3', 'openai-readonly-destructive': '6.3', 'annot-delete-marked-safe': '6.3', 'annot-write-marked-readonly': '6.3',
    'sec-bidi-controls': '3.3', 'sec-homoglyph': '3.3', 'sec-cross-tool-steering': '3.4', 'sec-encoded-blob': '3.3', 'sec-secret-seeking': '3.3', 'surface-delete-guard': '6.3',
  };
  const CHECKS = C.map((c) => Object.assign({}, c, { source: SRC[c.src].url + (c.anchor || ''), sourceTitle: SRC[c.src].title + (c.src === 'openai' && OPENAI_SECTION[c.id] ? ', section ' + OPENAI_SECTION[c.id] : ''), docs: DOCS_BASE + c.id }));
  const CHECK = {};
  CHECKS.forEach((c) => { CHECK[c.id] = c; });

  // ---------------------------------------------------------------- input parsing

  function parseInput(text) {
    let data;
    if (typeof text !== 'string' || !text.trim()) return { error: 'Paste the answer to tools/list first.', errorType: 'empty' };
    try { data = JSON.parse(text); } catch (e) { return { error: 'This is not valid JSON: ' + e.message + '. Paste the full answer to tools/list.', errorType: 'not_json' }; }
    return parseData(data);
  }

  function resultOf(x) {
    if (x && typeof x === 'object' && !Array.isArray(x)) {
      if (x.result && typeof x.result === 'object' && Array.isArray(x.result.tools)) return { kind: 'jsonrpc', result: x.result, rpc: x };
      if (Array.isArray(x.tools)) return { kind: 'tools', result: x };
    }
    return null;
  }

  function parseData(data) {
    let entries = null, kind = null; const pages = [];
    if (Array.isArray(data) && data.length && data.every((d) => resultOf(d))) {
      kind = 'pages';
      data.forEach((d) => pages.push(resultOf(d)));
      entries = [].concat.apply([], pages.map((p) => p.result.tools));
    } else if (Array.isArray(data)) { kind = 'array'; entries = data; }
    else {
      const r = resultOf(data);
      if (r) { kind = r.kind; pages.push(r); entries = r.result.tools; }
      else if (data && typeof data === 'object' && data.error && data.jsonrpc) return { error: 'This is a JSON-RPC error answer, not a tool list: ' + (data.error.message || JSON.stringify(data.error)) + '.', errorType: 'jsonrpc_error' };
    }
    if (!entries) return { error: 'No tool list found. Expected an array of tools, {"tools": [...]}, a JSON-RPC answer with result.tools, or an array of such answers (one per page).', errorType: 'no_tools_key' };
    const tools = [], bad = [];
    entries.forEach((t, i) => { if (t && typeof t === 'object' && !Array.isArray(t) && typeof t.name === 'string') tools.push(t); else bad.push(i); });
    if (!tools.length) return { error: 'The list holds no tool with a name.', errorType: 'no_named_tools' };
    return { tools, badEntries: bad, envelope: { kind, pages } };
  }

  // ---------------------------------------------------------------- helpers

  const isObj = (x) => x !== null && typeof x === 'object' && !Array.isArray(x);
  const ann = (t) => (isObj(t.annotations) ? t.annotations : {});
  const schemaOf = (t) => (t.inputSchema !== undefined ? t.inputSchema : t.input_schema);
  const props = (t) => { const s = schemaOf(t); return isObj(s) && isObj(s.properties) ? s.properties : {}; };
  const desc = (t) => (typeof t.description === 'string' ? t.description.trim() : '');
  const titleOf = (t) => (typeof t.title === 'string' && t.title.trim()) || (typeof ann(t).title === 'string' && ann(t).title.trim()) || '';
  const has = Object.prototype.hasOwnProperty;

  function tokens(name) {
    return String(name).replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  }
  const norm = (k) => tokens(k).join('_');
  const set = (s) => new Set(s.split(' '));
  const READ_V = set('get list search find read fetch query describe show view count lookup look check validate preview browse retrieve download export inspect explain summarize summarise suggest recommend analyze analyse compare calculate compute estimate whoami ping status diff render convert parse translate info stat stats peek poll head lint verify test can has is');
  const DELETE_V = set('delete remove drop purge destroy clear truncate wipe revoke cancel reset erase unlink uninstall unpublish deactivate disable ban kick terminate kill abort void overwrite replace rollback detach unregister unsubscribe empty prune evict');
  // execute, run and call are left out on purpose: they name read queries as often as writes.
  const CREATE_V = set('create add send post insert upload comment reply publish invite submit order pay charge book schedule transfer refund new make register enqueue queue start trigger launch fork clone copy duplicate import share notify email message tweet attach subscribe generate dispatch deploy provision spawn open draft compose');
  const UPDATE_V = set('update edit set patch put rename move assign unassign merge close reopen archive unarchive write upsert modify change toggle approve reject label tag untag lock unlock pin unpin star unstar mark restore transition sync save configure enable rotate grant resolve apply commit push link unlink scale restart stop pause resume promote demote');
  const JOB_V = set('start trigger launch queue enqueue schedule dispatch kick spawn deploy provision');
  // "open" reads (open_nodes, open_file) when its object is something that exists already; open_issue and open_pull_request create.
  const OPEN_READ = set('node nodes file files page pages url urls link links document documents doc docs tab tabs entity entities graph resource resources path paths directory folder');
  // Operations on two operands (source and target) or one state change: not a replacement of the whole object.
  const REWIRE_V = set('move rename assign unassign transition merge restore sync');

  function verbClass(tok) {
    if (DELETE_V.has(tok)) return 'delete';
    if (CREATE_V.has(tok)) return 'create';
    if (UPDATE_V.has(tok)) return 'update';
    if (READ_V.has(tok)) return 'read';
    return null;
  }
  // Verb-first names (create_issue) are read from the first word, resource-first names (issues.create) from the last.
  function kindOf(name) {
    const tk = tokens(name);
    if (!tk.length) return null;
    if (tk[0] === 'open' && tk.length > 1 && OPEN_READ.has(tk[1])) return 'read';
    const first = verbClass(tk[0]);
    if (first) return first;
    const last = verbClass(tk[tk.length - 1]);
    if (last) return last;
    // Middle words: a read verb before any write word wins (tempo_search_tag_values), and a write word followed by a
    // plural or config noun is itself a noun (loki_label_names, alloy_label_config).
    const NOUNISH = /^(names|values|keys|ids|list|lists|config|configs|configuration|schema|schemas|stats|info|details|types|sets)$/;
    const writes = [];
    for (let i = 1; i < tk.length - 1; i++) {
      const c = verbClass(tk[i]);
      if (!c) continue;
      if (c === 'read') { if (!writes.length) return 'read'; continue; }
      if (!NOUNISH.test(tk[i + 1])) writes.push(c);
    }
    for (const k of ['delete', 'create', 'update']) if (writes.includes(k)) return k;
    return null;
  }
  const leadVerb = (name) => { const tk = tokens(name); const v = tk.find((x) => verbClass(x)); return v || ''; };

  function humanize(name) {
    const tk = tokens(name);
    if (!tk.length) return String(name);
    const s = tk.join(' ');
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  const JSONS = (x) => JSON.stringify(x, null, 2);

  // ---------------------------------------------------------------- JSON Schema: walk, refs, x-mcp-header, validation

  const SCHEMA_MAP_KW = ['properties', 'patternProperties', '$defs', 'definitions', 'dependentSchemas'];
  const SCHEMA_ONE_KW = ['additionalProperties', 'unevaluatedProperties', 'additionalItems', 'unevaluatedItems', 'contains', 'propertyNames', 'not', 'if', 'then', 'else'];
  const SCHEMA_ARR_KW = ['allOf', 'anyOf', 'oneOf', 'prefixItems'];

  // Visits every subschema. cb(schema, path[], depth, staticChain) where staticChain is true when every step from the root is "properties".
  function walkSchema(schema, cb) {
    const seen = new Set();
    function visit(s, path, depth, stat) {
      if (!isObj(s) || seen.has(s)) return;
      seen.add(s);
      cb(s, path, depth, stat);
      SCHEMA_MAP_KW.forEach((kw) => { if (isObj(s[kw])) Object.keys(s[kw]).forEach((k) => visit(s[kw][k], path.concat(kw, k), depth + 1, stat && kw === 'properties')); });
      SCHEMA_ONE_KW.forEach((kw) => visit(s[kw], path.concat(kw), depth + 1, false));
      SCHEMA_ARR_KW.forEach((kw) => { if (Array.isArray(s[kw])) s[kw].forEach((x, i) => visit(x, path.concat(kw, String(i)), depth + 1, false)); });
      if (Array.isArray(s.items)) s.items.forEach((x, i) => visit(x, path.concat('items', String(i)), depth + 1, false));
      else visit(s.items, path.concat('items'), depth + 1, false);
      if (isObj(s.dependencies)) Object.keys(s.dependencies).forEach((k) => visit(s.dependencies[k], path.concat('dependencies', k), depth + 1, false));
    }
    visit(schema, [], 0, true);
  }

  function pointerGet(rootSchema, pointer) {
    if (pointer === '' || pointer === '#') return rootSchema;
    if (!pointer.startsWith('#/')) return undefined;
    let cur = rootSchema;
    for (const raw of pointer.slice(2).split('/')) {
      let part;
      try { part = decodeURIComponent(raw).replace(/~1/g, '/').replace(/~0/g, '~'); } catch (e) { return undefined; }
      if (cur === null || typeof cur !== 'object' || !has.call(cur, part)) return undefined;
      cur = cur[part];
    }
    return cur;
  }

  function schemaFacts(schema) {
    const facts = { depth: 0, count: 0, refs: [], headers: [], patterns: [], anchors: new Set(), ids: new Set() };
    walkSchema(schema, (s, path, depth, stat) => {
      facts.count += 1;
      if (depth > facts.depth) facts.depth = depth;
      if (typeof s.$anchor === 'string') facts.anchors.add(s.$anchor);
      if (typeof s.$dynamicAnchor === 'string') facts.anchors.add(s.$dynamicAnchor);
      if (typeof s.$id === 'string') facts.ids.add(s.$id);
      if (typeof s.$ref === 'string') facts.refs.push({ ref: s.$ref, path });
      if (typeof s.pattern === 'string') facts.patterns.push({ pattern: s.pattern, path });
      if (has.call(s, 'x-mcp-header')) facts.headers.push({ value: s['x-mcp-header'], path, stat, schema: s });
    });
    return facts;
  }

  const JS_PATH = (path) => (path.length ? path.join('.') : '(root)');
  const TCHAR = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
  const SAFE_INT = 9007199254740991;

  function checkHeaders(facts) {
    const problems = [];
    const seen = {};
    facts.headers.forEach((h) => {
      const where = JS_PATH(h.path);
      const v = h.value;
      if (typeof v !== 'string' || v === '') { problems.push(where + ': the value is empty or not a string'); return; }
      if (/[\u0000-\u001f\u007f]/.test(v)) problems.push(where + ': "' + v.replace(/[\r\n]/g, ' ') + '" contains control characters (CR or LF)');
      else if (!TCHAR.test(v)) problems.push(where + ': "' + v + '" is not an HTTP field-name token');
      const lk = v.toLowerCase();
      if (seen[lk]) problems.push(where + ': "' + v + '" repeats "' + seen[lk] + '" (names must differ ignoring case)');
      else seen[lk] = v;
      if (!h.path.length || !h.stat) problems.push(where + ': not statically reachable (only a chain of "properties" from the root is allowed, not items, composition or $ref)');
      const ty = h.schema.type;
      if (ty === 'number') problems.push(where + ': on a property of type number, which is not permitted');
      else if (Array.isArray(ty)) problems.push(where + ': type ' + JSON.stringify(ty) + ' is not a single primitive type (string, integer or boolean)');
      else if (ty === undefined) problems.push(where + ': the property declares no type (string, integer or boolean required)');
      else if (!['string', 'integer', 'boolean'].includes(ty)) problems.push(where + ': on a property of type ' + JSON.stringify(ty) + ', not string, integer or boolean');
      if (ty === 'integer' && ((typeof h.schema.maximum === 'number' && h.schema.maximum > SAFE_INT) || (typeof h.schema.minimum === 'number' && h.schema.minimum < -SAFE_INT)))
        problems.push(where + ': allows integers outside the safe range of ±(2^53 - 1)');
    });
    return problems;
  }

  const SENSITIVE_KEY = /(^|_)(password|passwd|passphrase|secret|token|api_?key|apikey|otp|mfa|cookie|session|credential|credentials|private_key|ssn|email|phone|address|card|cvv|dob|birth)(_|$)/;

  // Validator: Ajv 2020-12 when available (bundled in the page, vendor/ in Node), otherwise a minimal structural validator.
  let ajvInstance = null, ajvTried = false;
  function getAjv(opts) {
    if (opts && opts.ajv === false) return null;
    if (opts && opts.ajv) return opts.ajv;
    if (ajvTried) return ajvInstance;
    ajvTried = true;
    let Ajv = root.ajv2020 || null;
    if (!Ajv && typeof require === 'function') { try { Ajv = require('./vendor/ajv2020.min.js'); } catch (e) { Ajv = null; } }
    if (Ajv) {
      const Ctor = Ajv.default || Ajv;
      // Ajv compiles its meta-schema with new Function. Under a Content-Security-Policy without 'unsafe-eval' that throws,
      // so probe once and fall back to the minimal validator instead of reporting false schema errors.
      try { ajvInstance = new Ctor({ strict: false, validateFormats: false, allErrors: true }); ajvInstance.validateSchema({ type: 'object' }); } catch (e) { ajvInstance = null; }
    }
    return ajvInstance;
  }
  const ENGINE_AJV = 'Ajv 8.17.1, JSON Schema 2020-12 meta-schema (bundled)';
  const ENGINE_MIN = 'Built-in minimal validator (Ajv not available): checks keyword types, not the full meta-schema';
  // Ajv's 2020-12 build cannot validate other dialects (draft-07 needs a second, ~120 KB build), so those schemas
  // get the structural check, labelled as such: Ajv is available, the dialect is the reason.
  const ENGINE_DIALECT = 'Structural check only for schemas that declare another JSON Schema dialect (for example draft-07); full meta-schema validation covers 2020-12';
  const D2020 = /^https?:\/\/json-schema\.org\/draft\/2020-12\/schema#?$/;
  const TYPES = ['array', 'boolean', 'integer', 'null', 'number', 'object', 'string'];

  function minimalValidate(schema) {
    const errs = [];
    walkSchema(schema, (s, path) => {
      const at = JS_PATH(path);
      if (has.call(s, 'type')) {
        const ts = Array.isArray(s.type) ? s.type : [s.type];
        if (!ts.length || ts.some((x) => !TYPES.includes(x))) errs.push(at + '/type must be one of ' + TYPES.join(', '));
      }
      if (has.call(s, 'properties') && !isObj(s.properties)) errs.push(at + '/properties must be an object');
      if (isObj(s.properties)) Object.keys(s.properties).forEach((k) => { const v = s.properties[k]; if (!isObj(v) && typeof v !== 'boolean') errs.push(at + '/properties/' + k + ' must be a schema (object or boolean)'); });
      if (has.call(s, 'required') && (!Array.isArray(s.required) || s.required.some((x) => typeof x !== 'string') || new Set(s.required).size !== s.required.length)) errs.push(at + '/required must be an array of unique strings');
      if (has.call(s, 'enum') && !Array.isArray(s.enum)) errs.push(at + '/enum must be an array');
      ['minimum', 'maximum', 'exclusiveMinimum', 'exclusiveMaximum', 'multipleOf'].forEach((k) => { if (has.call(s, k) && typeof s[k] !== 'number') errs.push(at + '/' + k + ' must be a number'); });
      ['minLength', 'maxLength', 'minItems', 'maxItems', 'minProperties', 'maxProperties'].forEach((k) => { if (has.call(s, k) && !(Number.isInteger(s[k]) && s[k] >= 0)) errs.push(at + '/' + k + ' must be a non-negative integer'); });
      SCHEMA_ARR_KW.forEach((k) => { if (has.call(s, k) && (!Array.isArray(s[k]) || !s[k].length)) errs.push(at + '/' + k + ' must be a non-empty array of schemas'); });
      if (has.call(s, '$ref') && typeof s.$ref !== 'string') errs.push(at + '/$ref must be a string');
      if (has.call(s, 'additionalProperties') && !isObj(s.additionalProperties) && typeof s.additionalProperties !== 'boolean') errs.push(at + '/additionalProperties must be a schema');
    });
    return errs;
  }

  function validateSchema(schema, label, opts) {
    const out = { errors: [], dialectNote: null, engine: null };
    if (typeof schema === 'boolean') { out.engine = 'n/a'; return out; }
    const declared = isObj(schema) && typeof schema.$schema === 'string' ? schema.$schema : null;
    const ajv = getAjv(opts);
    if (declared && !D2020.test(declared)) out.dialectNote = declared;
    if (ajv && !out.dialectNote) {
      out.engine = ENGINE_AJV;
      let ok = false;
      try { ok = ajv.validateSchema(schema); } catch (e) {
        if (e instanceof EvalError || /unsafe-eval|Content Security Policy|evaluate a string/i.test(String(e && e.message))) {
          out.engine = ENGINE_MIN;
          minimalValidate(schema).slice(0, 5).forEach((x) => out.errors.push(label + '.' + x));
          return out;
        }
        out.errors.push(label + ': ' + e.message); return out;
      }
      if (!ok) (ajv.errors || []).slice(0, 5).forEach((e) => out.errors.push(label + (e.instancePath || '') + ' ' + e.message + (e.params && e.params.allowedValues ? ' (' + e.params.allowedValues.join(', ') + ')' : '')));
    } else {
      out.engine = ajv && out.dialectNote ? ENGINE_DIALECT : ENGINE_MIN;
      minimalValidate(schema).slice(0, 5).forEach((e) => out.errors.push(label + '.' + e));
    }
    return out;
  }

  function checkRefs(rootSchema, facts) {
    const remote = [], broken = [];
    facts.refs.forEach((r) => {
      const ref = r.ref;
      if (ref.startsWith('#')) {
        if (ref === '#' || ref.startsWith('#/')) { if (pointerGet(rootSchema, ref) === undefined) broken.push(ref); }
        else if (!facts.anchors.has(ref.slice(1))) broken.push(ref);
      } else if (facts.ids.has(ref) || facts.ids.has(ref.split('#')[0])) {
        // resolves to a schema resource defined inside this schema
      } else remote.push(ref);
    });
    return { remote, broken };
  }

  // ---------------------------------------------------------------- string scanning (security)

  function collectStrings(x, path, out) {
    if (typeof x === 'string') out.push({ path: path || '(value)', value: x });
    else if (Array.isArray(x)) x.forEach((v, i) => collectStrings(v, path + '[' + i + ']', out));
    else if (isObj(x)) Object.keys(x).forEach((k) => { out.push({ path: (path ? path + '.' : '') + k + ' (key)', value: k, key: true }); collectStrings(x[k], (path ? path + '.' : '') + k, out); });
    return out;
  }

  const RE_TAGS = /[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}]/u;
  const RE_BIDI = /[‪-‮⁦-⁩]/;
  const RE_ZW = /[​-‏⁠-⁤﻿᠎­͏؜ᅟᅠㅤﾠ]/;
  const RE_CTRL = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/;
  const STRIP_RE = /[\u{E0000}-\u{E007F}\u{E0100}-\u{E01EF}‪-‮⁦-⁩​-‏⁠-⁤﻿᠎­͏؜ᅟᅠㅤﾠ\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/gu;
  const RE_LATIN = /\p{Script=Latin}/u;
  const RE_CONFUSABLE = /[\p{Script=Cyrillic}\p{Script=Greek}\p{Script=Armenian}\p{Script=Cherokee}]/u;
  const HTML_COMMENT = new RegExp('<' + '!--');
  const RE_MARKUP = /<\s*\/?\s*(important|system|instructions?|admin|secret|hidden|sudo|assistant|human|override|prompt|context)\s*>|\[\/?INST\]|<\|(im_start|im_end|system|endoftext|user|assistant)\|>|^\s*#{1,3}\s*(system|instructions)\b/im;
  const RE_PHRASES = [
    /\b(ignore|disregard|forget|override|bypass)\b[^.\n]{0,40}\b(previous|prior|above|earlier|other|all|any|system|safety|your)\b[^.\n]{0,25}\b(instructions?|prompts?|rules|guidelines|directives|messages|policies)\b/i,
    /\b(do not|don['’]t|never)\s+(tell|inform|mention|show|reveal|notify|alert)\b[^.\n]{0,30}\b(the\s+)?user\b/i,
    /\bwithout\s+(asking|telling|informing|notifying|alerting|confirming with|the knowledge of)\b[^.\n]{0,20}\buser\b/i,
    /\b(reveal|print|output|repeat|disclose|leak)\b[^.\n]{0,25}\bsystem prompt\b/i,
    /\b(you are now|from now on,? you|act as (an?|the) (assistant|ai|system|admin))\b/i,
    /\b(this|these) (instructions?|rules?) (take|takes|have|has) (precedence|priority)\b/i,
  ];
  const RE_STEER_HARD = /\b(always (call|use|run|invoke) this( tool)? (first|before)|before (using|calling|invoking) (any|other|another)( other)? tools?|(call|use|invoke) this (tool )?before anything|never (use|call) (any )?other tools?|instead of (any|all) other tools?|(only|exclusively) use this tool)\b/i;
  const RE_STEER_SOFT = /\b(prefer this (tool|plugin|server|connector)|use this (tool )?instead of|rather than (using|calling) (the )?[\w.-]+ (tool|plugin|server|connector)|(better|faster|more accurate) than (other|the [\w.-]+) (tools?|plugins?|servers?)|do not use (the )?(?!this\b)[\w.-]+ (tool|plugin|server|connector))\b/i;
  const RE_EXTERNAL = /\b(fetch|read|load|follow|get|download|retrieve|check|obey)\b[^.\n]{0,40}\b(instructions?|rules|guidelines|directives|prompts?|policies)\b[^.\n]{0,30}\b(from|at|in)\b[^.\n]{0,25}(https?:\/\/|www\.|\burl\b|remote|gist|pastebin)/i;
  const RE_SECRETS = /(~\/\.ssh|\bid_(rsa|ed25519|ecdsa)\b|\.ssh\/|(^|[\s"'`(])\.env\b|\.aws\/credentials|\bmcp\.json\b|claude_desktop_config|\.npmrc|\.netrc|\.pgpass|~\/\.kube\/config|(?<!\bwhether (or not )?(to |\w+ (should|will|can) ))\b(send|forward|post|upload|include|pass|exfiltrate)\b[^.\n]{0,40}\b(api keys?|credentials|secrets|passwords?|ssh keys?|private keys?|environment variables|conversation history|chat history|previous messages)\b)/i;
  const RE_B64 = /[A-Za-z0-9+/]{40,}={0,2}|[A-Za-z0-9_-]{48,}/g;
  const RE_HEX = /\b(?:[0-9a-fA-F]{2}){24,}\b/g;

  const atobSafe = (s) => { try { const b = s.replace(/-/g, '+').replace(/_/g, '/'); return typeof root.atob === 'function' ? root.atob(b + '==='.slice((b.length + 3) % 4)) : null; } catch (e) { return null; } };
  const printable = (s) => s && s.length >= 12 && (s.match(/[\x20-\x7E\n\t]/g) || []).length / s.length > 0.9 && /[a-z]{3,}\s+[a-z]{2,}/i.test(s);
  const decodeTags = (s) => Array.from(s).map((ch) => { const cp = ch.codePointAt(0); return cp >= 0xE0020 && cp <= 0xE007E ? String.fromCharCode(cp - 0xE0000) : ''; }).join('');
  const clip = (s, n) => (s.length > n ? s.slice(0, n) + '…' : s);
  const visible = (s) => s.replace(STRIP_RE, (c) => '\\u{' + c.codePointAt(0).toString(16).toUpperCase() + '}');

  function scanTool(t, push, siblings) {
    siblings = siblings || [];
    const strings = collectStrings(t, '', []);
    const hits = {};
    const once = (id, sev, msg, path) => { const k = id + '|' + sev; if (hits[k]) { hits[k].paths.push(path); return; } hits[k] = { id, sev, msg, paths: [path] }; };
    strings.forEach(({ path, value, key }) => {
      if (RE_TAGS.test(value)) { const d = decodeTags(value); once('sec-invisible-encoding', 'blocking', 'Invisible tag or variation-selector characters' + (d.trim() ? '; hidden text reads: "' + clip(d, 120) + '"' : '') + '.', path); }
      if (RE_BIDI.test(value)) once('sec-bidi-controls', 'blocking', 'Bidirectional override or isolate characters.', path);
      if (RE_ZW.test(value)) once('sec-zero-width', 'attention', 'Zero-width or other invisible characters: ' + clip(visible(value).match(/\\u\{[0-9A-F]+\}/g).filter((v, i, a) => a.indexOf(v) === i).join(' '), 60) + '.', path);
      if (RE_CTRL.test(value)) once('sec-control-chars', 'attention', 'Control characters.', path);
      if (path === 'name' || path === 'name (key)') {
        if (/[^\x00-\x7F]/.test(value) && /\p{L}/u.test(value.replace(/[\x00-\x7F]/g, ''))) once('sec-homoglyph', 'blocking', 'The tool name contains non-ASCII letters (' + Array.from(new Set(value.replace(/[\x00-\x7F]/g, ''))).map((c) => 'U+' + c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')).join(', ') + ') that can imitate another tool\'s name.', path);
      } else if (!key) {
        const mixed = value.split(/[\s.,;:!?()"'`[\]{}<>/\\]+/).filter((w) => w.length > 1 && RE_LATIN.test(w) && RE_CONFUSABLE.test(w));
        if (mixed.length) once('sec-homoglyph', 'attention', 'Words mix Latin with look-alike letters from another script: ' + clip(mixed.slice(0, 3).join(', '), 60) + '.', path);
      }
      if (key) return;
      if (HTML_COMMENT.test(value)) once('sec-html-comment', 'blocking', 'An HTML comment hides text from rendered views.', path);
      const mk = value.match(RE_MARKUP);
      if (mk) once('sec-instruction-markup', 'blocking', 'Prompt markup "' + clip(mk[0].trim(), 40) + '".', path);
      for (const re of RE_PHRASES) { const m = value.match(re); if (m) { once('sec-instruction-phrases', 'blocking', 'Instruction to the model: "' + clip(m[0], 80) + '".', path); break; } }
      const sh = value.match(RE_STEER_HARD);
      if (sh) once('sec-cross-tool-steering', 'blocking', 'Steers the model away from other tools: "' + clip(sh[0], 80) + '".', path);
      else {
        const ss = value.match(RE_STEER_SOFT);
        // Routing between tools of the same server ("prefer this tool over search_x") is not steering away from other servers.
        const sibling = ss && siblings.some((n) => new RegExp('(^|[^A-Za-z0-9_-])' + n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '($|[^A-Za-z0-9_-])').test(value));
        if (ss && !sibling) once('sec-cross-tool-steering', 'attention', 'Steers tool selection: "' + clip(ss[0], 80) + '".', path);
      }
      const ex = value.match(RE_EXTERNAL);
      if (ex) once('sec-external-instructions', 'blocking', 'Points the model at outside instructions: "' + clip(ex[0], 80) + '".', path);
      const sc = value.match(RE_SECRETS);
      if (sc) once('sec-secret-seeking', 'blocking', 'Seeks secrets or local files: "' + clip(sc[0].trim(), 80) + '".', path);
      if (!/^data:/i.test(value) && !/^https?:\/\//i.test(value) && !/(^|\.)(pattern|src|\$ref|\$id|\$schema)$/.test(path)) {
        const blobs = (value.match(RE_B64) || []).concat(value.match(RE_HEX) || []);
        for (const b of blobs) {
          const isHex = /^[0-9a-fA-F]+$/.test(b);
          if (!isHex && !(/[A-Z]/.test(b) && /[a-z]/.test(b) && /[0-9+/_-]/.test(b))) continue;
          const dec = isHex ? b.match(/../g).map((h) => String.fromCharCode(parseInt(h, 16))).join('') : atobSafe(b);
          if (printable(dec)) { once('sec-encoded-blob', 'blocking', 'An encoded block decodes to text: "' + clip(dec.replace(/\s+/g, ' '), 100) + '".', path); break; }
          if (!isHex && b.length >= 80) { once('sec-encoded-blob', 'attention', 'A ' + b.length + '-character encoded-looking block.', path); break; }
        }
      }
    });
    Object.keys(hits).forEach((k) => { const h = hits[k]; push(h.id, h.sev, h.msg + ' In: ' + h.paths.slice(0, 4).join(', ') + (h.paths.length > 4 ? ' and ' + (h.paths.length - 4) + ' more' : '') + '.', h.paths[0]); });
  }

  // ---------------------------------------------------------------- argument-name detectors

  function argNames(t) { return Object.keys(props(t)); }

  function credentialArgs(t) {
    const hard = [], soft = [];
    const pp = props(t);
    argNames(t).forEach((k) => {
      const tk = tokens(k), n = tk.join('_');
      // A boolean flag (hide_secret, withCredentials) cannot carry a credential.
      if (isObj(pp[k]) && (pp[k].type === 'boolean' || (Array.isArray(pp[k].type) && pp[k].type.every((x) => x === 'boolean' || x === 'null')))) return;
      const last = tk[tk.length - 1];
      if (['name', 'names', 'id', 'ids', 'count', 'length', 'policy', 'hint', 'expiry', 'expires', 'type', 'ref', 'label', 'path', 'arn', 'version', 'field', 'header', 'required', 'reset', 'set'].includes(last)) return;
      if (/^(page|next|prev|previous|continuation|cursor|sync|resume|pagination|max|min|num|output|input|completion|prompt)_/.test(n) && /token/.test(n)) return;
      if (/(^|_)tokens?$/.test(n) && /(max|count|limit|num|budget|usage)/.test(n)) return;
      if (/(^|_)(password|passwd|passphrase|pwd|secret|apikey|otp|totp|hotp|mfa|2fa|passcode|pin_code|cvv|cvc|ssn|cookie|cookies|credential|credentials)(_|$)/.test(n) ||
          /(^|_)api_key(_|$)/.test(n) || /(^|_)(access|refresh|auth|bearer|session|id|oauth|personal_access|client|private|secret)_(token|key|secret)(_|$)/.test(n) ||
          /(^|_)private_key(_|$)/.test(n) || /(^|_)(card|cc|credit_card)_(number|num|no)(_|$)/.test(n) || /^(card|credit_card|pan)$/.test(n) ||
          /(^|_)(social_security|national_id|passport_number|tax_id)(_|$)/.test(n)) hard.push(k);
      else if (/^(token|auth|authorization|api_token)$/.test(n)) soft.push(k);
    });
    return { hard, soft };
  }

  function conversationArgs(t) {
    const hard = [], soft = [];
    argNames(t).forEach((k) => {
      const n = norm(k);
      if (/(^|_)(conversation|conversations|transcript|transcripts|chat_history|chat_log|chat_logs|chat_context|prior_turns|previous_turns|previous_messages|message_history|dialog_history|dialogue|full_context|memories)(_|$)/.test(n) || /^(memory|user_memory|claude_memory|chat_memory|conversation_summary)$/.test(n)) hard.push(k);
      else if (/^(messages|history|context|additional_context|extra_context|user_context|background|session_context)$/.test(n)) soft.push(k);
    });
    return { hard, soft };
  }

  function locationArgs(t) {
    const hard = [], soft = [];
    argNames(t).forEach((k) => {
      const tk = tokens(k), n = tk.join('_');
      if (tk.some((x) => ['email', 'ip', 'mac', 'wallet', 'contract', 'memory', 'ethereum', 'btc', 'url', 'web', 'server', 'host', 'bitcoin', 'mail', 'sender', 'recipient', 'from', 'to', 'cc', 'bcc', 'reply'].includes(x))) return;
      if (/^(lat|latitude|lng|lon|long|longitude|coordinates|coords|gps|geo|geolocation|latlng|lat_lng|lat_lon|location_coordinates|user_coordinates|position)$/.test(n) || /(^|_)(latitude|longitude|gps|geolocation)(_|$)/.test(n)) hard.push(k);
      else if (/(^|_)(address|street|street_address|zip|zipcode|zip_code|postal_code|postcode|location|home_address|current_location)(_|$)/.test(n)) soft.push(k);
    });
    return { hard, soft };
  }

  const SAFE_M = ['GET', 'HEAD', 'OPTIONS'];
  const UNSAFE_M = ['POST', 'PUT', 'PATCH', 'DELETE'];
  function mixedMethodTool(t) {
    const p = props(t);
    for (const key of Object.keys(p)) {
      if (!/^(method|http_method|httpmethod|verb|http_verb|request_method)$/i.test(key)) continue;
      const en = isObj(p[key]) && Array.isArray(p[key].enum) ? p[key].enum.map((v) => String(v).toUpperCase()) : null;
      // A bare "method" is an HTTP method only on a tool that reads as an HTTP request; elsewhere it names an RPC method or an action.
      const httpish = !/^method$/i.test(key) || API_TOOL.test(apiName(t.name)) || Object.keys(p).some((k) => FREEFORM_API.test(norm(k)) && norm(k) !== 'body') ||
        (isObj(p[key]) && typeof p[key].description === 'string' && /\b(HTTP|GET|POST|PUT|PATCH|DELETE)\b/.test(p[key].description));
      if (!en) { if (httpish) return 'takes a free-form "' + key + '" argument'; continue; }
      if (en.some((v) => SAFE_M.includes(v)) && en.some((v) => UNSAFE_M.includes(v))) return 'accepts both read and write HTTP methods in "' + key + '" (' + en.join(', ') + ')';
    }
    return null;
  }
  // Query-language arguments always count; "path"/"endpoint"/"body" count only on a tool that reads as a raw API request.
  const FREEFORM_LANG = /^(sql|graphql|gql|soql|sosl|jql|cql|cypher|promql|logql|kql|spl|hql|query_string|raw_query|api_path|url_path|request_path|request_body|raw_body|raw_request)$/;
  const FREEFORM_API = /^(path|endpoint|body|url|uri)$/;
  const API_TOOL = /(^|_)(api|request|http|rest|graphql|endpoint|fetch_api|call_api|raw)(_|$)/;
  // "pull_request", "merge_request" and similar are resources, not raw API requests.
  function apiName(name) { return norm(name).replace(/(^|_)(pull|merge|review|feature|change|access|join|friend|follow|connection|purchase)_requests?(?=_|$)/g, '$1resource'); }
  const freeformArgs = (t) => {
    const apiLike = API_TOOL.test(apiName(t.name)) || !!mixedMethodTool(t);
    return argNames(t).filter((k) => FREEFORM_LANG.test(norm(k)) || (apiLike && FREEFORM_API.test(norm(k))));
  };
  const NAMES_API = /(https?:\/\/|\b[A-Z][A-Za-z0-9.]*(?:\s[A-Z][A-Za-z0-9.]*)?\s(Web |REST |GraphQL |Admin |HTTP |Graph |Management |Public )?API\b|\b(PostgreSQL|Postgres|MySQL|MariaDB|SQLite|BigQuery|Snowflake|ClickHouse|Redshift|DuckDB|Spanner|SQL Server|T-SQL|Oracle|Neo4j|Prometheus|Loki|Elasticsearch|OpenSearch|Splunk|Jira|Confluence|Salesforce|Kusto|Cypher)\b)/;
  // Database and engine names also count in lower case ("on the postgres database").
  const NAMES_DB = /\b(postgresql|postgres|mysql|mariadb|sqlite|bigquery|snowflake|clickhouse|redshift|duckdb|elasticsearch|opensearch|prometheus)\b/i;

  // ---------------------------------------------------------------- per-tool checks

  const RETRY_WORDS = /(retr(y|ies|ied|ying)|idempot|duplicate|safe to repeat|more than once|called again|calling it again|same key|repeat(ed)? call|repeats? the effect)/i;
  const USE_WHEN = /\b(use (this|it|when|for|before|after|to)|call (this|it) (when|to|before|after)|do not use|don['’]t use|only use|useful (when|for))\b/i;
  const PROMO = /(^|_)(best|official|ultimate|recommended|preferred|greatest|awesome|amazing|perfect|pick_me|top_rated|number_one|no1|super)(_|$)/;
  // Applied to the name split into words plus the description.
  const MONEY = /\b(transfers?|sends?|wires?|withdraws?|withdraw|remits?|moves?|payouts?|pay out|swaps?)\b[^.\n]{0,30}\b(money|funds|payments?|usd|eur|crypto|cryptocurrency|bitcoin|btc|eth|ether|usdc|stablecoins?|tokens|financial assets|wallet|balance)\b|\b(wire transfer|send crypto|withdraw funds)\b/i;
  const AIMEDIA = /\b(generate|generates|create|creates|synthesi[sz]es?|produces?|render)\b[^.\n]{0,30}\b(images?|photos?|pictures?|videos?|audio|speech|voices?|music|songs?|artwork)\b[^.\n]{0,40}\b(ai|model|diffusion|dall|stable|midjourney|tts|text[- ]to)\b|\btext[- ]to[- ](image|video|speech|audio|music)\b|^(generate|create) (image|video|audio|speech|music)\b/i;
  const VAGUE = new Set(['id', 'user', 'data', 'value', 'obj', 'object', 'item', 'input', 'params', 'args', 'arguments', 'payload', 'info', 'thing', 'stuff', 'body_json', 'q']);
  const CONSTRAINED = /^(state|status|type|kind|sort|sort_by|order|order_by|direction|sort_order|format|mode|level|priority|visibility|role|scope|severity|category|unit|units|interval|granularity|period|response_format|output_format)$/;
  const LIST_V = new Set(['list', 'search', 'find', 'query', 'browse']);
  const PAGE_ARG = /^(limit|page_size|per_page|max_results|max|count|top|first|last|page|cursor|offset|after|before|next_token|page_token|starting_after|max_items|size)$/;
  const RF_ARG = /^(response_format|format|fields|verbosity|detail|details|view|select|include|output_format|concise)$/;
  const HANDLE_NOUN = /^(session|basket|cart|context|transaction|browser|tab|sandbox|handle|lock|lease|kernel|terminal|shell|upload_session|checkout)$/;
  const LIFETIME = /(expir|lifetime|ttl|time[- ]to[- ]live|idle|inactiv|after \d+ ?(s|sec|seconds?|m|min|minutes?|h|hours?|days?)|until (it is |they are )?(closed|deleted|ended)|retain|retention|persist(s|ed)? (until|for))/i;

  function checkTool(t, ctx) {
    const items = [];
    const push = (id, severity, message, path, extra) => {
      const c = CHECK[id];
      items.push(Object.assign({ id, section: c.section, affects: c.affects, severity: severity || c.severity, message, path: path || null }, extra || {}));
    };
    const a = ann(t);
    const d = desc(t);
    const name = t.name;
    const kind = kindOf(name);
    const readOnly = a.readOnlyHint === true;
    const s = schemaOf(t);
    const p = props(t);
    const pk = Object.keys(p);

    // ---- spec: shape and types
    if (t.inputSchema === undefined && t.input_schema !== undefined) push('spec-input-schema-field-name', null, 'The tool has "input_schema" but no "inputSchema".', 'input_schema');
    else if (t.inputSchema === undefined || t.inputSchema === null) push('spec-input-schema-missing', null, t.inputSchema === null ? 'inputSchema is null.' : 'The tool has no inputSchema.', 'inputSchema');
    if (s !== undefined && s !== null) {
      if (!isObj(s)) push('spec-input-schema-root-object', null, 'inputSchema is ' + (Array.isArray(s) ? 'an array' : typeof s) + ', not a schema object with type "object".', 'inputSchema');
      else if (s.type !== 'object') push('spec-input-schema-root-object', null, 'The root type is ' + (s.type === undefined ? 'missing' : JSON.stringify(s.type)) + '; it must be "object".', 'inputSchema.type');
    }
    const typeErr = [];
    if (has.call(t, 'title') && typeof t.title !== 'string') typeErr.push('title must be a string');
    if (has.call(t, 'description') && typeof t.description !== 'string') typeErr.push('description must be a string');
    if (has.call(t, 'annotations')) {
      if (!isObj(t.annotations)) typeErr.push('annotations must be an object');
      else {
        ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'].forEach((k) => { if (has.call(a, k) && typeof a[k] !== 'boolean') typeErr.push('annotations.' + k + ' must be a boolean, not ' + JSON.stringify(a[k])); });
        if (has.call(a, 'title') && typeof a.title !== 'string') typeErr.push('annotations.title must be a string');
      }
    }
    if (has.call(t, 'outputSchema') && !isObj(t.outputSchema)) typeErr.push('outputSchema must be a schema object');
    if (has.call(t, '_meta') && !isObj(t._meta)) typeErr.push('_meta must be an object');
    if (has.call(t, 'icons') && !Array.isArray(t.icons)) typeErr.push('icons must be an array');
    if (typeErr.length) push('spec-field-types', null, typeErr.join('; ') + '.', null);
    // A hint spelled another way (destructive_hint, ReadOnlyHint, open-world-hint): clients ignore it.
    if (isObj(t.annotations)) {
      const HINTS = { readonlyhint: ['readOnlyHint', 'false'], destructivehint: ['destructiveHint', 'true'], idempotenthint: ['idempotentHint', 'false'], openworldhint: ['openWorldHint', 'true'] };
      Object.keys(a).forEach((k) => {
        const h = HINTS[k.toLowerCase().replace(/[_\s-]/g, '')];
        if (!h || k === h[0]) return;
        push('spec-annotation-key-case', null, 'annotations.' + JSON.stringify(k).slice(1, -1) + ' is not a ToolAnnotations key; clients ignore it and ' + (has.call(a, h[0]) ? 'read ' + h[0] + ' (also set) instead.' : 'use the default ' + h[0] + ': ' + h[1] + '.'), 'annotations.' + k);
      });
    }

    // ---- spec: names
    if (name.length < 1 || name.length > 128) push('spec-name-length', null, 'The name is ' + name.length + ' characters.', 'name');
    if (name.length && !/^[A-Za-z0-9_.-]+$/.test(name)) push('spec-name-charset', null, 'The name contains ' + JSON.stringify(Array.from(new Set(name.replace(/[A-Za-z0-9_.-]/g, ''))).join('')) + '.', 'name');

    // ---- spec: schemas
    const schemaPairs = [];
    if (isObj(s)) schemaPairs.push(['inputSchema', s]);
    if (isObj(t.outputSchema)) schemaPairs.push(['outputSchema', t.outputSchema]);
    schemaPairs.forEach(([label, sc]) => {
      const v = validateSchema(sc, label, ctx.opts);
      ctx.engines.add(v.engine);
      const facts = schemaFacts(sc);
      const refs = checkRefs(sc, facts);
      const errs = v.errors.slice();
      refs.broken.forEach((r) => errs.push(label + ': $ref "' + r + '" does not resolve inside the schema'));
      facts.patterns.forEach((pt) => { try { new RegExp(pt.pattern, 'u'); } catch (e) { errs.push(label + '.' + JS_PATH(pt.path) + '.pattern does not compile: ' + clip(pt.pattern, 40)); } });
      if (errs.length) push('spec-schema-valid', null, errs.slice(0, 5).join('; ') + '.', label);
      if (v.dialectNote) push('spec-schema-dialect', null, label + ' declares "' + v.dialectNote + '".', label + '.$schema');
      if (refs.remote.length) push('spec-ref-remote', null, label + ' references ' + refs.remote.slice(0, 3).map((r) => '"' + r + '"').join(', ') + '.', label);
      if (facts.depth > 10 || facts.count > 500) push('spec-composition-bounds', null, label + ' nests ' + facts.depth + ' levels deep with ' + facts.count + ' subschemas.', label, { data: { depth: facts.depth, subschemas: facts.count } });
      if (label === 'inputSchema') {
        const hp = checkHeaders(facts);
        if (hp.length) push('spec-x-mcp-header', null, hp.slice(0, 4).join('; ') + '. Conforming HTTP clients leave this tool out of the list.', 'inputSchema');
        const sens = facts.headers.filter((h) => h.path.length && SENSITIVE_KEY.test(norm(h.path[h.path.length - 1])));
        if (sens.length) push('spec-x-mcp-header-sensitive', null, 'x-mcp-header on ' + sens.map((h) => '"' + h.path[h.path.length - 1] + '"').join(', ') + '.', 'inputSchema');
        ctx.headerFacts = facts.headers;
      }
    });
    if (Array.isArray(t.icons)) {
      const badIcons = t.icons.filter((ic) => !isObj(ic) || typeof ic.src !== 'string' || !/^(https:|data:)/i.test(ic.src.trim()));
      if (badIcons.length) push('spec-icon-scheme', null, 'Icon source ' + badIcons.slice(0, 2).map((ic) => JSON.stringify(isObj(ic) ? clip(String(ic.src), 50) : ic)).join(', ') + ' is not https: or data:.', 'icons');
    }
    if (isObj(t._meta)) {
      const badKeys = [], reserved = [];
      Object.keys(t._meta).forEach((k) => {
        if (['progressToken', 'traceparent', 'tracestate', 'baggage'].includes(k)) return;
        const slash = k.lastIndexOf('/');
        const prefix = slash >= 0 ? k.slice(0, slash) : null;
        const nm = slash >= 0 ? k.slice(slash + 1) : k;
        const labelOk = (l) => /^[A-Za-z]([A-Za-z0-9-]*[A-Za-z0-9])?$/.test(l);
        if ((prefix !== null && !prefix.split('.').every(labelOk)) || (nm !== '' && !/^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/.test(nm))) badKeys.push(k);
        else if (prefix && ['modelcontextprotocol', 'mcp'].includes((prefix.split('.')[1] || '').toLowerCase())) reserved.push(k);
      });
      if (badKeys.length) push('spec-meta-key', null, 'Key ' + badKeys.slice(0, 3).map((k) => JSON.stringify(k)).join(', ') + ' does not follow the grammar.', '_meta');
      if (reserved.length) push('spec-meta-reserved', null, 'Key ' + reserved.slice(0, 3).map((k) => JSON.stringify(k)).join(', ') + ' uses a reserved prefix.', '_meta');
    }
    if (has.call(t, 'execution')) push('spec-execution-legacy', null, 'The tool has an "execution" field' + (isObj(t.execution) && t.execution.taskSupport ? ' (taskSupport: ' + JSON.stringify(t.execution.taskSupport) + ')' : '') + '.', 'execution');

    // ---- Anthropic
    if (!titleOf(t)) push('anthropic-title', null, 'No title, and no annotations.title.', 'title');
    if (!readOnly) {
      if (typeof a.destructiveHint !== 'boolean') push('anthropic-hint', null, 'Neither readOnlyHint: true nor destructiveHint is set' + (has.call(a, 'readOnlyHint') ? '' : ' (no annotations hint at all)') + '. A client treats a missing destructiveHint as true.', 'annotations');
      else if (a.destructiveHint === false && kind !== 'delete') push('anthropic-hint-platforms-differ', null, 'destructiveHint: false on a write tool. OpenAI accepts false for purely additive writes; Anthropic\'s wording asks for true on tools that modify data.', 'annotations.destructiveHint');
    }
    if (name.length > 64) push('anthropic-name-length', null, 'The name is ' + name.length + ' characters.', 'name');
    const mixed = mixedMethodTool(t);
    if (mixed) push('anthropic-read-write-split', null, 'The tool ' + mixed + '.', 'inputSchema.properties');
    const ff = freeformArgs(t);
    if (ff.length && !NAMES_API.test(d) && !NAMES_DB.test(d)) push('anthropic-api-docs', null, 'Free-form ' + ff.map((k) => '"' + k + '"').join(', ') + ', but the description neither links nor names the target API.', 'description');
    if (!d) push('anthropic-description', 'blocking', 'No description.', 'description');
    else if (d.length < 40) push('anthropic-description', 'attention', 'The description is ' + d.length + ' characters: "' + d + '".', 'description');
    const conv = conversationArgs(t);
    if (conv.hard.length) push('anthropic-conversation-data', null, 'Asks for ' + conv.hard.map((k) => '"' + k + '"').join(', ') + '.', 'inputSchema.properties');
    const useText = tokens(name).join(' ') + '. ' + d;
    if (MONEY.test(useText)) push('anthropic-unsupported-use', null, 'Reads as moving money or crypto.', 'description');
    else if (AIMEDIA.test(useText)) push('anthropic-unsupported-use', null, 'Reads as AI generation of images, video or audio.', 'description');

    // ---- OpenAI
    const missing = ['readOnlyHint', 'destructiveHint', 'openWorldHint'].filter((k) => typeof a[k] !== 'boolean');
    if (missing.length) push('openai-hints-explicit', null, 'Not set to true or false: ' + missing.join(', ') + '.', 'annotations');
    if (!d) push('openai-description', null, 'No description.', 'description');
    const ntk = norm(name);
    if (PROMO.test(ntk)) push('openai-name-promotional', null, 'The name "' + name + '" contains promotional wording.', 'name');
    if (/^(tool|func|fn|function|op|operation|action|cmd|command|endpoint|method|api|call|x|t)_?\d+$/.test(ntk) || /[0-9a-f]{8,}/.test(ntk) || tokens(name).every((x) => x.length <= 2)) push('openai-name-opaque', null, 'The name "' + name + '" does not say what the tool does.', 'name');
    if (!readOnly && a.idempotentHint !== true && !RETRY_WORDS.test(d) && kind !== 'read') push('openai-retry', null, 'Neither idempotentHint: true nor any word on retries in the description.', 'description');
    if (conv.hard.length) push('openai-conversation-input', 'blocking', 'Asks for ' + conv.hard.map((k) => '"' + k + '"').join(', ') + '.', 'inputSchema.properties');
    else if (conv.soft.length) push('openai-conversation-input', 'attention', 'Takes ' + conv.soft.map((k) => '"' + k + '"').join(', ') + '; make sure it is task data, not conversation context.', 'inputSchema.properties');
    const cred = credentialArgs(t);
    if (cred.hard.length) push('openai-restricted-input', 'blocking', 'Asks for ' + cred.hard.map((k) => '"' + k + '"').join(', ') + '.', 'inputSchema.properties');
    else if (cred.soft.length) push('openai-restricted-input', 'attention', 'Takes ' + cred.soft.map((k) => '"' + k + '"').join(', ') + '; if this is an access credential, take it through authorization instead.', 'inputSchema.properties');
    const loc = locationArgs(t);
    if (loc.hard.length) push('openai-precise-location', 'blocking', 'Asks for coordinates: ' + loc.hard.map((k) => '"' + k + '"').join(', ') + '.', 'inputSchema.properties');
    else if (loc.soft.length) push('openai-precise-location', 'attention', 'Takes location fields ' + loc.soft.map((k) => '"' + k + '"').join(', ') + '.', 'inputSchema.properties');
    const execName = /(^|_)(execute|invoke|run|call|dispatch|perform|do)(_|$)/.test(ntk) || ['execute', 'invoke', 'dispatch', 'call', 'run'].includes(ntk);
    const opArg = pk.find((k) => /^(tool|tool_name|action|operation|operation_id|operationid|command|cmd|op|function|function_name|endpoint_name|method_name)$/.test(norm(k)) || /^[a-z]+_(command|cmd)$/.test(norm(k)) || (norm(k) === 'method' && !(isObj(p[k]) && Array.isArray(p[k].enum))));
    if (execName && opArg && !(isObj(p[opArg]) && Array.isArray(p[opArg].enum) && p[opArg].enum.length <= 3)) push('openai-generic-executor', null, 'Runs whatever "' + opArg + '" names.', 'inputSchema.properties.' + opArg);
    const lv = leadVerb(name);
    if (readOnly && JOB_V.has(lv)) push('openai-readonly-starts-job', null, 'The name starts with "' + lv + '" but readOnlyHint is true.', 'annotations.readOnlyHint');
    if (readOnly && a.destructiveHint === true) push('openai-readonly-destructive', null, 'readOnlyHint: true together with destructiveHint: true.', 'annotations.destructiveHint');

    // ---- both
    if (!readOnly && a.destructiveHint === false && kind === 'delete') push('annot-delete-marked-safe', null, 'The name reads as "' + (tokens(name).find((x) => DELETE_V.has(x)) || 'delete') + '" but destructiveHint is false.', 'annotations.destructiveHint');
    if (readOnly && (kind === 'create' || kind === 'update' || kind === 'delete') && !JOB_V.has(lv)) push('annot-write-marked-readonly', null, 'The name reads as a ' + kind + ' but readOnlyHint is true.', 'annotations.readOnlyHint');

    // ---- security scan over every string
    scanTool(t, (id, sev, msg, path) => push(id, sev, msg, path), (ctx.names || []).filter((n) => n !== name));

    // ---- quality
    const noDesc = pk.filter((k) => isObj(p[k]) && !(typeof p[k].description === 'string' && p[k].description.trim()) && !p[k].$ref);
    if (noDesc.length) push('schema-param-description', null, 'No description on ' + noDesc.slice(0, 6).map((k) => '"' + k + '"').join(', ') + (noDesc.length > 6 ? ' and ' + (noDesc.length - 6) + ' more' : '') + '.', 'inputSchema.properties');
    const noEnum = pk.filter((k) => CONSTRAINED.test(norm(k)) && isObj(p[k]) && (p[k].type === 'string' || p[k].type === undefined) && !p[k].enum && !has.call(p[k], 'const') && !p[k].pattern && !p[k].$ref && !p[k].oneOf && !p[k].anyOf);
    if (noEnum.length) push('schema-enum-missing', null, 'No enum on ' + noEnum.map((k) => '"' + k + '"').join(', ') + '.', 'inputSchema.properties');
    if (isObj(s) && Array.isArray(s.required)) {
      const undeclared = s.required.filter((r) => typeof r === 'string' && !has.call(p, r));
      const open = s.additionalProperties !== false || isObj(s.patternProperties);
      if (undeclared.length && !(s.properties === undefined && open)) push('schema-required-unknown', s.additionalProperties === false && !isObj(s.patternProperties) ? 'blocking' : 'attention', 'Required but not declared: ' + undeclared.map((k) => '"' + k + '"').join(', ') + (s.additionalProperties === false ? ', and additionalProperties is false, so no call can pass validation' : '') + '.', 'inputSchema.required');
    }
    if (isObj(s) && s.type === 'object' && s.additionalProperties !== false && s.unevaluatedProperties !== false && !isObj(s.additionalProperties) && !s.oneOf && !s.anyOf && !s.allOf)
      push('schema-additional-properties', null, 'inputSchema does not set additionalProperties: false.', 'inputSchema');
    const vague = pk.filter((k) => VAGUE.has(norm(k)));
    if (vague.length) push('schema-vague-param', null, 'Vague argument name ' + vague.map((k) => '"' + k + '"').join(', ') + '.', 'inputSchema.properties');
    const isList = LIST_V.has(tokens(name)[0]) || LIST_V.has(tokens(name)[tokens(name).length - 1]);
    if (isList && kind === 'read' && !pk.some((k) => PAGE_ARG.test(norm(k)))) push('schema-pagination', null, 'A list or search tool with no limit, page size or cursor argument.', 'inputSchema.properties');
    if (['search', 'query', 'find'].includes(tokens(name)[0]) && kind === 'read' && !pk.some((k) => RF_ARG.test(norm(k)))) push('schema-response-format', null, 'No response_format or fields argument.', 'inputSchema.properties');
    if (readOnly && !has.call(t, 'outputSchema')) push('schema-output-schema', null, 'A read-only tool with no outputSchema.', 'outputSchema');
    if (isObj(s)) {
      const branchTyped = [];
      ['oneOf', 'anyOf'].forEach((kw) => { if (Array.isArray(s[kw])) s[kw].forEach((b, i) => { if (isObj(b) && (has.call(b, 'type') || (isObj(b.properties) && Object.keys(b.properties).some((k) => isObj(b.properties[k]) && has.call(b.properties[k], 'type'))))) branchTyped.push(kw + '[' + i + ']'); }); });
      if (branchTyped.length) push('schema-oneof-branch-types', null, 'Type constraints inside ' + branchTyped.slice(0, 3).join(', ') + '.', 'inputSchema');
    }
    const openObj = pk.filter((k) => isObj(p[k]) && p[k].type === 'object' && !isObj(p[k].properties) && p[k].additionalProperties === undefined && !p[k].$ref && !p[k].patternProperties && !p[k].oneOf && !p[k].anyOf && !p[k].allOf);
    if (openObj.length) push('schema-open-object', null, 'Object argument with no declared fields: ' + openObj.map((k) => '"' + k + '"').join(', ') + '.', 'inputSchema.properties');
    if (d && !USE_WHEN.test(d)) push('design-use-when', null, 'The description does not say when to use the tool.', 'description');
    if (['create', 'open', 'start', 'begin', 'acquire', 'new', 'launch', 'spawn'].includes(tokens(name)[0]) && tokens(name).slice(1).some((x) => HANDLE_NOUN.test(x.replace(/s$/, ''))) && !LIFETIME.test(d)) push('design-handle-lifetime', null, 'Creates a handle but does not say when it expires.', 'description');

    return items;
  }

  // ---------------------------------------------------------------- write surface

  const RETRY_ARG = /(idempot|request_?id|client_?token|dedup|client_?reference|client_?request|operation_?id)/i;
  const VERSION_ARG = /(version|etag|if_?match|revision|expected_|updated_?at|^sha$|precondition|if_?unmodified|generation|resource_?version|lock_?token)/i;
  const VERSION_HEADER = /^(if-match|etag|if-unmodified-since|version|revision|if_match)$/i;
  const GUARD_ARG = /(confirm|dry_?run|preview|allow_|force|acknowledge|plan_?only|what_?if)/i;
  const MASK_ARG = /^(update_?mask|field_?mask|fields|mask|patch|changes|set_fields|paths)$/i;

  function surface(tools, perTool) {
    const rows = [];
    const tally = { retry: [0, 0], version: [0, 0], guard: [0, 0] };
    tools.forEach((t, idx) => {
      const a = ann(t);
      if (a.readOnlyHint === true) return;
      const kind0 = kindOf(t.name);
      if (kind0 === 'read') return; // named as a read; annotation gaps are reported elsewhere
      const p = props(t);
      const keys = Object.keys(p);
      const kind = kind0 || 'other write';
      const headerVersion = schemaFacts(schemaOf(t) || {}).headers.some((h) => typeof h.value === 'string' && VERSION_HEADER.test(h.value));
      const retryArg = keys.find((k) => RETRY_ARG.test(k));
      const versionArg = keys.find((k) => VERSION_ARG.test(k));
      const guardArg = keys.find((k) => GUARD_ARG.test(k));
      const found = [], missing = [], notes = [];
      const push = (id, sev, msg) => perTool[idx].findings.push({ id, section: 'surface', affects: ['surface'], severity: sev || CHECK[id].severity, message: msg, path: 'inputSchema.properties' });
      const want = (key, ok, label, foundLabel, id) => { tally[key][1] += 1; if (ok) { tally[key][0] += 1; found.push(foundLabel); } else { missing.push(label); push(id, null, 'Missing ' + label + '.'); } };
      if (kind === 'create') want('retry', !!retryArg || a.idempotentHint === true, 'a retry key or an idempotent declaration', retryArg ? 'retry key "' + retryArg + '"' : 'idempotentHint: true (declared, not shown)', 'surface-retry-key');
      if (kind === 'update' || kind === 'delete') want('version', !!versionArg || headerVersion, 'a version or precondition argument', versionArg ? 'version argument "' + versionArg + '"' : 'If-Match-style x-mcp-header', 'surface-version-guard');
      if (kind === 'delete') want('guard', !!guardArg, 'a confirm or dry-run argument', 'guard argument "' + guardArg + '"', 'surface-delete-guard');
      const lv = leadVerb(t.name);
      // Identifiers and scope (owner, repo, issue_number, namespace...) select the object; they are not fields of it.
      const nonId = keys.filter((k) => !/(^|_)(id|ids|key|name|path|slug|uid|uuid|number|num)$/i.test(norm(k)) &&
        !/^(owner|repo|repository|org|organization|organisation|workspace|namespace|project|team|account|tenant|branch|index|collection|database|db|schema|table|bucket)$/.test(norm(k)) &&
        !VERSION_ARG.test(k) && !RETRY_ARG.test(k));
      // MWS section 4: a tool whose schema requires every field is in full-replace mode.
      const sc = schemaOf(t);
      const req = isObj(sc) && Array.isArray(sc.required) ? sc.required : [];
      const allRequired = kind === 'update' && !REWIRE_V.has(lv) && nonId.length >= 2 && nonId.every((k) => req.includes(k)) && !keys.some((k) => isObj(p[k]) && p[k].type === 'object');
      if ((['replace', 'overwrite', 'put'].includes(lv) || allRequired) && !keys.some((k) => MASK_ARG.test(norm(k)))) {
        notes.push('full replacement without a field mask');
        push('surface-full-replace', null, (['replace', 'overwrite', 'put'].includes(lv) ? 'The name reads as "' + lv + '"' : 'Every one of its ' + nonId.length + ' field arguments is required') + ', and it takes no field mask.');
      }
      if (kind === 'delete' && !guardArg && keys.some((k) => isObj(p[k]) && (p[k].type === 'array' || /^(filter|query|where|selector|match|ids)$/.test(norm(k))))) {
        notes.push('bulk targets with no dry-run or confirm');
        push('surface-bulk-delete', null, 'Takes a list or filter of targets and no dry-run or confirm argument.');
      }
      if (kind === 'delete' && a.destructiveHint === false) notes.push('marked destructiveHint: false');
      rows.push({ name: t.name, kind, found, missing, notes });
    });
    const parts = [
      { key: 'retry', label: 'Create and send tools that take a retry key or declare themselves idempotent', have: tally.retry[0], of: tally.retry[1] },
      { key: 'version', label: 'Update and delete tools that take a version or precondition', have: tally.version[0], of: tally.version[1] },
      { key: 'guard', label: 'Delete tools that take a confirm or dry-run argument', have: tally.guard[0], of: tally.guard[1] },
    ];
    const used = parts.filter((x) => x.of > 0);
    if (!rows.length) return { writeTools: 0, score: null, grade: null, why: 'Every tool declares readOnlyHint: true or is named as a read, so there is no write surface to grade.', parts, rows };
    if (!used.length) return { writeTools: rows.length, score: null, grade: null, why: 'No tool name could be read as a create, update or delete, so this is not graded.', parts, rows };
    const score = Math.round((used.reduce((sum, x) => sum + x.have / x.of, 0) / used.length) * 100);
    return { writeTools: rows.length, score, grade: letter(score), why: null, parts, rows };
  }

  // ---------------------------------------------------------------- server-level checks

  function serverChecks(parsed, tools, perTool) {
    const out = [];
    const push = (id, severity, message, extra) => { const c = CHECK[id]; out.push(Object.assign({ id, section: c.section, affects: c.affects, severity: severity || c.severity, message, tool: null }, extra || {})); };
    if (parsed.badEntries && parsed.badEntries.length) push('spec-tool-shape', null, parsed.badEntries.length + ' entr' + (parsed.badEntries.length === 1 ? 'y' : 'ies') + ' (position ' + parsed.badEntries.slice(0, 5).join(', ') + ') ' + (parsed.badEntries.length === 1 ? 'is' : 'are') + ' not a tool object with a string name, and ' + (parsed.badEntries.length === 1 ? 'was' : 'were') + ' skipped.');
    const count = {};
    tools.forEach((t) => { count[t.name] = (count[t.name] || 0) + 1; });
    const dupes = Object.keys(count).filter((n) => count[n] > 1);
    if (dupes.length) {
      push('spec-name-unique', null, 'Repeated names: ' + dupes.join(', ') + '.');
      push('openai-name-unique', null, 'Repeated names: ' + dupes.join(', ') + '.');
    }
    const env = parsed.envelope || { kind: 'array', pages: [] };
    let era = 'unknown';
    const results = env.pages.map((pg) => pg.result);
    if (results.some((r) => has.call(r, 'resultType') || has.call(r, 'ttlMs') || has.call(r, 'cacheScope'))) era = '2026-07-28';
    else if (tools.some((t) => has.call(t, 'execution'))) era = '2025-11-25 or earlier';
    const checkEnvelope = env.kind === 'jsonrpc' || env.kind === 'pages' || era === '2026-07-28';
    if (checkEnvelope) {
      results.forEach((r, i) => {
        const pg = results.length > 1 ? 'Page ' + (i + 1) + ': ' : '';
        const newEra = era === '2026-07-28';
        if (!has.call(r, 'resultType')) push('spec-envelope-result-type', newEra ? 'attention' : 'advice', pg + 'No resultType in the result' + (newEra ? '' : ' (fine for a 2025-11-25 or earlier server)') + '.');
        else if (r.resultType !== 'complete') push('spec-envelope-result-type', 'blocking', pg + 'resultType is ' + JSON.stringify(r.resultType) + '; a tools/list result is "complete".');
        const miss = ['ttlMs', 'cacheScope'].filter((k) => !has.call(r, k));
        if (miss.length) push('spec-envelope-cache', newEra ? 'attention' : 'advice', pg + 'Missing ' + miss.join(' and ') + (newEra ? '' : ' (required from 2026-07-28 on)') + '.');
        if (has.call(r, 'ttlMs') && !(typeof r.ttlMs === 'number' && r.ttlMs >= 0 && isFinite(r.ttlMs))) push('spec-envelope-cache', 'blocking', pg + 'ttlMs is ' + JSON.stringify(r.ttlMs) + '; it must be a number of at least 0.');
        if (has.call(r, 'cacheScope') && !['public', 'private'].includes(r.cacheScope)) push('spec-envelope-cache', 'blocking', pg + 'cacheScope is ' + JSON.stringify(r.cacheScope) + '; it must be "public" or "private".');
      });
    }
    const last = results[results.length - 1];
    if (last && typeof last.nextCursor === 'string' && last.nextCursor) push('spec-pagination-partial', null, 'The ' + (results.length > 1 ? 'last pasted page' : 'answer') + ' has nextCursor ' + JSON.stringify(clip(last.nextCursor, 30)) + '; later pages were not pasted.');
    // near-duplicate descriptions
    const words = tools.map((t) => new Set(desc(t).toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 2)));
    const pairs = [];
    for (let i = 0; i < tools.length; i++) for (let j = i + 1; j < tools.length; j++) {
      const A = words[i], B = words[j];
      if (A.size < 5 || B.size < 5 || tools[i].name === tools[j].name) continue;
      let inter = 0; A.forEach((w) => { if (B.has(w)) inter += 1; });
      const jac = inter / (A.size + B.size - inter);
      if (jac >= 0.85) pairs.push(tools[i].name + ' and ' + tools[j].name + ' (' + Math.round(jac * 100) + '%)');
    }
    if (pairs.length) push('design-near-duplicate', null, 'Nearly identical descriptions: ' + pairs.slice(0, 4).join('; ') + '.');
    if (tools.length >= 10) {
      const tally = {};
      tools.forEach((t) => { const tk = tokens(t.name).map((x) => x.replace(/(?<=[a-z]{3})s$/, '')); new Set([tk[0], tk[tk.length - 1]].filter((x) => x && !verbClass(x))).forEach((x) => { tally[x] = (tally[x] || 0) + 1; }); if (/[.]/.test(t.name)) { const pre = t.name.split('.')[0]; tally['.' + pre] = (tally['.' + pre] || 0) + 1; } });
      const best = Math.max(0, ...Object.values(tally));
      if (best < tools.length / 2) push('design-namespace', null, tools.length + ' tools, and no service or resource word is shared by half of them.');
    }
    return { findings: out, era, envelopeChecked: checkEnvelope, dupes };
  }

  // ---------------------------------------------------------------- grading (rubric 2.0.0, see RUBRIC.md)

  const WEIGHTS = { tool: { blocking: 40, attention: 10, advice: 3 }, server: { blocking: 20, attention: 5, advice: 1 } };
  const BANDS = [['A', 90], ['B', 80], ['C', 65], ['D', 50], ['F', 0]];
  const ORDER = ['A', 'B', 'C', 'D', 'F'];
  const letter = (score) => BANDS.find((b) => score >= b[1])[0];
  const capAt = (g, cap) => (ORDER.indexOf(g) < ORDER.indexOf(cap) ? cap : g);
  const GRADED = ['spec', 'anthropic', 'openai', 'security', 'quality'];
  const SECTION_NAMES = { spec: 'MCP spec 2026-07-28', anthropic: 'Anthropic directory', openai: 'OpenAI directory', security: 'Poisoning and hidden text', quality: 'Schema and description quality', surface: 'Write-surface design', annotations: 'Annotations (both directories)' };

  function grade(perTool, server) {
    const sections = {};
    GRADED.forEach((sec) => {
      const toolScores = perTool.map((t) => Math.max(0, 100 - t.findings.filter((f) => f.affects.includes(sec)).reduce((s, f) => s + WEIGHTS.tool[f.severity], 0)));
      const mean = toolScores.length ? toolScores.reduce((a, b) => a + b, 0) / toolScores.length : 0;
      const sf = server.filter((f) => f.affects.includes(sec));
      const score = Math.max(0, Math.min(100, Math.round(mean - sf.reduce((s, f) => s + WEIGHTS.server[f.severity], 0))));
      const all = perTool.reduce((acc, t) => acc.concat(t.findings.filter((f) => f.affects.includes(sec))), []).concat(sf);
      const counts = { blocking: 0, attention: 0, advice: 0 };
      all.forEach((f) => { counts[f.severity] += 1; });
      const blockedTools = perTool.filter((t) => t.findings.some((f) => f.affects.includes(sec) && f.severity === 'blocking')).length;
      sections[sec] = { name: SECTION_NAMES[sec], score, grade: letter(score), counts, blockedTools, total: perTool.length, caps: [], ready: counts.blocking === 0 };
    });
    const any = (pred) => perTool.some((t) => t.findings.some(pred)) || server.some(pred);
    // Cap 1: a section with any blocking item is at most B.
    GRADED.forEach((sec) => { const s = sections[sec]; if (s.counts.blocking > 0 && ORDER.indexOf(s.grade) < ORDER.indexOf('B')) { s.grade = 'B'; s.caps.push('Capped at B: ' + s.counts.blocking + ' blocking item' + (s.counts.blocking === 1 ? '' : 's') + '.'); } });
    // Cap 2: a failed MCP MUST caps spec and both directory grades at C.
    if (any((f) => f.section === 'spec' && f.severity === 'blocking')) ['spec', 'anthropic', 'openai'].forEach((sec) => { const s = sections[sec]; const g = capAt(s.grade, 'C'); if (g !== s.grade) { s.grade = g; s.caps.push('Capped at C: the list fails an MCP specification MUST.'); } });
    // Cap 3: any blocking poisoning finding gives F for security and both directories.
    if (any((f) => f.section === 'security' && f.severity === 'blocking')) ['security', 'anthropic', 'openai'].forEach((sec) => { const s = sections[sec]; s.grade = 'F'; s.caps.push('F: hidden or injected instructions found; both directories reject these.'); });
    return sections;
  }

  // ---------------------------------------------------------------- MWS-ANN-4 (catalog mode of the mcp-writecheck CLI)

  function mwsAnn4(t) {
    const a = ann(t);
    const miss = [];
    if (typeof a.readOnlyHint !== 'boolean') miss.push('readOnlyHint');
    if (a.readOnlyHint !== true && typeof a.destructiveHint !== 'boolean') miss.push('destructiveHint');
    return miss.length
      ? { requirement: 'MWS-ANN-4', level: 'SHOULD', tool: t.name, verdict: 'violated', detail: 'Does not set ' + miss.join(' or ') + ' explicitly.' }
      : { requirement: 'MWS-ANN-4', level: 'SHOULD', tool: t.name, verdict: 'held', detail: 'Sets readOnlyHint' + (a.readOnlyHint === true ? '' : ' and destructiveHint') + ' explicitly.' };
  }

  const NOT_TESTED = [
    ['Two writers editing one object', 'MWS-CONC-1 to 6'],
    ['A write based on stale data', 'MWS-CONC-2, MWS-UPD-2'],
    ['A retry after a lost answer', 'MWS-RETRY-1 to 3'],
    ['Whether a reported success is true', 'MWS-RES-1 to 4'],
    ['Unknown, misspelled or wrongly typed arguments', 'MWS-IN-1 to 7'],
    ['Writes that reach the wrong object or scope', 'MWS-TGT-1 to 3'],
    ['Whether read-only and non-destructive hints match behavior', 'MWS-ANN-1 to 3, MWS-ANN-5'],
    ['Partial writes, read-only modes and tool filters', 'MWS-ATOM-1 to 2, MWS-CFG-1 to 4'],
    ['Whether tools/list returns the same order every time', 'MCP 2026-07-28 (SHOULD, needs two calls)'],
    ['Whether results match outputSchema', 'MCP 2026-07-28 (MUST, needs real calls)'],
  ];

  // ---------------------------------------------------------------- SHA-256 (sync, pure) and canonical JSON, for definition pinning

  const K256 = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  function utf8(str) { if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(str); const s = unescape(encodeURIComponent(str)); const b = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i); return b; }
  function sha256(str) {
    const msg = utf8(str);
    const len = msg.length, bitLen = len * 8;
    const total = ((len + 9 + 63) >> 6) << 6;
    const buf = new Uint8Array(total); buf.set(msg); buf[len] = 0x80;
    const dv = new DataView(buf.buffer);
    dv.setUint32(total - 4, bitLen >>> 0); dv.setUint32(total - 8, Math.floor(bitLen / 0x100000000));
    const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const W = new Uint32Array(64);
    const r = (x, n) => (x >>> n) | (x << (32 - n));
    for (let o = 0; o < total; o += 64) {
      for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) { const s0 = r(W[i - 15], 7) ^ r(W[i - 15], 18) ^ (W[i - 15] >>> 3); const s1 = r(W[i - 2], 17) ^ r(W[i - 2], 19) ^ (W[i - 2] >>> 10); W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0; }
      let [a, b, c, d, e, f, g, h] = H;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (r(e, 6) ^ r(e, 11) ^ r(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + W[i]) >>> 0;
        const t2 = ((r(a, 2) ^ r(a, 13) ^ r(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
        h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
      }
      H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    return Array.from(H).map((x) => x.toString(16).padStart(8, '0')).join('');
  }
  function canonical(x) {
    if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
    if (isObj(x)) return '{' + Object.keys(x).sort().map((k) => JSON.stringify(k) + ':' + canonical(x[k])).join(',') + '}';
    return JSON.stringify(x === undefined ? null : x);
  }
  const toolHash = (t) => sha256(canonical(t));

  // ---------------------------------------------------------------- analyse

  function analyse(input, opts) {
    opts = opts || {};
    const parsed = Array.isArray(input) ? { tools: input.filter((t) => isObj(t) && typeof t.name === 'string'), badEntries: input.map((t, i) => (isObj(t) && typeof t.name === 'string' ? -1 : i)).filter((i) => i >= 0), envelope: { kind: 'array', pages: [] } } : input;
    const tools = parsed.tools;
    const ctx = { opts, engines: new Set(), names: tools.map((t) => t.name) };
    const perTool = tools.map((t) => {
      const json = JSON.stringify(t);
      const bytes = utf8(json).length;
      return { name: t.name, title: titleOf(t), hash: toolHash(t), bytes, findings: checkTool(t, ctx) };
    });
    const sur = surface(tools, perTool);
    const srv = serverChecks(parsed, tools, perTool);
    perTool.forEach((t) => t.findings.forEach((f) => { f.tool = t.name; }));
    const sections = grade(perTool, srv.findings);
    sections.surface = { name: SECTION_NAMES.surface, score: sur.score, grade: sur.grade, why: sur.why, writeTools: sur.writeTools, parts: sur.parts, rows: sur.rows, caps: [] };
    const totalBytes = perTool.reduce((s, r) => s + r.bytes, 0);
    const engines = Array.from(ctx.engines).filter(Boolean);
    return {
      tool: 'IsoKron MCP check',
      report_schema: REPORT_SCHEMA,
      rubric_version: RUBRIC_VERSION,
      spec_version: SPEC_VERSION,
      sources_read: SOURCES_READ,
      input: { envelope: (parsed.envelope || {}).kind || 'array', pages: ((parsed.envelope || {}).pages || []).length, tools: tools.length, skipped: (parsed.badEntries || []).length, era: srv.era, envelopeChecked: srv.envelopeChecked, catalogHash: sha256(canonical(tools)) },
      validator: engines.length ? engines.join('; ') : (getAjv(opts) ? ENGINE_AJV : ENGINE_MIN),
      sections,
      tools: perTool,
      server: srv.findings,
      weight: { bytes: totalBytes, approxTokens: Math.round(totalBytes / 4), heaviest: [...perTool].sort((x, y) => y.bytes - x.bytes).slice(0, 3).map((r) => ({ name: r.name, bytes: r.bytes })) },
      mws: tools.map(mwsAnn4),
      notTested: NOT_TESTED,
    };
  }

  function check(text, opts) {
    const p = parseInput(text);
    if (p.error) return p;
    return analyse(p, opts);
  }

  const allFindings = (r) => r.tools.reduce((acc, t) => acc.concat(t.findings), []).concat(r.server);

  // ---------------------------------------------------------------- fixes

  function suggestAnnotations(t) {
    const a = ann(t);
    const kind = kindOf(t.name);
    const lv = leadVerb(t.name);
    let ro = typeof a.readOnlyHint === 'boolean' ? a.readOnlyHint : kind === 'read';
    if (ro && (kind === 'create' || kind === 'update' || kind === 'delete' || JOB_V.has(lv))) ro = false;
    let destr;
    if (ro) destr = false;
    else if (kind === 'delete') destr = true;
    else destr = typeof a.destructiveHint === 'boolean' ? a.destructiveHint : true;
    const out = Object.assign({}, a, { readOnlyHint: ro, destructiveHint: destr, openWorldHint: typeof a.openWorldHint === 'boolean' ? a.openWorldHint : true });
    return out;
  }

  const SNIPPETS = {
    'anthropic-title': (t) => '"title": ' + JSON.stringify(humanize(t.name)),
    'anthropic-hint': (t) => '"annotations": ' + JSON.stringify(suggestAnnotations(t)),
    'openai-hints-explicit': (t) => '"annotations": ' + JSON.stringify(suggestAnnotations(t)),
    'annot-delete-marked-safe': (t) => '"annotations": ' + JSON.stringify(Object.assign({}, ann(t), { readOnlyHint: false, destructiveHint: true })),
    'annot-write-marked-readonly': (t) => '"annotations": ' + JSON.stringify(suggestAnnotations(t)),
    'openai-readonly-starts-job': (t) => '"annotations": ' + JSON.stringify(suggestAnnotations(t)),
    'openai-readonly-destructive': (t) => '"annotations": ' + JSON.stringify(Object.assign({}, ann(t), { destructiveHint: false })),
    'spec-input-schema-missing': () => '"inputSchema": { "type": "object", "additionalProperties": false }',
    'spec-input-schema-root-object': (t) => { const s = schemaOf(t); return '"inputSchema": ' + JSON.stringify(Object.assign({ type: 'object' }, isObj(s) ? s : {}, { type: 'object' })); },
    'schema-additional-properties': () => '"additionalProperties": false',
    'surface-retry-key': () => '"idempotency_key": { "type": "string", "description": "Client-chosen key. A repeated call with the same key returns the first result instead of creating a duplicate." }',
    'surface-version-guard': () => '"expected_version": { "type": "string", "description": "The version returned by the last read. The write is refused with a conflict if the object has changed since." }',
    'surface-delete-guard': () => '"dry_run": { "type": "boolean", "default": true, "description": "When true, return what would be deleted without deleting it." }',
    'schema-pagination': () => '"limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },\n"cursor": { "type": "string", "description": "Cursor from the previous page." }',
    'schema-response-format': () => '"response_format": { "type": "string", "enum": ["concise", "detailed"], "default": "concise" }',
    'openai-retry': (t) => '"description": ' + JSON.stringify(desc(t) + (desc(t) && !/[.!?]$/.test(desc(t)) ? '.' : '') + ' Calling it again with the same arguments repeats the effect.'),
    'design-use-when': (t) => '"description": ' + JSON.stringify(desc(t) + (desc(t) && !/[.!?]$/.test(desc(t)) ? '.' : '') + ' Use this when … Do not use for …'),
    'spec-envelope-result-type': () => '"resultType": "complete"',
    'spec-envelope-cache': () => '"ttlMs": 300000,\n"cacheScope": "private"',
    'schema-enum-missing': (t, f) => { const k = (f.message.match(/"([^"]+)"/) || [])[1] || 'state'; return JSON.stringify(k) + ': { "type": "string", "enum": ["…", "…"], "description": "…" }'; },
  };
  ['sec-invisible-encoding', 'sec-bidi-controls', 'sec-zero-width', 'sec-control-chars'].forEach((id) => { SNIPPETS[id] = (t, f) => { const path = (f.path || '').replace(/ \(key\)$/, ''); const v = getPath(t, path); return typeof v === 'string' ? JSON.stringify(path.split('.').pop()) + ': ' + JSON.stringify(v.replace(STRIP_RE, '')) : null; }; });

  function getPath(obj, path) {
    if (!path) return undefined;
    let cur = obj;
    const parts = path.replace(/\[(\d+)\]/g, '.$1').split('.');
    for (const p of parts) { if (cur === null || typeof cur !== 'object') return undefined; cur = cur[p]; }
    return cur;
  }

  function snippetFor(tool, finding) {
    const fn = SNIPPETS[finding.id];
    if (!fn) return null;
    try { return fn(tool, finding) || null; } catch (e) { return null; }
  }

  function stripDeep(x, changes, path) {
    if (typeof x === 'string') { const y = x.replace(STRIP_RE, (c) => (c === '\n' || c === '\t' || c === '\r' ? c : '')); if (y !== x) changes.push(path); return y; }
    if (Array.isArray(x)) return x.map((v, i) => stripDeep(v, changes, path + '[' + i + ']'));
    if (isObj(x)) { const o = {}; Object.keys(x).forEach((k) => { const nk = stripDeep(k, changes, path + '.' + k + ' (key)'); o[nk] = stripDeep(x[k], changes, path ? path + '.' + k : k); }); return o; }
    return x;
  }

  // Applies the changes a tool list can safely carry; returns the fixed list in the pasted shape, plus every change with a review flag.
  function fixCatalog(parsed) {
    const changes = [];
    const fixed = parsed.tools.map((t0) => {
      const strip = [];
      const t = stripDeep(t0, strip, '');
      if (strip.length) changes.push({ tool: t.name, change: 'Removed invisible or control characters in ' + strip.slice(0, 3).join(', ') + (strip.length > 3 ? ' and ' + (strip.length - 3) + ' more' : '') + '.', review: false });
      if (t.inputSchema === undefined && t.input_schema !== undefined) { t.inputSchema = t.input_schema; delete t.input_schema; changes.push({ tool: t.name, change: 'Renamed input_schema to inputSchema.', review: false }); }
      if (t.inputSchema === undefined || t.inputSchema === null) { t.inputSchema = { type: 'object' }; changes.push({ tool: t.name, change: 'Added inputSchema {"type": "object"} (accepts any object; declare the real arguments).', review: true }); }
      else if (isObj(t.inputSchema) && t.inputSchema.type !== 'object') { t.inputSchema = Object.assign({ type: 'object' }, t.inputSchema, { type: 'object' }); changes.push({ tool: t.name, change: 'Set inputSchema type to "object".', review: false }); }
      if (!titleOf(t)) { t.title = humanize(t.name); changes.push({ tool: t.name, change: 'Added title "' + t.title + '" (check the wording).', review: true }); }
      const before = ann(t);
      const after = suggestAnnotations(t);
      const diffs = ['readOnlyHint', 'destructiveHint', 'openWorldHint'].filter((k) => before[k] !== after[k]);
      if (diffs.length) {
        t.annotations = after;
        const parts = diffs.map((k) => k + ': ' + (has.call(before, k) ? JSON.stringify(before[k]) + ' → ' : '') + after[k]);
        changes.push({ tool: t.name, change: 'Annotations ' + parts.join(', ') + '. Inferred from the name and the specification defaults; confirm each matches what the tool does.', review: true });
      }
      const s = t.inputSchema;
      if (isObj(s) && isObj(s.properties) && s.additionalProperties === undefined && s.unevaluatedProperties === undefined && !s.oneOf && !s.anyOf && !s.allOf && !s.patternProperties) {
        s.additionalProperties = false;
        changes.push({ tool: t.name, change: 'Added "additionalProperties": false (the server must also reject unknown arguments).', review: true });
      }
      return t;
    });
    const env = parsed.envelope || { kind: 'array' };
    let out;
    if (env.kind === 'array') out = fixed;
    else if (env.kind === 'jsonrpc' && env.pages.length === 1) out = Object.assign({}, env.pages[0].rpc, { result: Object.assign({}, env.pages[0].result, { tools: fixed }) });
    else out = { tools: fixed };
    return { json: JSON.stringify(out, null, 2), changes, tools: fixed };
  }

  // ---------------------------------------------------------------- diff (rug-pull check)

  function diffCatalogs(oldTools, newTools) {
    const byName = (list) => { const m = new Map(); list.forEach((t) => { if (isObj(t) && typeof t.name === 'string' && !m.has(t.name)) m.set(t.name, t); }); return m; };
    const A = byName(oldTools), B = byName(newTools);
    const added = [], removed = [], changed = [];
    let unchanged = 0;
    A.forEach((t, n) => { if (!B.has(n)) removed.push(n); });
    B.forEach((t, n) => {
      if (!A.has(n)) { added.push({ name: n, readOnlyHint: ann(t).readOnlyHint, destructiveHint: ann(t).destructiveHint }); return; }
      const o = A.get(n);
      if (toolHash(o) === toolHash(t)) { unchanged += 1; return; }
      const ch = [];
      const ao = ann(o), an = ann(t);
      ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint'].forEach((k) => {
        if (ao[k] !== an[k]) {
          const risky = (k === 'readOnlyHint' && an[k] === true) || (k === 'destructiveHint' && an[k] !== true && ao[k] === true) || (k === 'idempotentHint' && an[k] === true);
          ch.push({ field: 'annotations.' + k, from: ao[k], to: an[k], risk: risky ? 'high' : 'low', note: risky ? 'A client may now run this tool with less confirmation.' : '' });
        }
      });
      if (titleOf(o) !== titleOf(t)) ch.push({ field: 'title', from: titleOf(o), to: titleOf(t), risk: 'low' });
      if (desc(o) !== desc(t)) ch.push({ field: 'description', from: clip(desc(o), 200), to: clip(desc(t), 200), risk: 'medium', note: 'Re-read the new description before trusting it.' });
      const po = Object.keys(props(o)), pn = Object.keys(props(t));
      const addArgs = pn.filter((k) => !po.includes(k)), remArgs = po.filter((k) => !pn.includes(k));
      if (addArgs.length) ch.push({ field: 'arguments added', to: addArgs.join(', '), risk: 'medium' });
      if (remArgs.length) ch.push({ field: 'arguments removed', from: remArgs.join(', '), risk: 'medium' });
      const so = schemaOf(o) || {}, sn = schemaOf(t) || {};
      const ro = Array.isArray(so.required) ? so.required : [], rn = Array.isArray(sn.required) ? sn.required : [];
      if (canonical(ro.slice().sort()) !== canonical(rn.slice().sort())) ch.push({ field: 'required', from: ro.join(', '), to: rn.join(', '), risk: 'low' });
      if (!addArgs.length && !remArgs.length && canonical(so) !== canonical(sn) && canonical(ro.slice().sort()) === canonical(rn.slice().sort())) ch.push({ field: 'inputSchema', note: 'Argument definitions changed.', risk: 'medium' });
      if (canonical(o.outputSchema) !== canonical(t.outputSchema)) ch.push({ field: 'outputSchema', note: 'Changed.', risk: 'low' });
      if (!ch.length) ch.push({ field: 'other', note: 'Other fields changed (icons, _meta or similar).', risk: 'low' });
      changed.push({ name: n, oldHash: toolHash(o).slice(0, 12), newHash: toolHash(t).slice(0, 12), changes: ch });
    });
    return { added, removed, changed, unchanged, highRisk: changed.filter((c) => c.changes.some((x) => x.risk === 'high')).map((c) => c.name) };
  }

  // ---------------------------------------------------------------- permalink (compressed input in the URL fragment; never sent to a server)

  function b64urlEncode(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    const b = typeof root.btoa === 'function' ? root.btoa(s) : Buffer.from(s, 'binary').toString('base64');
    return b.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function b64urlDecode(str) {
    const b = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = typeof root.atob === 'function' ? root.atob(b + '==='.slice((b.length + 3) % 4)) : Buffer.from(b, 'base64').toString('binary');
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  async function pipeThrough(bytes, stream) {
    const res = new Response(new Blob([bytes]).stream().pipeThrough(stream));
    return new Uint8Array(await res.arrayBuffer());
  }
  async function encodeFragment(text) {
    if (typeof root.CompressionStream !== 'function') throw new Error('This browser cannot compress; private links need a current browser.');
    const z = await pipeThrough(utf8(text), new root.CompressionStream('deflate-raw'));
    return 'r=' + RUBRIC_VERSION + '&z=' + b64urlEncode(z);
  }
  // Limits for private links: a fragment over 256 KB is refused before decoding, and decompression stops at 5 MB,
  // so a crafted link cannot make the page inflate a "zip bomb".
  const LINK_MAX_FRAGMENT = 256 * 1024;
  const LINK_MAX_OUTPUT = 5 * 1024 * 1024;
  async function inflateCapped(bytes, max) {
    const reader = new Blob([bytes]).stream().pipeThrough(new root.DecompressionStream('deflate-raw')).getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > max) {
        try { await reader.cancel(); } catch (e) { /* already closed */ }
        throw new Error('The tool list in this link is larger than ' + (max / 1048576) + ' MB when unpacked, so it was not opened.');
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) { out.set(c, off); off += c.length; }
    return out;
  }
  async function decodeFragment(hash, limits) {
    const lim = Object.assign({ fragment: LINK_MAX_FRAGMENT, output: LINK_MAX_OUTPUT }, limits || {});
    const h = String(hash || '').replace(/^#/, '');
    if (h.length > lim.fragment) throw new Error('This link is ' + Math.round(h.length / 1024) + ' KB, more than the ' + Math.round(lim.fragment / 1024) + ' KB a private link may carry, so it was not opened.');
    const params = {};
    h.split('&').forEach((kv) => { const i = kv.indexOf('='); if (i > 0) params[kv.slice(0, i)] = kv.slice(i + 1); });
    if (!params.z) return null;
    if (!/^[A-Za-z0-9_-]+$/.test(params.z)) throw new Error('The link is damaged: it contains characters a private link never has.');
    if (typeof root.DecompressionStream !== 'function') throw new Error('This browser cannot decompress the link.');
    let bytes;
    try { bytes = await inflateCapped(b64urlDecode(params.z), lim.output); } catch (e) {
      if (/larger than/.test(e.message)) throw e;
      throw new Error('The link is damaged or cut short (often by a chat app); its tool list could not be unpacked.');
    }
    const text = typeof TextDecoder !== 'undefined' ? new TextDecoder().decode(bytes) : Buffer.from(bytes).toString('utf8');
    return { text, rubric: params.r || null, sameRubric: params.r === RUBRIC_VERSION };
  }

  // ---------------------------------------------------------------- exports

  const SEV_LABEL = { blocking: 'Blocking', attention: 'Attention', advice: 'Advice' };
  // Table-cell text: escape pipes, backslashes and Markdown/HTML punctuation, fold newlines.
  const mdEsc = (s) => String(s).replace(/\r?\n|\r/g, ' ').replace(/([\\`*_[\]<>|])/g, '\\$1');
  // A tool name as inline code: names come from the pasted list, so they may hold backticks, pipes or newlines.
  const mdCode = (s) => {
    const t = String(s).replace(/\r?\n|\r/g, ' ').replace(/\|/g, '\\|');
    const run = Math.max(0, ...(t.match(/`+/g) || []).map((m) => m.length));
    const fence = '`'.repeat(run + 1);
    return fence + (run ? ' ' + t + ' ' : t) + fence;
  };

  function toMarkdown(r) {
    const out = [];
    out.push('# MCP tool list check', '');
    out.push('Rubric ' + r.rubric_version + ', MCP specification ' + r.spec_version + ', directory rules as read on ' + r.sources_read + '. ' + r.input.tools + ' tools' + (r.input.skipped ? ', ' + r.input.skipped + ' entries skipped' : '') + '. Protocol era: ' + r.input.era + '. Schema validator: ' + r.validator + '.', '');
    out.push('| Section | Grade | Score | Blocking | Attention | Advice | Notes |', '|---|---|---|---|---|---|---|');
    GRADED.forEach((k) => { const s = r.sections[k]; out.push('| ' + s.name + ' | ' + s.grade + ' | ' + s.score + ' | ' + s.counts.blocking + ' | ' + s.counts.attention + ' | ' + s.counts.advice + ' | ' + mdEsc((k === 'anthropic' || k === 'openai' ? (s.ready ? 'No blocking items. ' : 'Not ready: ' + s.blockedTools + ' of ' + s.total + ' tools blocked. ') : '') + s.caps.join(' ')) + ' |'); });
    const su = r.sections.surface;
    out.push('| ' + su.name + ' | ' + (su.grade || 'n/a') + ' | ' + (su.score === null ? 'n/a' : su.score) + ' | | | | ' + mdEsc(su.why || su.writeTools + ' write tools') + ' |');
    out.push('', '## Findings', '', '| Tool | Severity | Check | Finding | Source |', '|---|---|---|---|---|');
    allFindings(r).filter((f) => f.section !== 'surface').forEach((f) => out.push('| ' + (f.tool ? mdCode(f.tool) : '(server)') + ' | ' + SEV_LABEL[f.severity] + ' | [' + f.id + '](' + CHECK[f.id].docs + ') | ' + mdEsc(f.message) + ' | [' + mdEsc(CHECK[f.id].sourceTitle) + '](' + CHECK[f.id].source + ') |'));
    out.push('', '## Write-surface design (static, by tool name and arguments; not a test)', '');
    out.push(su.grade ? '- Grade ' + su.grade + ' (' + su.score + ') across ' + su.writeTools + ' write tools' : '- Not graded. ' + su.why);
    su.parts.filter((p) => p.of > 0).forEach((p) => out.push('- ' + p.label + ': ' + p.have + ' of ' + p.of));
    if (su.rows.length) { out.push('', '| Tool | Read as | Found | Missing | Notes |', '|---|---|---|---|---|'); su.rows.forEach((w) => out.push('| ' + mdCode(w.name) + ' | ' + w.kind + ' | ' + mdEsc(w.found.join('; ') || 'none') + ' | ' + mdEsc(w.missing.join('; ') || 'nothing') + ' | ' + mdEsc(w.notes.join('; ')) + ' |')); }
    out.push('', '## MWS 0.9 records (catalog only)', '', '| Requirement | Tool | Verdict | Detail |', '|---|---|---|---|');
    r.mws.forEach((m) => out.push('| ' + mdEsc(m.requirement) + ' (' + mdEsc(m.level) + ') | ' + mdCode(m.tool) + ' | ' + mdEsc(m.verdict) + ' | ' + mdEsc(m.detail) + ' |'));
    out.push('', 'Every other MWS requirement is not tested by a tool list alone. MWS 0.9 section 5.2 forbids totals, so none is given.');
    out.push('', '## Definition hashes (SHA-256 of canonical JSON)', '', '- Catalog: `' + r.input.catalogHash + '`');
    r.tools.forEach((t) => out.push('- ' + mdCode(t.name) + ': `' + t.hash + '`'));
    return out.join('\n');
  }

  function toJSON(r) {
    const enrich = (f) => Object.assign({}, f, { title: CHECK[f.id].title, docs: CHECK[f.id].docs, source: CHECK[f.id].source });
    return JSON.stringify(Object.assign({}, r, { tools: r.tools.map((t) => Object.assign({}, t, { findings: t.findings.map(enrich) })), server: r.server.map(enrich) }), null, 2);
  }

  function toSarif(r) {
    const used = Array.from(new Set(allFindings(r).map((f) => f.id)));
    const level = { blocking: 'error', attention: 'warning', advice: 'note' };
    return JSON.stringify({
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'isokron-mcp-check', version: RUBRIC_VERSION, informationUri: 'https://isokron.ai/mcp-check', rules: used.map((id) => ({ id, name: id, shortDescription: { text: CHECK[id].title }, fullDescription: { text: CHECK[id].explain }, helpUri: CHECK[id].docs, defaultConfiguration: { level: level[CHECK[id].severity] } })) } },
        results: allFindings(r).map((f) => ({ ruleId: f.id, level: level[f.severity], message: { text: (f.tool ? f.tool + ': ' : '') + f.message }, locations: [{ logicalLocations: [{ name: f.tool || 'tools/list', kind: 'object', fullyQualifiedName: (f.tool || 'tools/list') + (f.path ? '.' + f.path : '') }] }] })),
      }],
    }, null, 2);
  }

  // shields.io endpoint JSON, for a README badge served from a stored public report.
  function badgeJson(r) {
    const g = [r.sections.anthropic.grade, r.sections.openai.grade];
    const worst = g.sort((x, y) => ORDER.indexOf(y) - ORDER.indexOf(x))[0];
    return { schemaVersion: 1, label: 'MCP check', message: 'Claude ' + r.sections.anthropic.grade + ' · ChatGPT ' + r.sections.openai.grade + ' · spec ' + r.sections.spec.grade, color: { A: 'brightgreen', B: 'green', C: 'yellow', D: 'orange', F: 'red' }[worst] };
  }

  return {
    RUBRIC_VERSION, REPORT_SCHEMA, SPEC_VERSION, SOURCES_READ, DOCS_BASE, SOURCES: SRC, CHECKS, CHECK, WEIGHTS, BANDS, NOT_TESTED, SECTION_NAMES,
    parseInput, parseData, analyse, check, allFindings, fixCatalog, snippetFor, suggestAnnotations, diffCatalogs,
    encodeFragment, decodeFragment, toMarkdown, toJSON, toSarif, badgeJson,
    sha256, canonical, toolHash, kindOf, tokens, humanize, letter,
    _internal: { schemaFacts, checkHeaders, validateSchema, minimalValidate, credentialArgs, locationArgs, conversationArgs, mwsAnn4, surface },
  };
});
