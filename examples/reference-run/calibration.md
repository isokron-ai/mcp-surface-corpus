# Surface corpus: calibration report

Generated 2026-11-19T08:11:30.102Z. Rubric 2.1.0, 76 checks. Public example run on named reference servers: nothing is withheld. No server of the corpus is named.

## What was acquired

- Servers: 3
- Live list (server started in the sandbox), of those with a launch recipe: 3 of 3 (100%)
- Static list (read from source): 1 of 3 (33%)
- README names: 2 of 3 (67%)
- In the MCP Registry, of those looked up: 0 of 2 (0%)
- Starts with no environment set: 3 of 3 (100%)
- Tools per server: median 16 (quartiles 9.5 to 16, 3 servers)
- Estimated tokens of the list (bytes/4): median 4845 (quartiles 2960 to 5637.5, 3 servers)

## Checks on live lists

3 servers.

### Fire on almost every server (at least 90%)

- `spec-envelope-result-type` (attention): 100%
- `spec-envelope-cache` (attention): 100%
- `schema-additional-properties` (advice): 100%
- `design-use-when` (advice): 100%

### Never fire

`spec-tool-shape`, `spec-input-schema-missing`, `spec-input-schema-field-name`, `spec-input-schema-root-object`, `spec-schema-valid`, `spec-schema-dialect`, `spec-ref-remote`, `spec-composition-bounds`, `spec-name-length`, `spec-name-charset`, `spec-name-unique`, `spec-x-mcp-header`, `spec-x-mcp-header-sensitive`, `spec-field-types`, `spec-annotation-key-case`, `spec-icon-scheme`, `spec-meta-key`, `spec-meta-reserved`, `spec-pagination-partial`, `spec-execution-legacy`, `anthropic-hint`, `anthropic-name-length`, `anthropic-read-write-split`, `anthropic-api-docs`, `anthropic-conversation-data`, `anthropic-unsupported-use`, `openai-hints-explicit`, `openai-description`, `openai-name-unique`, `openai-name-promotional`, `openai-name-opaque`, `openai-conversation-input`, `openai-restricted-input`, `openai-generic-executor`, `openai-readonly-destructive`, `annot-delete-marked-safe`, `annot-write-marked-readonly`, `sec-invisible-encoding`, `sec-bidi-controls`, `sec-zero-width`, `sec-control-chars`, `sec-homoglyph`, `sec-html-comment`, `sec-instruction-markup`, `sec-instruction-phrases`, `sec-cross-tool-steering`, `sec-encoded-blob`, `sec-external-instructions`, `sec-secret-seeking`, `schema-param-description`, `schema-enum-missing`, `schema-required-unknown`, `schema-oneof-branch-types`, `schema-open-object`, `design-near-duplicate`, `design-handle-lifetime`, `surface-retry-key`, `surface-delete-guard`, `surface-bulk-delete`

### Prevalence

| Check | Servers |
|---|---|
| `spec-envelope-result-type` | 100% |
| `spec-envelope-cache` | 100% |
| `schema-additional-properties` | 100% |
| `design-use-when` | 100% |
| `anthropic-hint-platforms-differ` | 67% |
| `anthropic-description` | 67% |
| `openai-retry` | 67% |
| `surface-version-guard` | 67% |
| `anthropic-title` | 33% |
| `openai-precise-location` | 33% |
| `openai-readonly-starts-job` | 33% |
| `schema-vague-param` | 33% |
| `schema-pagination` | 33% |
| `schema-response-format` | 33% |
| `schema-output-schema` | 33% |
| `design-namespace` | 33% |
| `surface-full-replace` | 33% |

## Checks on static lists

1 servers.

### Fire on almost every server (at least 90%)

- `spec-execution-legacy` (advice): 100%
- `anthropic-hint-platforms-differ` (attention): 100%
- `openai-retry` (attention): 100%
- `schema-additional-properties` (advice): 100%
- `schema-pagination` (advice): 100%
- `schema-response-format` (advice): 100%
- `schema-output-schema` (advice): 100%
- `design-use-when` (advice): 100%
- `surface-version-guard` (attention): 100%

### Never fire

`spec-tool-shape`, `spec-input-schema-missing`, `spec-input-schema-field-name`, `spec-input-schema-root-object`, `spec-schema-valid`, `spec-schema-dialect`, `spec-ref-remote`, `spec-composition-bounds`, `spec-name-length`, `spec-name-charset`, `spec-name-unique`, `spec-x-mcp-header`, `spec-x-mcp-header-sensitive`, `spec-field-types`, `spec-annotation-key-case`, `spec-icon-scheme`, `spec-meta-key`, `spec-meta-reserved`, `spec-envelope-result-type`, `spec-envelope-cache`, `spec-pagination-partial`, `anthropic-title`, `anthropic-hint`, `anthropic-name-length`, `anthropic-read-write-split`, `anthropic-api-docs`, `anthropic-description`, `anthropic-conversation-data`, `anthropic-unsupported-use`, `openai-hints-explicit`, `openai-description`, `openai-name-unique`, `openai-name-promotional`, `openai-name-opaque`, `openai-conversation-input`, `openai-restricted-input`, `openai-precise-location`, `openai-generic-executor`, `openai-readonly-starts-job`, `openai-readonly-destructive`, `annot-delete-marked-safe`, `annot-write-marked-readonly`, `sec-invisible-encoding`, `sec-bidi-controls`, `sec-zero-width`, `sec-control-chars`, `sec-homoglyph`, `sec-html-comment`, `sec-instruction-markup`, `sec-instruction-phrases`, `sec-cross-tool-steering`, `sec-encoded-blob`, `sec-external-instructions`, `sec-secret-seeking`, `schema-param-description`, `schema-enum-missing`, `schema-required-unknown`, `schema-vague-param`, `schema-oneof-branch-types`, `schema-open-object`, `design-near-duplicate`, `design-namespace`, `design-handle-lifetime`, `surface-retry-key`, `surface-delete-guard`, `surface-full-replace`, `surface-bulk-delete`

### Prevalence

| Check | Servers |
|---|---|
| `spec-execution-legacy` | 100% |
| `anthropic-hint-platforms-differ` | 100% |
| `openai-retry` | 100% |
| `schema-additional-properties` | 100% |
| `schema-pagination` | 100% |
| `schema-response-format` | 100% |
| `schema-output-schema` | 100% |
| `design-use-when` | 100% |
| `surface-version-guard` | 100% |

## Checks that fire on no list at all

`spec-tool-shape`, `spec-input-schema-missing`, `spec-input-schema-field-name`, `spec-input-schema-root-object`, `spec-schema-valid`, `spec-schema-dialect`, `spec-ref-remote`, `spec-composition-bounds`, `spec-name-length`, `spec-name-charset`, `spec-name-unique`, `spec-x-mcp-header`, `spec-x-mcp-header-sensitive`, `spec-field-types`, `spec-annotation-key-case`, `spec-icon-scheme`, `spec-meta-key`, `spec-meta-reserved`, `spec-pagination-partial`, `anthropic-hint`, `anthropic-name-length`, `anthropic-read-write-split`, `anthropic-api-docs`, `anthropic-conversation-data`, `anthropic-unsupported-use`, `openai-hints-explicit`, `openai-description`, `openai-name-unique`, `openai-name-promotional`, `openai-name-opaque`, `openai-conversation-input`, `openai-restricted-input`, `openai-generic-executor`, `openai-readonly-destructive`, `annot-delete-marked-safe`, `annot-write-marked-readonly`, `sec-invisible-encoding`, `sec-bidi-controls`, `sec-zero-width`, `sec-control-chars`, `sec-homoglyph`, `sec-html-comment`, `sec-instruction-markup`, `sec-instruction-phrases`, `sec-cross-tool-steering`, `sec-encoded-blob`, `sec-external-instructions`, `sec-secret-seeking`, `schema-param-description`, `schema-enum-missing`, `schema-required-unknown`, `schema-oneof-branch-types`, `schema-open-object`, `design-near-duplicate`, `design-handle-lifetime`, `surface-retry-key`, `surface-delete-guard`, `surface-bulk-delete`

## Static against live

1 servers had both lists. Same tool names: 1 of 1 (100%). Static misses tools: 0 of 1 (0%). Static has tools the server does not list: 0 of 1 (0%).

Share of shared tools whose description is identical: median 1 (quartiles 1 to 1, 1 servers); input schema identical: median 0 (quartiles 0 to 0, 1 servers); parameter names identical: median 0 (quartiles 0 to 0, 1 servers).

### Checks whose static and live results disagree on at least 20% of servers

| Check | Disagree | Live only | Static only |
|---|---|---|---|
| `spec-envelope-result-type` | 100% | 1 | 0 |
| `spec-envelope-cache` | 100% | 1 | 0 |
| `spec-execution-legacy` | 100% | 0 | 1 |
| `schema-output-schema` | 100% | 0 | 1 |
| `surface-full-replace` | 100% | 1 | 0 |

