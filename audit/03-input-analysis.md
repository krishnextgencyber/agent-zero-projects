# Input Validation & Injection Analysis: `makenotion/notion-mcp-server`

**Audit target:** https://github.com/makenotion/notion-mcp-server v2.3.0

---

## 1. What Data Does an MCP Client Send?

All MCP communication is JSON-RPC 2.0. The two request types that carry
user-controlled data are:

### 1a. `tools/list` (ListTools)

```json
{ "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} }
```

No user-supplied parameters. Response is generated from the static
OpenAPI spec. **Not an injection surface.**

### 1b. `tools/call` (CallTool)

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "tools/call",
  "params": {
    "name": "<tool-name>",
    "arguments": {
      "<param1>": "<any value>",
      "<param2>": { "<nested>": "object" },
      "<param3>": ["array", "values"]
    }
  }
}
```

**`params.name`** — the tool identifier. Looked up in `openApiLookup`
(proxy.ts:154, 198-200). If not found: error thrown. Not further used.

**`params.arguments`** — completely arbitrary JSON object. This is the
primary injection surface. It is:
1. Passed to `deserializeParams()` (proxy.ts:161)
2. Then forwarded directly to `httpClient.executeOperation()` (proxy.ts:165)
3. Then sent to the Notion API as path params, query params, or request body

**There is no schema validation at any step.** The `inputSchema` field on
each tool is metadata for the LLM/client — the MCP SDK does not enforce
it before calling the handler.

---

## 2. How Are MCP Tool Parameters Processed?

### Step 1 — MCP SDK receives and deserializes JSON-RPC

**File:** `src/openapi-mcp-server/mcp/proxy.ts:150-151`

```typescript
this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: params } = request.params   // line 151
```

The MCP SDK parses the JSON-RPC envelope. `params.arguments` is typed
as `Record<string, unknown>` — any JSON value is accepted.

### Step 2 — `deserializeParams()`: recursive JSON re-parsing

**File:** `src/openapi-mcp-server/mcp/proxy.ts:33-84`

```typescript
function deserializeParams(params: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {}

  for (const [key, value] of Object.entries(params)) {
    if (typeof value === 'string') {
      const trimmed = value.trim()
      if ((trimmed.startsWith('{') && trimmed.endsWith('}')) ||
          (trimmed.startsWith('[') && trimmed.endsWith(']'))) {
        try {
          const parsed = JSON.parse(value)                    // line 43: parses user string
          if (typeof parsed === 'object' && parsed !== null) {
            result[key] = Array.isArray(parsed)
              ? parsed
              : deserializeParams(parsed as Record<string, unknown>)  // line 49: RECURSIVE
            continue
          }
        } catch { /* keep original */ }
      }
    } else if (Array.isArray(value)) {
      result[key] = value.map((item) => {
        // ...same logic per array item...
        const parsed = JSON.parse(item)                       // line 66: parses array items
        return deserializeParams(parsed)                      // line 70: RECURSIVE
      })
      continue
    }
    result[key] = value
  }
  return result
}
```

**Recursion has no depth limit.** See Finding INJ-1 below.

### Step 3 — `executeOperation()`: parameter routing without validation

**File:** `src/openapi-mcp-server/client/http-client.ts:104-165`

```typescript
async executeOperation(operation, params = {}) {
  // Route each param according to its 'in' field in the OpenAPI spec
  if (operation.parameters) {
    for (const param of operation.parameters) {
      if (param.in === 'path' || param.in === 'query') {
        urlParameters[param.name] = params[param.name]       // no validation
        delete bodyParams[param.name]
      }
      // 'header' and 'cookie' params silently fall through to bodyParams
    }
  }
  // For ops with no requestBody: everything goes to URL
  if (!operation.requestBody && !formData) {
    for (const key in bodyParams) {
      urlParameters[key] = bodyParams[key]                   // any extra key becomes URL param
    }
  }
  // Dispatch
  const response = await operationFn(urlParameters, bodyParams, requestConfig)
}
```

No type-checking, no length limits, no allowlist, no sanitization.

---

## 3. Are Parameters Validated Before Reaching Notion API?

**No. There is zero application-level validation.** The complete path from
MCP input to Notion API call has no guards:

```
MCP tool arguments (any JSON)
  │
  ▼
deserializeParams()       ← no schema check; just JSON.parse recursion
  │
  ▼
executeOperation()        ← routes by param.in; no type/length/format check
  │
  ▼
openapi-client-axios      ← builds URL via bath-es5; applies encodeURIComponent
  │                          to path params (safe); Axios serializes query params
  ▼
HTTPS request to Notion API  ← Notion performs its own server-side validation
```

**Path parameters** — bath-es5 (`path.js`) applies `encodeURIComponent`
before substituting into the URL template:

```javascript
// bath-es5/path.js
return parameterNames.reduce((a, name) => {
  return a.split('{' + name + '}').join(encodeURIComponent(params[name]))  // SAFE
}, template);
```

`/` → `%2F`, so `../../etc` → `..%2F..%2Fetc`. **Path traversal in URL
path parameters is mitigated** by the library.

**Query parameters** — passed to Axios which also percent-encodes values.
`\r\n` injection via query params does not reach HTTP headers.

**Request body** — passed as a raw JavaScript object to Axios, which
serializes it as JSON. Object keys and values are not validated. The
spec has several operations with `additionalProperties: true`, meaning
**any extra key in the body is accepted and forwarded to Notion**.

---

## 4. Is There `eval()`, `exec()`, or Dynamic Code Execution?

### 4a. Commented-out `eval` — dead code, historically planned

**File:** `src/openapi-mcp-server/openapi/parser.ts:458-463`

```typescript
// Generate Zod schema from input schema
try {
  // const zodSchemaStr = jsonSchemaToZod(inputSchema, { module: "cjs" })
  // console.log(zodSchemaStr)
  // // Execute the function with the zod instance
  // const zodSchema = eval(zodSchemaStr) as z.ZodType    // ← line 463: COMMENTED OUT

  return { name: methodName, description, inputSchema, ... }
```

This `eval` was clearly intended to be active — it is the only statement
in a `try` block that still has a matching `catch` handler (lines 471-479).
The `try/catch` wraps the `return` statement on lines 465-470 even though
nothing in it can throw.

If this code were uncommented:
- `jsonSchemaToZod(inputSchema, ...)` converts a JSON Schema to a
  JavaScript code string.
- `inputSchema` is built from the OpenAPI spec, not directly from
  user tool arguments.
- **However:** schema description fields are pulled from the spec's
  description strings, and description content is not sanitized.
  A malicious spec could embed JavaScript in a `description` field that
  survives into `zodSchemaStr` and executes via `eval`.

**Current status:** Not exploitable (code is commented out). The
`try/catch` skeleton remaining in live code is a maintenance hazard.

### 4b. No `exec`, `spawn`, `execFile`, `execSync` anywhere

Confirmed by grep of entire `src/` and `scripts/` tree. The server does
not invoke any shell commands.

---

## 5. How Is Mustache Used? Can Tool Parameters Reach Templates?

### The Mustache module exists but is dead code in this release

**File:** `src/openapi-mcp-server/auth/template.ts`

```typescript
import Mustache from 'mustache'

export function renderAuthTemplate(template: AuthTemplate, context: TemplateContext): AuthTemplate {
  // Disable HTML escaping for URLs
  Mustache.escape = (text) => text                           // line 6: GLOBAL MUTATION

  const renderedUrl = Mustache.render(template.url, context) // line 9
  // ...
  if (template.body) {
    renderedTemplate.body = Mustache.render(template.body, context)  // line 20
  }
  return renderedTemplate
}
```

**`renderAuthTemplate` is never called.** Confirmed by exhaustive grep:
the function is exported from `auth/index.ts` but has zero callers in
`proxy.ts`, `http-client.ts`, `init-server.ts`, or `start-server.ts`.

### The global mutation is an active side-effect risk

`Mustache.escape = (text) => text` (line 6) **modifies the Mustache
module singleton globally for the entire Node.js process**. Because
`renderAuthTemplate` is exported and could be called by any future
code importing it, activating it would permanently disable HTML escaping
for every subsequent `Mustache.render()` call in the process.

**The `TemplateContext` type shows what inputs the template system was designed to accept:**

**File:** `src/openapi-mcp-server/auth/types.ts:22-26`

```typescript
export interface TemplateContext {
  securityScheme?: SecurityScheme
  servers?: Server[]
  args: Record<string, string>    // ← user-supplied key/value pairs
}
```

`context.args` is a free-form `Record<string, string>`. If `renderAuthTemplate`
were wired into the call path and an MCP client could control `args`,
the combination of:
1. `Mustache.escape = (text) => text` (escaping disabled)
2. `Mustache.render(template.url, context)` (user args interpolated into URL)
3. `Mustache.render(template.body, context)` (user args interpolated into body)

…would constitute a **Server-Side Template Injection** into the auth
URL and request body, with no output encoding.

### Can tool parameters currently reach Mustache? No.

The data flow `CallTool arguments → deserializeParams → httpClient.executeOperation`
never touches `renderAuthTemplate`. The Mustache code is isolated.

---

## 6. String Concatenation in SQL, URLs, or Commands

### 6a. No SQL — confirmed

There are no database calls anywhere in the codebase. No SQL injection surface.

### 6b. No shell commands — confirmed

No `exec`, `spawn`, `child_process` usage anywhere.

### 6c. URL construction — safe paths

**`start-server.ts:258`** — Only URL concatenation involving external data:

```typescript
console.log(
  `Notion integration settings: https://www.notion.so/profile/integrations/internal/${data.id}`
)
```

`data.id` comes from the Notion API response at `GET /v1/users/me`. This
URL is **only logged**, never fetched. An MITM attacker on the Notion API
connection could inject a malicious `id` here, but it only affects log output.

**`init-server.ts:20`** — spec file path:

```typescript
rawSpec = fs.readFileSync(path.resolve(process.cwd(), specPath), 'utf-8')
```

`specPath` is hardcoded in `start-server.ts:16` as
`path.resolve(directory, '../scripts/notion-openapi.json')`. It is not
user-controllable via the MCP protocol.

**`proxy.ts:124`** — tool name construction:

```typescript
const toolNameWithMethod = `${toolName}-${method.name}`
```

Both `toolName` (always `"API"`) and `method.name` come from the static
OpenAPI spec converter output. Not user-controlled.

### 6d. File path concatenation — unsafe (existing finding)

**File:** `src/openapi-mcp-server/client/http-client.ts:83`

```typescript
function addFile(name: string, filePath: string) {
  const fileStream = fs.createReadStream(filePath)   // filePath = params[param]
  formData.append(name, fileStream)
}
```

`filePath` flows directly from the MCP tool argument `params[param]`
(line 60: `const filePath = params[param]`). No `path.resolve()` with
prefix check, no allowlist, no rejection of `..` or absolute paths.

Although the current Notion OpenAPI spec has no `multipart/form-data`
endpoints, this code is on the live execution path and would be triggered
by any future file upload operation added to the spec.

---

## FINDING INJ-1 — Unbounded Recursion in `deserializeParams` → Stack Overflow DoS

**File:** `src/openapi-mcp-server/mcp/proxy.ts:33-84`
**Severity:** Medium (DoS)
**Exploitable on:** Both stdio (no size limit) and HTTP transport (within 100kb body limit)

### Mechanism

`deserializeParams` calls itself recursively for every nested JSON object
it encounters, with **no depth limit**. Each call adds one stack frame.
V8's default stack depth is approximately 10,000–15,000 frames.

A single tool argument value constructed as a JSON string nested N levels
deep causes N recursive calls:

```
deserializeParams({ key: '{"a":"{"a":"{"a": ... }"}"}' })
  -> JSON.parse -> object -> deserializeParams(object)
    -> JSON.parse -> object -> deserializeParams(object)
      -> ... (N levels)
        -> RangeError: Maximum call stack size exceeded
```

### Proof-of-Concept payload

```python
def make_nested_json_string(depth: int) -> str:
    s = '"leaf"'
    for _ in range(depth):
        s = '{"a":' + s + '}'
    return s

# Depth 10000 = ~60,005 bytes — within 100kb HTTP body limit
payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "API-post-search",
        "arguments": {
            "query": make_nested_json_string(10000)
        }
    }
}
```

**Result:** `RangeError: Maximum call stack size exceeded` propagates
out of `deserializeParams`, through `executeOperation`, and crashes the
MCP handler. On stdio transport, this **terminates the server process**.
On HTTP transport, the error is caught at Express level (start-server.ts:193)
and returns a 500 JSON-RPC error — the server survives but the request
fails.

### Affected call sites

Both recursive call sites have no depth guard:
- `proxy.ts:49` — object deserialization
- `proxy.ts:70` — array item deserialization

---

## FINDING INJ-2 — No Schema Validation: Arbitrary Extra Fields Forwarded to Notion API

**File:** `src/openapi-mcp-server/mcp/proxy.ts:161-165`
**File:** `src/openapi-mcp-server/client/http-client.ts:137-145`
**Severity:** Low-Medium

### Mechanism

Tool arguments are never validated against the declared `inputSchema`.
Any key-value pair in `arguments` that is not a declared path/query
parameter flows into the request body:

```typescript
// http-client.ts:137-145
if (!operation.requestBody && !formData) {
  for (const key in bodyParams) {
    if (bodyParams[key] !== undefined) {
      urlParameters[key] = bodyParams[key]   // ANY extra key → URL params
    }
  }
}
```

For operations **with** a requestBody, undeclared fields remain in
`bodyParams` and are sent as part of the JSON body.

Additionally, the Notion spec declares:

```json
// PATCH /v1/pages/{page_id} requestBody:
"properties": {
  "type": "object",
  "additionalProperties": true    // ← any key/value accepted
}
```

This means an MCP client can inject arbitrary property update commands
into Notion pages beyond what the declared schema describes, limited only
by what Notion's server-side validation accepts.

### Proof-of-Concept

```json
{
  "method": "tools/call",
  "params": {
    "name": "API-patch-page",
    "arguments": {
      "page_id": "abc-123",
      "properties": {
        "__SECRET_KEY__": "injected",
        "any_undeclared_field": { "rich_text": [{ "text": { "content": "pwned" } }] }
      },
      "undeclared_top_level_param": "injected_into_body"
    }
  }
}
```

The `undeclared_top_level_param` and extra `properties` fields are
forwarded to Notion unchanged.

---

## FINDING INJ-3 — Commented `eval` Skeleton Indicates Future Code-Execution Risk

**File:** `src/openapi-mcp-server/openapi/parser.ts:458-479`
**Severity:** Informational (currently inactive)

```typescript
try {
  // const zodSchemaStr = jsonSchemaToZod(inputSchema, { module: "cjs" })
  // const zodSchema = eval(zodSchemaStr) as z.ZodType     // line 463

  return {
    name: methodName, description, inputSchema,            // line 465
    ...(returnSchema ? { returnSchema } : {}),
  }
} catch (error) {
  console.warn(`Failed to generate Zod schema for ${methodName}:`, error)
  return {                                                  // line 474
    name: methodName, description, inputSchema,
    ...(returnSchema ? { returnSchema } : {}),
  }
}
```

The `try` block's only statement is `return` (line 465), which cannot
throw. The `catch` block is therefore unreachable dead code. This
skeleton shows the `eval` was previously active and was commented out
rather than deleted — it may be re-enabled in a future version.

If re-enabled: `jsonSchemaToZod` generates a JavaScript code string from
`inputSchema`. While `inputSchema` is primarily spec-derived, the
`description` fields from spec operations are copied into schema
descriptions (parser.ts:391), and description content is not sanitized.
A malicious spec file (e.g., via `BASE_URL` + modified spec) could
embed JavaScript payloads.

---

## FINDING INJ-4 — Mustache Global State Mutation via Dead-Code Import

**File:** `src/openapi-mcp-server/auth/template.ts:6`
**Severity:** Low (currently inactive; process-wide impact if activated)

```typescript
export function renderAuthTemplate(...) {
  Mustache.escape = (text) => text    // line 6: mutates global singleton
```

`Mustache` is a module singleton. Setting `.escape` here changes it
**for every `Mustache.render()` call in the entire process** for the
remainder of its lifetime. Since `renderAuthTemplate` is exported and
importable, any caller (including future code or test code) that invokes
it will silently disable HTML escaping globally, enabling XSS in any
subsequent Mustache rendering that relies on escaping for safety.

---

## Summary: Input Surface Map

```
MCP tool argument (any JSON)
│
├── params.name  ─────────────────────────────► openApiLookup[name]
│     No injection; only used for lookup; error if not found
│
└── params.arguments (Record<string, unknown>)
      │
      ▼
      deserializeParams()                       ← INJ-1: unbounded recursion
        │  JSON.parse on string values
        │  recursive for nested objects/arrays
        ▼
      deserialized params (still unvalidated)
        │
        ├── path params   ─────────────────────► bath-es5 encodeURIComponent ✓ SAFE
        ├── query params  ─────────────────────► Axios URL encoding ✓ SAFE
        ├── body params   ─────────────────────► JSON serialized, forwarded raw ← INJ-2
        └── file path     ─────────────────────► fs.createReadStream(filePath) ← LFI (from audit 01)
```

| Finding | File | Lines | Severity |
|---------|------|-------|----------|
| INJ-1: Stack overflow DoS via deeply nested JSON string | `proxy.ts` | 33-84 | **Medium** |
| INJ-2: No schema validation; extra fields forwarded to Notion | `proxy.ts:161`, `http-client.ts:137` | 161, 137-145 | **Low-Med** |
| INJ-3: Dead `eval` skeleton in try/catch block | `parser.ts` | 458-479 | **Informational** |
| INJ-4: Mustache global escape mutation via dead code | `template.ts` | 6 | **Low** |
| (from 01) LFI via unvalidated file path | `http-client.ts` | 83 | **High** |
| Path param injection | `bath-es5/path.js` | — | ✓ Mitigated |
| Prototype pollution via JSON.parse | `proxy.ts` | 43, 66 | ✓ Not exploitable |
| SQL injection | — | — | ✓ No SQL used |
| Shell injection | — | — | ✓ No shell calls |
