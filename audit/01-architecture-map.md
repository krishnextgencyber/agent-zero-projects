# Architecture Map: `makenotion/notion-mcp-server`

**Audit target:** https://github.com/makenotion/notion-mcp-server
**Version analysed:** 2.3.0 (`package.json:9`)
**Commit:** HEAD of `main` as of 2026-03-30
**File inventory (src/):**

| # | File | Purpose |
|---|------|---------|
| 1 | `scripts/start-server.ts` | Entry point; transport selection, HTTP auth, Express setup |
| 2 | `src/init-server.ts` | Loads & validates OpenAPI spec; creates `MCPProxy` |
| 3 | `src/openapi-mcp-server/mcp/proxy.ts` | MCP protocol handler; `ListTools` + `CallTool` |
| 4 | `src/openapi-mcp-server/client/http-client.ts` | Axios-based HTTP client; executes OpenAPI operations |
| 5 | `src/openapi-mcp-server/openapi/parser.ts` | Converts OpenAPI spec into MCP tool definitions |
| 6 | `src/openapi-mcp-server/openapi/file-upload.ts` | Identifies binary/multipart upload parameters |
| 7 | `src/openapi-mcp-server/auth/template.ts` | Mustache template renderer for auth URLs/bodies |
| 8 | `src/openapi-mcp-server/auth/types.ts` | TypeScript types for auth template system |
| 9 | `src/openapi-mcp-server/client/polyfill-headers.ts` | `Headers` polyfill for Node < 18 |
| 10 | `src/openapi-mcp-server/index.ts` | Re-exports `OpenAPIToMCPConverter` and `HttpClient` |

---

## 1. Request Arrival

### 1a. Stdio Transport (default)

**File:** `scripts/start-server.ts:76-80`

```typescript
if (transport === 'stdio') {
  const proxy = await initProxy(specPath, baseUrl)      // line 78
  await proxy.connect(new StdioServerTransport())        // line 79
  return proxy.getServer()                               // line 80
}
```

The MCP SDK's `StdioServerTransport` reads newline-delimited JSON-RPC
messages from `process.stdin` and writes responses to `process.stdout`.
No network listener is opened. The process is invoked by the MCP client
(e.g. Claude Desktop, Cursor) as a child process.

**Trust boundary:** The parent process (MCP client) is fully trusted.
There is no authentication on the stdio path. Any process that can write
to the server's stdin can issue arbitrary MCP commands.

### 1b. HTTP Transport (`--transport http`)

**File:** `scripts/start-server.ts:81-266`

```
Express app created                          line 83
  app.use(express.json())                    line 84
  Bearer token auth middleware registered    line 142  (if auth enabled)
  POST /mcp  handler                         line 150
  GET  /mcp  handler (SSE)                   line 209
  DELETE /mcp handler (session teardown)     line 221
  GET  /health (no auth)                     line 132
  app.listen('0.0.0.0', port)                line 233
```

Requests arrive as standard HTTP POST to `/mcp`. The body is a JSON-RPC
message (or batch). A `Mcp-Session-Id` header identifies the session.

**Session lifecycle:**
1. First request must be an `isInitializeRequest` (SDK check, line 159).
2. Server creates a `StreamableHTTPServerTransport` with a random UUID
   session ID (line 161-163).
3. Session is stored in a `transports` map keyed by session ID (line 147).
4. Subsequent requests reuse the transport by session ID (line 157).

---

## 2. Authentication

### 2a. Notion API Token — Bearer Auth to Notion

**File:** `src/openapi-mcp-server/mcp/proxy.ts:202-231`

```typescript
private parseHeadersFromEnv(): Record<string, string> {
  // Priority 1: OPENAPI_MCP_HEADERS (JSON string of arbitrary headers)
  const headersJson = process.env.OPENAPI_MCP_HEADERS    // line 204
  if (headersJson) {
    const headers = JSON.parse(headersJson)               // line 206
    // ... validation ...
    return headers                                         // line 212
  }

  // Priority 2: NOTION_TOKEN (converted to Bearer auth + version header)
  const notionToken = process.env.NOTION_TOKEN            // line 221
  if (notionToken) {
    return {
      'Authorization': `Bearer ${notionToken}`,           // line 224
      'Notion-Version': '2025-09-03'                      // line 225
    }
  }

  return {}   // no auth                                   // line 228
}
```

These headers are baked into the `HttpClient` at construction time and
attached to **every** outgoing Axios request:

**File:** `src/openapi-mcp-server/client/http-client.ts:36-49`

```typescript
constructor(config: HttpClientConfig, openApiSpec) {
  this.client = new OpenAPIClientAxios({
    definition: openApiSpec,
    axiosConfigDefaults: {
      baseURL: config.baseUrl,                            // line 41
      headers: {
        'Content-Type': 'application/json',               // line 43
        'User-Agent': 'notion-mcp-server',                // line 44
        ...config.headers,                                // line 45  <-- NOTION_TOKEN injected here
      },
    },
  })
}
```

**Key observation:** The Notion token is set once at process startup and
applies globally to all requests. There is no per-request, per-user, or
per-session token. All MCP clients sharing the same server instance
operate under the same Notion identity.

### 2b. HTTP Transport Bearer Auth — MCP Client to MCP Server

**File:** `scripts/start-server.ts:87-129`

```typescript
// Token sourcing (line 90):
authToken = options.authToken               // --auth-token CLI arg
  || process.env.AUTH_TOKEN                 // AUTH_TOKEN env var
  || randomBytes(32).toString('hex')        // auto-generated 64-char hex

// Auto-generated token written to /tmp (lines 93-95):
authTokenFilePath = path.join(os.tmpdir(), `.notion-mcp-auth-token-${process.pid}`)
fs.writeFileSync(authTokenFilePath, authToken, { mode: 0o600 })

// Middleware (lines 100-129):
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]     // line 102
  if (!token)        -> 401                                 // line 104
  if (token !== authToken) -> 403                           // line 116  <-- non-constant-time
  next()                                                    // line 128
}

// Applied to /mcp routes only when auth enabled (line 142):
if (!options.disableAuth) {
  app.use('/mcp', authenticateToken)
}
```

**Auth bypass path:** The `--disable-auth` flag (line 39) or absent
token entirely disables authentication, making the MCP server
accessible to anyone who can reach the HTTP port.

---

## 3. Request Transformation (MCP -> OpenAPI)

### 3a. Tool Discovery (ListTools)

**File:** `src/openapi-mcp-server/mcp/proxy.ts:117-147`

```typescript
this.server.setRequestHandler(ListToolsRequestSchema, async () => {
  const tools: Tool[] = []
  Object.entries(this.tools).forEach(([toolName, def]) => {
    def.methods.forEach(method => {
      const toolNameWithMethod = `${toolName}-${method.name}`      // line 124
      const truncatedToolName = this.truncateToolName(toolNameWithMethod)  // line 125
      tools.push({
        name: truncatedToolName,                                    // line 132
        description: method.description,                            // line 133
        inputSchema: method.inputSchema,                            // line 134
        annotations: { ... }                                        // line 135-141
      })
    })
  })
  return { tools }
})
```

Tool names follow the pattern `API-{operationId}` (e.g. `API-post-search`,
`API-get-user`). Names exceeding 64 characters are truncated at line 125
via `truncateToolName()` (lines 245-250).

### 3b. Tool Invocation (CallTool)

**File:** `src/openapi-mcp-server/mcp/proxy.ts:150-195`

```typescript
this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: params } = request.params           // line 151

  // 1. Look up the OpenAPI operation by tool name
  const operation = this.findOperation(name)                    // line 154
  if (!operation) throw new Error(`Method ${name} not found`)  // line 156

  // 2. Deserialize any double-serialized JSON string params
  const deserializedParams = params
    ? deserializeParams(params as Record<string, unknown>)      // line 161
    : {}

  // 3. Forward to HttpClient
  const response = await this.httpClient.executeOperation(
    operation, deserializedParams                               // line 165
  )

  // 4. Return Notion API response as MCP text content
  return {
    content: [{
      type: 'text',
      text: JSON.stringify(response.data),                      // line 172
    }],
  }
})
```

### 3c. Parameter Deserialization

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
          const parsed = JSON.parse(value)                     // line 43
          if (typeof parsed === 'object' && parsed !== null) {
            result[key] = Array.isArray(parsed)
              ? parsed
              : deserializeParams(parsed)                      // line 49  recursive
            continue
          }
        } catch { /* keep original string */ }
      }
    } else if (Array.isArray(value)) {
      result[key] = value.map((item) => { /* same logic per item */ })  // lines 58-77
      continue
    }
    result[key] = value
  }
  return result
}
```

This function exists to work around MCP clients (Claude Desktop, Cursor)
that double-serialize nested JSON objects. It recursively parses any
string value that looks like JSON.

### 3d. OpenAPI Spec Parsing and Tool Generation

**File:** `src/openapi-mcp-server/openapi/parser.ts:170-203`

```typescript
convertToMCPTools() {
  const apiName = 'API'
  for (const [path, pathItem] of Object.entries(this.openApiSpec.paths || {})) {
    for (const [method, operation] of Object.entries(pathItem)) {
      if (!this.isOperation(method, operation)) continue

      const mcpMethod = this.convertOperationToMCPMethod(operation, method, path)  // line 189
      // ...
      openApiLookup[apiName + '-' + uniqueName] = { ...operation, method, path }   // line 196
    }
  }
}
```

Each OpenAPI operation becomes one MCP tool. The converter:

1. **Extracts parameters** (`parser.ts:384-398`): path, query, header,
   and cookie parameters from the operation are added to the tool's
   `inputSchema.properties`.
2. **Extracts request body** (`parser.ts:400-435`): JSON or multipart
   body schema properties are flattened into the same `inputSchema`.
3. **Resolves `$ref` references** (`parser.ts:30-46`): `$ref` pointers
   are resolved against `components/schemas`.
4. **Converts binary fields** (`parser.ts:104-107`): `format: binary`
   becomes `format: uri-reference` with description "absolute paths to
   local files".
5. **Adds string fallbacks** (`parser.ts:490-516`): Complex types get
   `anyOf: [original, {type: 'string'}]` to handle double-serialization.

---

## 4. Forwarding to Notion API

### 4a. Parameter Routing

**File:** `src/openapi-mcp-server/client/http-client.ts:104-196`

```typescript
async executeOperation(operation, params = {}) {
  const operationId = operation.operationId                     // line 109

  // 1. Check for file uploads
  const formData = await this.prepareFileUpload(operation, params)  // line 115

  // 2. Separate parameters by location
  const urlParameters: Record<string, any> = {}
  const bodyParams: Record<string, any> = formData || { ...params }  // line 119

  // 3. Extract path + query params from operation definition
  if (operation.parameters) {
    for (const param of operation.parameters) {
      if ('name' in param && param.name && param.in) {
        if (param.in === 'path' || param.in === 'query') {     // line 125
          urlParameters[param.name] = params[param.name]
          if (!formData) delete bodyParams[param.name]
        }
        // NOTE: 'header' and 'cookie' params are NOT extracted here.
        // They remain in bodyParams.
      }
    }
  }

  // 4. For operations without requestBody, move all remaining params to URL
  if (!operation.requestBody && !formData) {                    // line 138
    for (const key in bodyParams) {
      urlParameters[key] = bodyParams[key]                      // line 140
      delete bodyParams[key]
    }
  }

  // 5. Dispatch via openapi-client-axios
  const operationFn = (api as any)[operationId]                 // line 147
  const response = await operationFn(
    urlParameters,                                               // arg 1: path + query
    hasBody ? bodyParams : undefined,                            // arg 2: request body
    requestConfig                                                // arg 3: per-request headers
  )                                                              // line 165
}
```

**Parameter flow summary:**

```
MCP tool arguments
  |
  v
deserializeParams()          -- JSON string -> object conversion
  |
  v
executeOperation(operation, params)
  |
  +---> param.in === 'path'   ---> urlParameters (path substitution)
  +---> param.in === 'query'  ---> urlParameters (query string)
  +---> param.in === 'header' ---> bodyParams (BUG: not forwarded as header)
  +---> param.in === 'cookie' ---> bodyParams (BUG: not forwarded as cookie)
  +---> requestBody fields    ---> bodyParams (JSON body)
  +---> no requestBody?       ---> all remaining bodyParams -> urlParameters
  |
  v
openapi-client-axios operationFn(urlParameters, bodyParams, config)
  |
  v
Axios request to baseURL (https://api.notion.com by default)
  with global headers: { Authorization, Notion-Version, Content-Type, User-Agent }
```

### 4b. File Upload Handling

**File:** `src/openapi-mcp-server/client/http-client.ts:52-99`

```typescript
private async prepareFileUpload(operation, params) {
  const fileParams = isFileUploadParameter(operation)           // line 53
  if (fileParams.length === 0) return null

  const formData = new FormData()
  for (const param of fileParams) {
    const filePath = params[param]                              // line 60
    // ...
    function addFile(name: string, filePath: string) {
      const fileStream = fs.createReadStream(filePath)          // line 83  <-- no validation
      formData.append(name, fileStream)
    }
  }
  return formData
}
```

**File:** `src/openapi-mcp-server/openapi/file-upload.ts:8-40`

```typescript
export function isFileUploadParameter(operation): string[] {
  // Looks for multipart/form-data content type
  // Returns names of properties with type: string, format: binary
  // Also handles arrays of binary items
}
```

### 4c. Base URL Resolution

**File:** `scripts/start-server.ts:18`

```typescript
const baseUrl = process.env.BASE_URL ?? undefined
```

**File:** `src/init-server.ts:30-32`

```typescript
if (baseUrl) {
  parsed.servers[0].url = baseUrl    // overrides https://api.notion.com
}
```

The OpenAPI spec ships with `servers: [{ url: "https://api.notion.com" }]`
(`scripts/notion-openapi.json`). The `BASE_URL` env var replaces this
globally, redirecting all API traffic (including the Authorization header)
to the specified host.

### 4d. Error Response Path

**File:** `src/openapi-mcp-server/mcp/proxy.ts:176-194`

```typescript
} catch (error) {
  if (error instanceof HttpClientError) {
    const data = error.data?.response?.data ?? error.data ?? {}   // line 180
    return {
      content: [{
        type: 'text',
        text: JSON.stringify({
          status: 'error',
          ...(typeof data === 'object' ? data : { data: data }),  // line 187
        }),
      }],
    }
  }
  throw error   // non-HTTP errors re-thrown to SDK                // line 193
}
```

**File:** `src/openapi-mcp-server/client/http-client.ts:178-195`

```typescript
} catch (error: any) {
  if (error.response) {
    throw new HttpClientError(
      error.response.statusText || 'Request failed',
      error.response.status,
      error.response.data,                                         // line 192
      headers
    )
  }
  throw error
}
```

The full Notion API error response body (`error.response.data`) is
captured in `HttpClientError.data` and then returned verbatim to the
MCP client in proxy.ts line 180-187.

---

## 5. Auxiliary Components

### 5a. Auth Template System (unused)

**Files:** `src/openapi-mcp-server/auth/template.ts`, `auth/types.ts`

```typescript
// template.ts:6
Mustache.escape = (text) => text   // globally disables HTML escaping

// Renders URL and body templates with Mustache
export function renderAuthTemplate(template, context): AuthTemplate
```

This module is exported via `auth/index.ts` but is **never imported** by
`proxy.ts`, `http-client.ts`, `init-server.ts`, or `start-server.ts`.
It is dead code in the current release.

### 5b. Headers Polyfill

**File:** `src/openapi-mcp-server/client/polyfill-headers.ts`

Provides a `Headers` class for Node.js < 18. Used by `http-client.ts`
to wrap response headers.

### 5c. OpenAPI Spec

**File:** `scripts/notion-openapi.json`

- 22 operations across 16 path patterns
- All operations reference `#/components/parameters/notionVersion`
  (a header parameter: `Notion-Version`, `in: header`)
- Security scheme: `bearerAuth` (HTTP bearer token)
- No `multipart/form-data` endpoints in current spec
- Base server: `https://api.notion.com`

---

## 6. Complete Request Flow Diagram

```
                        MCP CLIENT (Claude Desktop / Cursor / etc.)
                                    |
                    +===============+===============+
                    |                               |
              [stdio mode]                    [HTTP mode]
                    |                               |
                    |                    Express server (0.0.0.0:3000)
                    |                       GET /health (no auth)
                    |                       POST/GET/DELETE /mcp
                    |                               |
                    |                    authenticateToken middleware
                    |                    scripts/start-server.ts:100-129
                    |                      Bearer token check (line 116)
                    |                      --disable-auth bypasses
                    |                               |
              StdioServerTransport      StreamableHTTPServerTransport
              start-server.ts:79         start-server.ts:161
                    |                               |
                    +===============+===============+
                                    |
                              MCP SDK Server
                          proxy.ts:94 (constructor)
                                    |
                    +---------------+---------------+
                    |                               |
              ListToolsRequest               CallToolRequest
              proxy.ts:118                   proxy.ts:150
                    |                               |
              Returns tool list              findOperation(name)
              from converter output          proxy.ts:198
                    |                               |
                    |                       deserializeParams(args)
                    |                       proxy.ts:33-84
                    |                               |
                    |                       httpClient.executeOperation()
                    |                       http-client.ts:104
                    |                               |
                    |                       +-------+-------+
                    |                       |               |
                    |               prepareFileUpload()  parameter routing
                    |               http-client.ts:52   http-client.ts:117-144
                    |                       |               |
                    |                       +-------+-------+
                    |                               |
                    |                       axiosInstance[operationId](
                    |                         urlParams, body, config
                    |                       )
                    |                       http-client.ts:165
                    |                               |
                    |                               v
                    |                    +---------------------+
                    |                    | HTTPS request to:   |
                    |                    | baseURL + path      |
                    |                    | (api.notion.com or  |
                    |                    |  BASE_URL override) |
                    |                    +---------------------+
                    |                               |
                    |                          Notion API
                    |                          response
                    |                               |
                    |                       +-------+-------+
                    |                       |               |
                    |                   success          error
                    |                   proxy.ts:168    proxy.ts:176
                    |                       |               |
                    |                   JSON.stringify   HttpClientError
                    |                   (response.data)  data passed through
                    |                   proxy.ts:172     proxy.ts:180-189
                    |                       |               |
                    +-------+-------+-------+-------+-------+
                            |
                      MCP response
                      { content: [{ type: 'text', text: '...' }] }
                            |
                            v
                        MCP CLIENT
```

---

## 7. Security-Relevant Boundaries

| Boundary | Location | Protection |
|----------|----------|------------|
| MCP client -> MCP server (stdio) | `start-server.ts:79` | **None** (implicit trust of parent process) |
| MCP client -> MCP server (HTTP) | `start-server.ts:100-129` | Bearer token; non-constant-time compare (line 116) |
| MCP server -> Notion API | `http-client.ts:165` | Bearer token from env; no per-request auth |
| File system -> upload | `http-client.ts:83` | **None** (arbitrary path read via `fs.createReadStream`) |
| OpenAPI spec -> tool schema | `parser.ts:384-398` | Header params exposed to MCP clients as tool inputs |
| Notion API -> MCP client (errors) | `proxy.ts:180-189` | **None** (full error body passed through) |
| Env var `BASE_URL` -> baseURL | `init-server.ts:31-32` | **None** (arbitrary URL, token follows) |
| Env var `OPENAPI_MCP_HEADERS` -> headers | `proxy.ts:204-212` | **None** (arbitrary headers injected) |
