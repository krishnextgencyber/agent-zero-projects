# Authentication Analysis: `makenotion/notion-mcp-server`

**Audit target:** https://github.com/makenotion/notion-mcp-server v2.3.0

---

## Table of Contents

1. [How NOTION_TOKEN Is Read and Used](#1-how-notion_token-is-read-and-used)
2. [How OPENAPI_MCP_HEADERS Is Parsed](#2-how-openapi_mcp_headers-is-parsed)
3. [How the HTTP Transport Auth Token Works](#3-how-the-http-transport-auth-token-works)
4. [Is the Token Comparison Timing-Safe?](#4-is-the-token-comparison-timing-safe)
5. [Can Any Request Bypass Authentication?](#5-can-any-request-bypass-authentication)
6. [Is the Auth Token Logged Anywhere?](#6-is-the-auth-token-logged-anywhere)

---

## 1. How NOTION_TOKEN Is Read and Used

### Reading the token

**File:** `src/openapi-mcp-server/mcp/proxy.ts:221-228`

```typescript
// Alternative: try NOTION_TOKEN
const notionToken = process.env.NOTION_TOKEN           // line 222
if (notionToken) {
  return {
    'Authorization': `Bearer ${notionToken}`,          // line 225
    'Notion-Version': '2025-09-03'                     // line 226
  }
}
```

`parseHeadersFromEnv()` is called once, during `MCPProxy` construction
(`proxy.ts:102`). The token is read from `process.env.NOTION_TOKEN` and
converted to a `Bearer` authorization header. It is the **second-priority**
source: `OPENAPI_MCP_HEADERS` (if non-empty) takes precedence.

### How the token propagates

```
process.env.NOTION_TOKEN
  |
  v
MCPProxy constructor (proxy.ts:93)
  |
  v
this.parseHeadersFromEnv() (proxy.ts:102)
  returns: { 'Authorization': 'Bearer <token>', 'Notion-Version': '2025-09-03' }
  |
  v
new HttpClient({ baseUrl, headers: <above> }, openApiSpec) (proxy.ts:99-105)
  |
  v
HttpClient constructor (http-client.ts:36-50)
  axiosConfigDefaults.headers = {
    'Content-Type': 'application/json',               // line 43
    'User-Agent': 'notion-mcp-server',                // line 44
    ...config.headers                                  // line 45 — token injected here
  }
  |
  v
Every Axios request inherits these default headers.
The token is sent with EVERY outgoing request to baseURL.
```

### Security observations

| Aspect | Status |
|--------|--------|
| Token stored in memory | Plaintext in Axios defaults — never cleared |
| Token scope | Global — all MCP sessions share one Notion identity |
| Token rotation | Requires process restart |
| Token sent to | `baseURL` (default: `https://api.notion.com`, overridable via `BASE_URL` env) |
| Token validated before use | **No** — any string is accepted, including empty string |

---

## 2. How OPENAPI_MCP_HEADERS Is Parsed

**File:** `src/openapi-mcp-server/mcp/proxy.ts:202-219`

```typescript
private parseHeadersFromEnv(): Record<string, string> {
  // First try OPENAPI_MCP_HEADERS (existing behavior)
  const headersJson = process.env.OPENAPI_MCP_HEADERS       // line 204
  if (headersJson) {
    try {
      const headers = JSON.parse(headersJson)                 // line 207 — arbitrary JSON parsed
      if (typeof headers !== 'object' || headers === null) {
        console.warn('OPENAPI_MCP_HEADERS environment variable must be a JSON object, got:', typeof headers)
                                                               // line 209 — warn but no throw
      } else if (Object.keys(headers).length > 0) {
        // Only use OPENAPI_MCP_HEADERS if it contains actual headers
        return headers                                         // line 212 — returned directly
      }
      // If OPENAPI_MCP_HEADERS is empty object, fall through to try NOTION_TOKEN
    } catch (error) {
      console.warn('Failed to parse OPENAPI_MCP_HEADERS environment variable:', error)
                                                               // line 216 — warn, fall through
      // Fall through to try NOTION_TOKEN
    }
  }
  // ... NOTION_TOKEN fallback ...
}
```

### Parsing flow

```
OPENAPI_MCP_HEADERS env var (raw string)
  |
  +-- JSON.parse() (line 207)
  |     |
  |     +-- Success: typeof check (line 208)
  |     |     |
  |     |     +-- Not object/null → console.warn, fall through to NOTION_TOKEN
  |     |     +-- Empty object {} → fall through to NOTION_TOKEN
  |     |     +-- Non-empty object → return directly (line 212)
  |     |
  |     +-- Failure (SyntaxError): console.warn, fall through to NOTION_TOKEN
  |
  +-- Not set: skip, try NOTION_TOKEN
```

### Security observations

**No header name validation.** The parsed headers object is returned
directly and spread into Axios defaults (`http-client.ts:45`). An
attacker who controls the env var can inject:

- `Host` header — may alter routing at reverse proxies
- `X-Forwarded-For` / `X-Real-IP` — IP spoofing
- `Content-Type` — override `application/json` default
- `Transfer-Encoding` — request smuggling
- `Authorization` — override any NOTION_TOKEN-derived auth
- Arbitrary custom headers

**Example of hostile OPENAPI_MCP_HEADERS value:**
```json
{
  "Authorization": "Bearer attacker_token",
  "Host": "evil.example.com",
  "X-Forwarded-For": "127.0.0.1"
}
```

**No header value sanitization.** Header values are not checked for
CRLF injection characters. While Axios and Node.js HTTP stack generally
reject bare `\r\n` in header values, some edge cases exist in older
Node versions.

**Priority confusion.** When both `OPENAPI_MCP_HEADERS` and
`NOTION_TOKEN` are set, `OPENAPI_MCP_HEADERS` wins if it is a non-empty
object (line 210-212). The Dockerfile sets `ENV OPENAPI_MCP_HEADERS="{}"`,
which falls through to `NOTION_TOKEN` due to the empty-object check.
This means any Docker deployment that overrides `OPENAPI_MCP_HEADERS`
with content silently disables `NOTION_TOKEN`.

**Relevant Dockerfile line:**
```dockerfile
# Dockerfile:34
ENV OPENAPI_MCP_HEADERS="{}"
```

---

## 3. How the HTTP Transport Auth Token Works

### Token sourcing

**File:** `scripts/start-server.ts:86-97`

```typescript
// Generate or use provided auth token (from CLI arg or env var) only if auth is enabled
let authToken: string | undefined
let authTokenFilePath: string | undefined
if (!options.disableAuth) {                                    // line 89
  authToken = options.authToken                                // line 90 — from --auth-token CLI arg
    || process.env.AUTH_TOKEN                                  //         — from AUTH_TOKEN env var
    || randomBytes(32).toString('hex')                         //         — auto-generated 64-char hex

  if (!options.authToken && !process.env.AUTH_TOKEN) {
    // Write auto-generated token to a file with restricted permissions instead of logging it
    authTokenFilePath = path.join(
      os.tmpdir(),
      `.notion-mcp-auth-token-${process.pid}`                  // line 93 — predictable filename
    )
    fs.writeFileSync(authTokenFilePath, authToken, { mode: 0o600 })  // line 94
    console.log(`Generated auth token written to: ${authTokenFilePath}`)  // line 95
  }
}
```

**Token priority chain:**
1. `--auth-token <value>` CLI argument (line 35-37)
2. `AUTH_TOKEN` environment variable
3. `randomBytes(32).toString('hex')` — 256-bit entropy, 64 hex chars

### Middleware implementation

**File:** `scripts/start-server.ts:100-129`

```typescript
const authenticateToken = (req: express.Request, res: express.Response, next: express.NextFunction): void => {
  const authHeader = req.headers['authorization']              // line 101
  const token = authHeader && authHeader.split(' ')[1]         // line 102 — extract after "Bearer "

  if (!token) {                                                // line 104
    res.status(401).json({
      jsonrpc: '2.0',
      error: { code: -32001, message: 'Unauthorized: Missing bearer token' },
      id: null,
    })
    return
  }

  if (token !== authToken) {                                   // line 116 — NOT timing-safe
    res.status(403).json({
      jsonrpc: '2.0',
      error: { code: -32002, message: 'Forbidden: Invalid bearer token' },
      id: null,
    })
    return
  }

  next()                                                       // line 128
}
```

### Middleware registration

**File:** `scripts/start-server.ts:141-144`

```typescript
// Apply authentication to all /mcp routes only if auth is enabled
if (!options.disableAuth) {
  app.use('/mcp', authenticateToken)                           // line 143
}
```

### Route protection map

| Route | Method | Auth protected? |
|-------|--------|-----------------|
| `GET /health` | GET | **No** (line 132, registered before auth middleware) |
| `POST /mcp` | POST | Yes, if auth enabled |
| `GET /mcp` | GET | Yes, if auth enabled |
| `DELETE /mcp` | DELETE | Yes, if auth enabled |
| Any other path | Any | No (404 from Express) |

### Token storage

Auto-generated tokens are written to:

```
/tmp/.notion-mcp-auth-token-<PID>
```

**Security properties of this file:**
- File mode: `0o600` (owner-only read/write) — **correct**
- Filename contains PID — **predictable** (visible in `/proc`, `ps`)
- `/tmp` directory — **world-traversable** (other users can list filenames)
- **Never deleted** — the file persists after process exit (no cleanup handler)
- Docker runs as root (no `USER` directive in Dockerfile) — any container escape reads it

---

## 4. Is the Token Comparison Timing-Safe?

### **No. The comparison is NOT timing-safe.**

**File:** `scripts/start-server.ts:116`

```typescript
if (token !== authToken) {
```

JavaScript's `!==` operator performs a **byte-by-byte comparison that
short-circuits on the first mismatch**. The comparison time is
proportional to the length of the matching prefix between `token` and
`authToken`.

### Why this matters

The auto-generated token is 64 hex characters (0-9, a-f). An attacker
can determine each character independently by measuring response times:

1. Send 16 requests, each with a different first character (0-f).
2. The request with the longest response time reveals the correct first byte.
3. Fix the first byte, repeat for the second, etc.
4. After 64 x 16 = **1,024 requests**, the full token is known.

### Additional amplification factors

- The token comparison occurs at the Express middleware level (line 116),
  before any JSON parsing or MCP processing. This means the timing
  signal is **not obscured by variable processing time** downstream.
- The HTTP transport binds to `0.0.0.0` (line 233), so the timing
  attack can be mounted from the local network (near-zero jitter).
- The 401 vs 403 response codes also leak information: `token !== authToken`
  is only evaluated after confirming a token is present (line 104).

### Fix required

```typescript
import { timingSafeEqual } from 'node:crypto'

// Replace line 116 with:
const tokenBuf = Buffer.from(token)
const authTokenBuf = Buffer.from(authToken!)
if (tokenBuf.length !== authTokenBuf.length ||
    !timingSafeEqual(tokenBuf, authTokenBuf)) {
```

---

## 5. Can Any Request Bypass Authentication?

### Bypass 1: `--disable-auth` flag completely removes middleware

**File:** `scripts/start-server.ts:38-39`

```typescript
} else if (args[i] === '--disable-auth') {
  disableAuth = true;
}
```

**File:** `scripts/start-server.ts:89, 141-144`

```typescript
if (!options.disableAuth) {
  authToken = ...                                // token never set
}

if (!options.disableAuth) {
  app.use('/mcp', authenticateToken)             // middleware never registered
}
```

When `--disable-auth` is passed, **no authentication middleware is
registered at all**. Every request to `/mcp` is processed without any
identity check. The `authToken` variable remains `undefined`.

### Bypass 2: `/health` endpoint is always unauthenticated

**File:** `scripts/start-server.ts:132-139`

```typescript
// Health endpoint (no authentication required)
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    transport: 'http',
    port: options.port                                        // line 137
  })
})
```

This is registered **before** the auth middleware (line 132 < line 143).
It leaks:
- Server status (confirms the service is running)
- Exact server timestamp (clock skew information)
- Port number (confirms configuration)

No Notion tokens are leaked here, but the endpoint enables
reconnaissance.

### Bypass 3: Stdio transport has zero authentication

**File:** `scripts/start-server.ts:76-80`

```typescript
if (transport === 'stdio') {
  const proxy = await initProxy(specPath, baseUrl)
  await proxy.connect(new StdioServerTransport())
  return proxy.getServer()
}
```

The stdio transport relies entirely on the parent process (MCP client)
for security. Any process that can write to the server's stdin can
issue arbitrary MCP tool calls. There is:
- No authentication
- No authorization (any tool can be called)
- No rate limiting
- No input size limits (beyond available memory)

### Bypass 4: Notion API called without auth when no token configured

**File:** `src/openapi-mcp-server/mcp/proxy.ts:228-230`

```typescript
    // ... if neither OPENAPI_MCP_HEADERS nor NOTION_TOKEN set ...
    return {}                                                 // line 230
```

If neither `NOTION_TOKEN` nor `OPENAPI_MCP_HEADERS` is set, the server
starts successfully with **no Authorization header**. All API calls to
Notion will fail with 401 — but the MCP server itself is fully
operational and will happily forward tool calls. No startup warning or
error is emitted.

### Bypass 5: Session ID is the only "auth" after initial request

**File:** `scripts/start-server.ts:156-158`

```typescript
if (sessionId && transports[sessionId]) {
  transport = transports[sessionId]                          // line 158
}
```

After the initial authenticated request establishes a session, subsequent
requests only need the `Mcp-Session-Id` header (a UUID). The bearer
token is still checked by middleware, but the session ID itself becomes
an **additional credential**: anyone who learns a session ID and has a
valid bearer token can inject commands into that session.

Session IDs are UUIDs (`randomUUID()`, line 162) — 122 bits of entropy,
not brute-forceable. But they are transmitted in HTTP headers in
plaintext (no TLS enforced by the server).

---

## 6. Is the Auth Token Logged Anywhere?

### 6a. HTTP transport auth token — indirect file path logged

**File:** `scripts/start-server.ts:95`

```typescript
console.log(`Generated auth token written to: ${authTokenFilePath}`)
```

The **file path** is logged, not the token itself. However, the file path
reveals the PID and the existence of the token file. An attacker reading
logs knows exactly where to look.

**File:** `scripts/start-server.ts:242`

```typescript
console.log(`Read your auth token from: ${authTokenFilePath}`)
```

Same path logged again at startup.

### 6b. `--auth-token` CLI arg visible in process listing

**File:** `scripts/start-server.ts:35-37`

```typescript
} else if (args[i] === '--auth-token' && i + 1 < args.length) {
  authToken = args[i + 1];
```

When `--auth-token <token>` is used, the token appears in:
- `ps aux` output
- `/proc/<PID>/cmdline`
- Shell history (if typed interactively)
- Docker inspect output (if passed via Docker `command:`)

### 6c. Notion API token — leaked via Axios error objects

**File:** `src/openapi-mcp-server/client/http-client.ts:193-194`

```typescript
      throw new HttpClientError(..., error.response.data, headers)  // line 192
    }
    throw error    // line 194 — raw Axios error re-thrown
  }
```

**File:** `src/openapi-mcp-server/mcp/proxy.ts:193`

```typescript
    throw error   // non-HttpClientError re-thrown to MCP SDK
```

When a **network-level error** occurs (DNS failure, connection refused,
timeout), Axios throws an error **without** `.response` (the `if` on
line 179 of http-client.ts is false). The raw error is re-thrown at
http-client.ts:194 and then again at proxy.ts:193.

Axios error objects include a `.config` property containing the full
request configuration, including:

```
error.config.headers.Authorization = "Bearer <NOTION_TOKEN>"
```

The MCP SDK's default error handler serializes the thrown error into a
JSON-RPC error response. If the error's `.config.headers` survive
serialization, the Notion token is **sent to the MCP client**.

Additionally, **`start-server.ts:194`** logs the full error:

```typescript
console.error('Error handling MCP request:', error)           // line 194
```

If the MCP SDK re-throws an error from the transport layer, this
`console.error` call will print the entire error object — potentially
including `.config.headers.Authorization` — to stderr/stdout.

### 6d. OPENAPI_MCP_HEADERS parse failure leaks partial content

**File:** `src/openapi-mcp-server/mcp/proxy.ts:216`

```typescript
console.warn('Failed to parse OPENAPI_MCP_HEADERS environment variable:', error)
```

The `error` from `JSON.parse()` failure includes the problematic string
in its message. If `OPENAPI_MCP_HEADERS` contains a token but is
malformed JSON, the error message logged to stderr could include partial
token content.

Example: `OPENAPI_MCP_HEADERS='{"Authorization": "Bearer ntn_secret' }` (truncated)
would produce a SyntaxError whose message includes the truncated string.

### 6e. Notion bot ID logged (minor)

**File:** `scripts/start-server.ts:258`

```typescript
console.log(`Notion integration settings: https://www.notion.so/profile/integrations/internal/${data.id}`)
```

The integration bot ID is logged. This is not the token itself, but it
identifies the specific integration and links to its settings page.

---

## Summary of Auth Findings

| # | Finding | Severity | File:Line |
|---|---------|----------|-----------|
| A1 | Token comparison is NOT timing-safe (`!==`) | **High** | `start-server.ts:116` |
| A2 | `--disable-auth` removes all HTTP auth | **Medium** (by design, but dangerous) | `start-server.ts:38-39,141-144` |
| A3 | Stdio transport has zero authentication | **Medium** (by design) | `start-server.ts:76-80` |
| A4 | Notion token leaks via raw Axios errors re-thrown to MCP clients | **High** | `http-client.ts:194` -> `proxy.ts:193` |
| A5 | `--auth-token` value visible in process listing | **Medium** | `start-server.ts:35-37` |
| A6 | Auto-generated token file never cleaned up from `/tmp` | **Low** | `start-server.ts:93-94` |
| A7 | Server starts without warning when no Notion token is configured | **Low** | `proxy.ts:230` |
| A8 | OPENAPI_MCP_HEADERS allows arbitrary header injection | **Medium** | `proxy.ts:207,212` |
| A9 | Docker container runs as root (no USER directive) | **Low** | `Dockerfile` (no USER) |
| A10 | `/health` endpoint leaks server metadata without auth | **Low** | `start-server.ts:132-139` |
| A11 | `console.error` at `start-server.ts:194` can log full error objects containing tokens | **Medium** | `start-server.ts:194` |
| A12 | `OPENAPI_MCP_HEADERS` parse failure may log partial token in error message | **Low** | `proxy.ts:216` |
