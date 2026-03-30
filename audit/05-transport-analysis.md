# Audit Report: Transport Security Analysis
## notion-mcp-server v2.3.0 — Phase 5

**Scope:** HTTP transport binding, auth token generation, session management, rate limiting, CORS, error handling
**Analyst:** White-box static analysis
**Date:** 2026-03-30

---

## Executive Summary

The HTTP transport has **one confirmed high-severity finding** (TRANS-1: binding to `0.0.0.0`), **one confirmed medium-severity finding** (TRANS-4: no rate limiting), and several low-severity issues including missing CORS/DNS-rebinding protection, missing `X-Powered-By` suppression, and session TTL absence. The auth token itself is cryptographically strong (`randomBytes(32)`, 256-bit), but its delivery mechanism has two weaknesses: it leaks via `--auth-token` in process arguments, and the `/tmp` file path is predictable by PID. The comparison is non-constant-time (previously documented as AUTH-3).

---

## TRANS-1 — Server Binds to All Interfaces (`0.0.0.0`) (CONFIRMED)

### Severity: HIGH

**File:** `scripts/start-server.ts`, line 233

```typescript
app.listen(port, '0.0.0.0', async () => {
  console.log(`MCP Server listening on port ${port}`)
  console.log(`Endpoint: http://0.0.0.0:${port}/mcp`)
```

The server binds to `0.0.0.0` — all network interfaces — not just `127.0.0.1` (loopback). This means:

- In **Docker containers**: the MCP endpoint is reachable from the host and from any container on the same bridge network, not just the container itself.
- In **cloud VMs** (EC2, GCE, Azure): the port is exposed on the public IP unless blocked by a firewall/security group.
- In **local development**: the endpoint is reachable from the LAN.

**Impact matrix:**

| Deployment | Auth Enabled (`default`) | Auth Disabled (`--disable-auth`) |
|-----------|--------------------------|----------------------------------|
| Container on Docker bridge | Anyone on bridge can reach `/mcp`; must guess/steal 256-bit token | Anyone on bridge has full Notion API access |
| Cloud VM without SG | Publicly exposed; bearer token is the only guard | Notion API fully open to internet |
| Local dev machine | Reachable from LAN; token required | Notion API open to LAN |

**Proof of Concept (LAN access):**

```bash
# On attacker machine on same LAN/Docker network:
curl http://<victim-ip>:3000/health
# Returns: {"status":"healthy","timestamp":"...","transport":"http","port":3000}

# Without token (auth disabled):
curl -X POST http://<victim-ip>:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"attacker","version":"1.0"}},"id":1}'
# Returns: MCP session initialized — full Notion API access
```

**Root Cause:** `scripts/start-server.ts:233` — hardcoded `'0.0.0.0'` bind address.

**Recommended Fix:**

```typescript
const bindAddress = process.env.BIND_ADDRESS ?? '127.0.0.1'  // default to loopback
app.listen(port, bindAddress, async () => { ... })
```

Document the `--bind` flag or `BIND_ADDRESS` env var in the help text. Require explicit opt-in for external binding.

---

## TRANS-2 — Auth Token Exposed in Process Arguments (CONFIRMED)

### Severity: MEDIUM

**File:** `scripts/start-server.ts`, lines 35–36 and 90

```typescript
} else if (args[i] === '--auth-token' && i + 1 < args.length) {
  authToken = args[i + 1];  // value stored from CLI args
```

```typescript
authToken = options.authToken || process.env.AUTH_TOKEN || randomBytes(32).toString('hex')
```

When the user provides `--auth-token <value>`, it is visible in:

1. **`ps aux` / `/proc/<pid>/cmdline`** — readable by any user with access to the process list:
   ```bash
   $ ps aux | grep notion
   user  1234  ...  node notion-mcp-server --transport http --auth-token mysecrettoken123
   ```
2. **Shell history files** (`.bash_history`, `.zsh_history`) — persisted after the command exits.
3. **System audit logs** (`/var/log/auth.log`, auditd, CloudTrail) — command arguments are logged.

**Auto-generated token path** (`/tmp/.notion-mcp-auth-token-<PID>`) is safer (mode `0o600`, not in process args), but the PID is predictable from `ps` output and the `/tmp` directory listing is world-readable on most systems:

```bash
# Anyone who can run ls /tmp can see the token file name:
$ ls /tmp/.notion-mcp-auth-token-*
/tmp/.notion-mcp-auth-token-1234

# If the process runs as the same user (or as root), the file is readable:
$ cat /tmp/.notion-mcp-auth-token-1234
a3f8c1e2d4b5...  # 64-char hex token
```

**Recommended Fix:** Never accept secrets via CLI arguments. Use only `AUTH_TOKEN` env var or a config file with restricted permissions. Add a `--auth-token-file` option for file-based delivery.

---

## TRANS-3 — Auth Token Comparison Is Not Timing-Safe (CONFIRMED)

### Severity: MEDIUM (previously documented as AUTH-3)

**File:** `scripts/start-server.ts`, line 116

```typescript
if (token !== authToken) {
```

JavaScript's `!==` operator uses short-circuit string comparison — it exits as soon as it finds a mismatching byte, leaking timing information proportional to the number of correct leading bytes. A timing oracle allows statistical brute-force of the token one byte at a time.

**Recommended Fix:**

```typescript
import { timingSafeEqual } from 'node:crypto'

const tokenBuf = Buffer.from(token, 'utf8')
const authBuf = Buffer.from(authToken, 'utf8')
if (tokenBuf.length !== authBuf.length || !timingSafeEqual(tokenBuf, authBuf)) {
  // reject
}
```

---

## TRANS-4 — No Rate Limiting on MCP Endpoint (CONFIRMED)

### Severity: MEDIUM

**File:** `scripts/start-server.ts`, lines 83–143

```typescript
const app = express()
app.use(express.json())
// ... NO rate limiting middleware applied ...
if (!options.disableAuth) {
  app.use('/mcp', authenticateToken)
}
```

`express-rate-limit` v8.3.1 is installed (as a transitive dependency of `@modelcontextprotocol/sdk`) but is **never imported or configured** by the application code. No rate limiting middleware appears anywhere in `start-server.ts` or any other file outside tests.

**Impact:**

1. **Token brute-force**: An attacker who can reach the server can send unlimited authentication attempts. The 256-bit auto-generated token is infeasible to brute-force, but user-supplied `--auth-token` values (which may be short or dictionary words) are not protected.

2. **Request flooding**: An attacker can flood the `/mcp` endpoint, issuing thousands of tool calls per second. Each tool call:
   - Spawns an `async` handler on the Express event loop
   - Issues an outbound HTTP request to Notion API (or `BASE_URL`) with no timeout
   - Holds an MCP session open indefinitely

3. **Session table exhaustion**: The `transports` map (line 147) is an in-memory object with no maximum size. An attacker who can authenticate (or if auth is disabled) can create unlimited sessions, each consuming server memory.

**Proof of Concept (DoS without auth, `--disable-auth` mode):**

```bash
# Flood with initialization requests (each creates a new session + spawns initProxy)
for i in $(seq 1 10000); do
  curl -s -X POST http://target:3000/mcp \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"x","version":"1"}},"id":1}' &
done
# Process and memory exhaustion
```

**Recommended Fix:**

```typescript
import rateLimit from 'express-rate-limit'

const limiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minute
  max: 100,              // 100 requests per window per IP
  standardHeaders: true,
  legacyHeaders: false,
})
app.use('/mcp', limiter)
app.use('/health', rateLimit({ windowMs: 60000, max: 30 }))
```

---

## TRANS-5 — No CORS Headers / DNS Rebinding Protection Disabled (CONFIRMED)

### Severity: MEDIUM

**File:** `scripts/start-server.ts`, lines 160–167

```typescript
transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
  onsessioninitialized: (sessionId) => {
    transports[sessionId] = transport
  }
})
```

The `StreamableHTTPServerTransport` constructor accepts security options `allowedOrigins`, `allowedHosts`, and `enableDnsRebindingProtection` (from MCP SDK `webStandardStreamableHttp.js` lines 66–79). **None of these are configured:**

```typescript
// MCP SDK WebStandardStreamableHTTPServerTransport constructor (sdk v1.26.0):
this._allowedHosts = options.allowedHosts;       // NOT SET → undefined
this._allowedOrigins = options.allowedOrigins;   // NOT SET → undefined
this._enableDnsRebindingProtection = options.enableDnsRebindingProtection ?? false;  // false
```

**Consequence 1 — DNS Rebinding Attack:**

DNS rebinding allows a malicious webpage to make cross-origin requests to the MCP server (which is bound to `0.0.0.0`). Since `enableDnsRebindingProtection: false` is the default, the SDK skips Host header validation entirely:

```javascript
// sdk webStandardStreamableHttp.js line 109:
if (!this._enableDnsRebindingProtection) {
  return undefined;  // skip all header validation
}
```

Attack scenario:
1. Victim visits `http://attacker.com` in their browser
2. Attacker's DNS TTL expires; DNS re-resolves `attacker.com` → `127.0.0.1`
3. Browser treats subsequent `fetch('http://attacker.com:3000/mcp')` as same-origin
4. If auth is disabled (or attacker obtains the token), full MCP tool access from the browser page

**Consequence 2 — No CORS Restriction:**

Express does not apply CORS headers. A browser page on any origin can make same-origin (after DNS rebinding) or cross-origin requests. Without an `Access-Control-Allow-Origin` restriction, the browser's CORS policy is the only barrier — but DNS rebinding bypasses it.

**Recommended Fix:**

```typescript
transport = new StreamableHTTPServerTransport({
  sessionIdGenerator: () => randomUUID(),
  enableDnsRebindingProtection: true,
  allowedHosts: ['localhost', `localhost:${port}`, '127.0.0.1', `127.0.0.1:${port}`],
  allowedOrigins: [],  // MCP clients are not browsers; reject all browser-origin requests
  onsessioninitialized: (sessionId) => {
    transports[sessionId] = transport
  }
})
```

---

## TRANS-6 — Session Has No TTL / Expiry (CONFIRMED)

### Severity: LOW

**File:** `scripts/start-server.ts`, lines 146–174

```typescript
const transports: { [sessionId: string]: StreamableHTTPServerTransport } = {}
// ...
onsessioninitialized: (sessionId) => {
  transports[sessionId] = transport
}
// Sessions are only removed on explicit close:
transport.onclose = () => {
  if (transport.sessionId) {
    delete transports[transport.sessionId]  // only on explicit DELETE or error
  }
}
```

Sessions are stored indefinitely in the in-memory `transports` map. There is no:
- Maximum session age (no TTL)
- Idle timeout (no last-activity tracking)
- Maximum concurrent session count

**Impact:** Abandoned sessions (e.g., client disconnected without `DELETE /mcp`) accumulate in memory indefinitely, eventually exhausting the Node.js heap.

Combined with TRANS-4 (no rate limiting), an attacker can create sessions faster than they are naturally cleaned up.

**Recommended Fix:** Add an idle-timeout sweep:

```typescript
const SESSION_TTL_MS = 30 * 60 * 1000  // 30 minutes
const sessionLastSeen: Map<string, number> = new Map()

setInterval(() => {
  const now = Date.now()
  for (const [id, t] of Object.entries(transports)) {
    if ((now - (sessionLastSeen.get(id) ?? 0)) > SESSION_TTL_MS) {
      t.close()
      delete transports[id]
      sessionLastSeen.delete(id)
    }
  }
}, 60_000)
```

---

## TRANS-7 — `/health` Endpoint Leaks Server Metadata (CONFIRMED)

### Severity: LOW

**File:** `scripts/start-server.ts`, lines 132–139

```typescript
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    transport: 'http',
    port: options.port           // ← leaks actual bind port
  })
})
```

The `/health` endpoint:
1. Requires **no authentication** (line 131: `// Health endpoint (no authentication required)`)
2. Returns the `port` number — useful for attackers enumerating services
3. Returns a `timestamp` — useful for timing correlation in attacks

More critically, the startup log (line 234–236) emits:
```
MCP Server listening on port 3000
Endpoint: http://0.0.0.0:3000/mcp
Read your auth token from: /tmp/.notion-mcp-auth-token-1234
```
If stdout is captured by a logging service (Datadog, Splunk, CloudWatch), the token file path (and indirectly the PID) is exposed to anyone with log access.

**Note:** The health endpoint also reveals that `X-Powered-By: Express` is sent by default (Express 4 does not suppress this header unless `app.disable('x-powered-by')` is called). This confirms the server framework and version to attackers.

**Recommended Fix:**

```typescript
// Suppress Express fingerprinting
app.disable('x-powered-by')

// Minimal health response (no operational metadata)
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy' })
})
```

---

## TRANS-8 — Error Responses Mix Content Types (INFORMATIONAL)

### Severity: INFORMATIONAL

**File:** `scripts/start-server.ts`, lines 210–213 and 222–225

```typescript
// GET /mcp — returns plain text on error
res.status(400).send('Invalid or missing session ID')

// DELETE /mcp — returns plain text on error
res.status(400).send('Invalid or missing session ID')

// POST /mcp — returns JSON on error
res.status(400).json({ jsonrpc: '2.0', error: { ... } })
```

The GET and DELETE error handlers return `text/plain` responses while POST returns `application/json`. This inconsistency can cause MCP client parsers to fail silently or surface confusing error messages rather than structured JSON-RPC error objects.

---

## Findings Summary

| ID | Title | Severity | Confirmed |
|----|-------|----------|-----------|
| TRANS-1 | Server binds to `0.0.0.0` — accessible from all interfaces | HIGH | YES |
| TRANS-2 | `--auth-token` value visible in `ps aux` / shell history | MEDIUM | YES |
| TRANS-3 | Non-constant-time token comparison (`!==`) | MEDIUM | YES (see AUTH-3) |
| TRANS-4 | No rate limiting on `/mcp` or `/health` endpoints | MEDIUM | YES |
| TRANS-5 | No CORS headers; DNS rebinding protection disabled | MEDIUM | YES |
| TRANS-6 | Sessions have no TTL — memory accumulation / session table exhaustion | LOW | YES |
| TRANS-7 | `/health` leaks port/metadata; no `X-Powered-By` suppression | LOW | YES |
| TRANS-8 | GET/DELETE `/mcp` return `text/plain` errors instead of JSON | INFORMATIONAL | YES |

---

## Key Code References

| File | Lines | Description |
|------|-------|-------------|
| `scripts/start-server.ts` | 233 | `app.listen(port, '0.0.0.0', ...)` — binds all interfaces |
| `scripts/start-server.ts` | 35–36 | `--auth-token` stored from CLI args (visible in `ps`) |
| `scripts/start-server.ts` | 90 | Token generation: `randomBytes(32).toString('hex')` (256-bit) |
| `scripts/start-server.ts` | 93–94 | Token written to `/tmp/.notion-mcp-auth-token-<PID>` (0o600) |
| `scripts/start-server.ts` | 116 | `token !== authToken` — non-constant-time comparison |
| `scripts/start-server.ts` | 142–143 | `app.use('/mcp', authenticateToken)` — auth applied, no rate limit |
| `scripts/start-server.ts` | 147 | `transports: { [sessionId: string]: ... }` — unbounded map |
| `scripts/start-server.ts` | 160–167 | `new StreamableHTTPServerTransport({...})` — no `allowedOrigins`, no DNS rebinding protection |
| `scripts/start-server.ts` | 132–139 | `/health` — unauthenticated, leaks port |
| MCP SDK `webStandardStreamableHttp.js` | 109 | `enableDnsRebindingProtection` defaults to `false` |
| MCP SDK `webStandardStreamableHttp.js` | 124–132 | `allowedOrigins` check — only runs when configured |
