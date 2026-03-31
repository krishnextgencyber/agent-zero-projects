# Audit Report: Dependencies & Supply Chain
## notion-mcp-server v2.3.0 — Phase 6

**Scope:** npm audit results, GitHub Actions workflow security, install scripts, supply-chain controls
**Analyst:** White-box static analysis
**Date:** 2026-03-31

---

## npm audit — Raw Output

```
# npm audit report

path-to-regexp  <=0.1.12 || 8.0.0 - 8.3.0
Severity: high
path-to-regexp vulnerable to Regular Expression Denial of Service via multiple route parameters
  https://github.com/advisories/GHSA-37ch-88jc-xwx2
path-to-regexp vulnerable to Denial of Service via sequential optional groups
  https://github.com/advisories/GHSA-j3q9-mxjg-w52f
path-to-regexp vulnerable to Regular Expression Denial of Service via multiple wildcards
  https://github.com/advisories/GHSA-27v5-c462-wpq7
fix available via `npm audit fix`
node_modules/path-to-regexp
node_modules/router/node_modules/path-to-regexp

picomatch  4.0.0 - 4.0.3
Severity: high
Picomatch: Method Injection in POSIX Character Classes causes incorrect Glob Matching
  https://github.com/advisories/GHSA-3v7f-55p6-f55p
Picomatch has a ReDoS vulnerability via extglob quantifiers
  https://github.com/advisories/GHSA-c2c7-rcm5-vvqj
fix available via `npm audit fix`
node_modules/picomatch

2 high severity vulnerabilities
```

**Metadata:**
- Total packages: 372
- Production: 179 | Dev: 192 | Optional: 77 | Peer: 2
- Critical: 0 | High: 2 | Moderate: 0 | Low: 0

---

## DEP-1 — `path-to-regexp` ReDoS (CVE chain) — HIGH, LOW EXPLOITABILITY

### Affected versions in tree

| Location | Version | Introduced by |
|----------|---------|---------------|
| `node_modules/path-to-regexp` | **0.1.12** | `express@4.22.1` |
| `node_modules/router/node_modules/path-to-regexp` | **8.3.0** | `router@2.2.0` ← `@modelcontextprotocol/sdk` bundled `express@5.2.1` |

### Advisories

| Advisory | Severity | Affected Range | CWE |
|----------|----------|----------------|-----|
| GHSA-37ch-88jc-xwx2 | HIGH (7.5) | `<0.1.13` | CWE-1333 |
| GHSA-j3q9-mxjg-w52f | HIGH (7.5) | `>=8.0.0 <8.4.0` | CWE-400, CWE-1333 |
| GHSA-27v5-c462-wpq7 | MODERATE (5.9) | `>=8.0.0 <8.4.0` | CWE-1333 |

### Exploitability Assessment: LOW

`path-to-regexp` is used by Express to **compile route pattern strings into regular expressions** at server startup. The ReDoS vulnerabilities are triggered by route pattern strings containing multiple parameters (e.g., `/:a/:b/:c`) or sequential optional groups (e.g., `/:a?/:b?`).

**Routes defined in `scripts/start-server.ts`:**
```typescript
app.get('/health', ...)      // no parameters
app.post('/mcp', ...)        // no parameters
app.get('/mcp', ...)         // no parameters
app.delete('/mcp', ...)      // no parameters
```

All routes are **static paths with no `:param` segments**. `path-to-regexp` is invoked at route registration time (startup), not per request. The route patterns are developer-controlled strings, not user input.

**Verdict:** The vulnerable code path is not reachable from user-supplied input in the current codebase. However, the vulnerability exists in the dependency tree, and any future route additions with parameters could reintroduce the risk. **Patch recommended.**

### Dependency Chain (prod)

```
notion-mcp-server
└── express@4.22.1                        [prod]
    └── path-to-regexp@0.1.12             ← VULNERABLE (GHSA-37ch-88jc-xwx2)

notion-mcp-server
└── @modelcontextprotocol/sdk@1.26.0      [prod]
    └── express@5.2.1                     [prod, nested]
        └── router@2.2.0                  [prod]
            └── path-to-regexp@8.3.0      ← VULNERABLE (GHSA-j3q9-mxjg-w52f, GHSA-27v5-c462-wpq7)
```

### Fix

```bash
npm audit fix
# Updates:
#   express@4.22.1 -> express@4.x (path-to-regexp 0.1.13+)
#   router@2.2.0 -> router@2.x (path-to-regexp 8.4.0+)
```

---

## DEP-2 — `picomatch` ReDoS + Method Injection — HIGH, NOT EXPLOITABLE IN PRODUCTION

### Affected version: `picomatch@4.0.3`

| Advisory | Severity | Affected Range | CWE |
|----------|----------|----------------|-----|
| GHSA-c2c7-rcm5-vvqj | HIGH (7.5) | `>=4.0.0 <4.0.4` | CWE-1333 (ReDoS via extglob quantifiers) |
| GHSA-3v7f-55p6-f55p | MODERATE (5.3) | `>=4.0.0 <4.0.4` | CWE-1321 (method injection in POSIX char classes) |

### Dependency Chain (dev only)

```
notion-mcp-server
└── vitest@4.0.18                         [dev]
    └── tinyglobby@0.2.13                 [dev]
    │   └── picomatch@4.0.3               ← VULNERABLE
    └── vite@6.3.4                        [dev]
        └── picomatch@4.0.3               ← VULNERABLE
```

**`picomatch` is a devDependency only** — not included in production builds. The `npm pack` / published package at `bin/cli.mjs` does not bundle vitest or picomatch.

**Verdict:** Not exploitable in production. The vulnerability only runs during `npm test` in development environments. Still worth patching.

### Fix

```bash
npm audit fix
# Updates picomatch@4.0.3 -> 4.0.4+
```

---

## GitHub Actions Workflow Analysis

### File: `.github/workflows/ci.yml`

```yaml
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
```

#### CI-1 — Actions Pinned to Full Commit SHAs (GOOD)

Both actions are pinned to full 40-character commit SHAs — not floating tags like `@v4` or `@latest`. This prevents **tag mutation attacks** where an action maintainer (or attacker who compromises the maintainer's account) could push malicious code to a tag that existing workflows would silently start running.

| Action | Pinned SHA | Resolved Version |
|--------|-----------|-----------------|
| `actions/checkout` | `08c6903cd8c0fde910a37f88322edcfb5dd907a8` | **v5.0.0** (confirmed: commit message "Prepare v5.0.0 release (#2238)") |
| `actions/setup-node` | `a0853c24544627f65ddf259abe73b1d18a591444` | **v5.0.0** (confirmed: matches `v5` and `v5.0.0` tags in `actions/setup-node`) |

**Note:** `actions/setup-node` latest is v6.3.0 at time of audit. The pinned v5.0.0 is not the latest but is a known-good version. SHA pinning is the critical control here. Recommend updating to latest SHA-pinned versions.

#### CI-2 — No Dangerous Triggers (GOOD)

The following dangerous triggers are **absent**:

| Trigger | Risk | Present? |
|---------|------|----------|
| `pull_request_target` | Runs in privileged context with repo secrets, can be triggered by fork PRs | **NO** |
| `workflow_run` | Can trigger on completion of a workflow from a fork | **NO** |
| `repository_dispatch` | External HTTP trigger | **NO** |
| `workflow_dispatch` | Manual trigger (moderate risk) | **NO** |

The workflow uses `pull_request` (not `pull_request_target`), which runs in an unprivileged context for fork PRs — the standard safe pattern.

#### CI-3 — No Explicit `permissions` Block (MEDIUM RISK)

**File:** `.github/workflows/ci.yml` — no `permissions:` key anywhere in the file.

```yaml
# MISSING from ci.yml:
# permissions:
#   contents: read
```

When `permissions` is omitted, GitHub uses the **repository's default token permissions**, which on many repositories defaults to **read/write for most scopes** (contents, packages, pull-requests, issues, etc.). If a dependency or build step were compromised (supply-chain attack), the `GITHUB_TOKEN` would grant write access to the repository.

**Recommended Fix:** Add a minimal permissions block at the top level and grant only what's needed:

```yaml
permissions:
  contents: read      # checkout only

jobs:
  test:
    permissions:
      contents: read  # reinforce at job level
```

This follows the principle of least privilege and is required by OpenSSF Scorecard.

#### CI-4 — No Secret Scanning or SAST Step (INFORMATIONAL)

The CI pipeline runs only `npm ci`, `npm run build`, and `npm test`. There is no:
- Secret scanning (e.g., `trufflesecurity/trufflehog`, `gitleaks/gitleaks-action`)
- Static analysis (e.g., CodeQL, Semgrep)
- Dependency review action (e.g., `actions/dependency-review-action`)
- SBOM generation

For a package published to npm that handles auth tokens and makes outbound API requests, adding at minimum `actions/dependency-review-action` would catch new vulnerable dependencies on PRs.

---

## Install Scripts Analysis

### Packages with `hasInstallScript: true`

| Package | Version | Type | Script | Risk |
|---------|---------|------|--------|------|
| `esbuild` | 0.25.5 | devDep | `postinstall: node install.js` | LOW |
| `esbuild` (vitest copy) | 0.27.3 | devDep | `postinstall: node install.js` | LOW |
| `fsevents` | 2.3.3 | devDep (optional, macOS) | `install: node-gyp rebuild` | LOW |

**`esbuild` postinstall analysis:**

`esbuild/install.js` downloads the platform-specific native binary package (e.g., `@esbuild/linux-x64`) from the npm registry. This is a well-known pattern for native tooling and is not inherently malicious. The binary package integrity is verified via `package-lock.json` SRI hashes (`sha512`). However, this does mean that `npm install` makes an additional outbound npm registry request to fetch the binary.

**`fsevents` install analysis:**

`fsevents` runs `node-gyp rebuild` to compile native C++ bindings for macOS FSEvents API. It is `optional` and `dev`-only — it only builds on macOS and is completely skipped on Linux/Windows CI. Not a risk.

**No production dependencies have install scripts.** All install-time code execution is limited to dev tooling.

---

## Package Integrity Controls

### Lock File

- **`lockfileVersion: 3`** — most recent format; includes integrity hashes for all packages
- All 26 direct dependencies have `sha512` integrity hashes in `package-lock.json`
- Zero packages resolved from git URLs, GitHub URLs, or non-npmjs.org registries

### Sample integrity verification

```
@modelcontextprotocol/sdk@1.26.0: sha512 ✓
axios@1.13.5:                      sha512 ✓
express@4.22.1:                    sha512 ✓
openapi-client-axios@7.6.0:        sha512 ✓
mustache@4.2.0:                    sha512 ✓
```

All 26 direct dependencies verified with `sha512` hashes. ✓

### No `.npmrc` custom registry

No `.npmrc` file exists. All packages resolve to `https://registry.npmjs.org/`. No risk of registry confusion attacks from custom private registry configuration.

---

## Additional Supply Chain Observations

### Node.js version: No constraint

`package.json` has no `engines` field, no `.nvmrc`, and no `.node-version` file. The CI matrix tests on `[20.x, 22.x]` but the published package has no minimum Node.js version enforcement.

**Risk:** A user running an EOL Node.js version (e.g., Node 16) would get no warning. Additionally, `npm audit` results can differ across Node.js versions.

**Recommendation:** Add to `package.json`:
```json
"engines": {
  "node": ">=20.0.0"
}
```

### `minimist@1.2.8` (dev)

`minimist` appeared in historical prototype-pollution advisories (`GHSA-xvch-5gv4-984h`, fixed in `1.2.6`). Version `1.2.8` is patched. Introduced via `mkdirp` (devDep). Not a finding.

---

## Findings Summary

| ID | Title | Severity | Production Impact |
|----|-------|----------|------------------|
| DEP-1 | `path-to-regexp` ReDoS (3 advisories) — in `express@4` and `router` (MCP SDK) | HIGH | LOW (static routes only) |
| DEP-2 | `picomatch` ReDoS + method injection | HIGH | NONE (dev only) |
| CI-3 | No `permissions:` block in CI workflow — GITHUB_TOKEN has default (broad) permissions | MEDIUM | Repo write risk on compromise |
| CI-4 | No secret scanning, SAST, or dependency review in CI | INFORMATIONAL | — |

---

## Key References

| File | Lines | Description |
|------|-------|-------------|
| `.github/workflows/ci.yml` | 4–7 | Triggers: `push` + `pull_request` (safe, no `pull_request_target`) |
| `.github/workflows/ci.yml` | 19 | `actions/checkout@08c6903...` = v5.0.0, SHA-pinned |
| `.github/workflows/ci.yml` | 22 | `actions/setup-node@a0853c24...` = v5.0.0, SHA-pinned |
| `package-lock.json` | — | `lockfileVersion: 3`, all deps with `sha512` integrity |
| `package.json` | — | No `engines` field; no Node.js version constraint |
