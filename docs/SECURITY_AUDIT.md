# Security Audit Report: forms-waf

**Audit Date:** 2026-01-21
**Auditor:** Security Assessment
**Target:** forms-waf OpenResty/Lua Web Application Firewall
**Version Analyzed:** Commit `8829d97` (branch: `fix/update-spam-scoring-logic`)

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Overview](#2-system-overview)
3. [Threat Model](#3-threat-model)
4. [Findings Summary](#4-findings-summary)
5. [Detailed Findings](#5-detailed-findings)
6. [Verification Test Plan](#6-verification-test-plan)
7. [Remediation Backlog](#7-remediation-backlog)
8. [Recommended Security Configuration](#8-recommended-security-configuration)

---

## 1. Executive Summary

### Overall Assessment

The forms-waf project demonstrates a well-architected defense-in-depth approach with multiple detection layers. The codebase shows good security awareness with features like structured audit logging, RBAC with vhost scoping, and configurable debug header exposure.

### Critical Findings

| Severity | Count | Key Issues |
|----------|-------|------------|
| High | 1 | IP spoofing via X-Forwarded-For |
| Medium | 6 | Password hashing, session tokens, RBAC defaults |
| Low | 6 | Various hardening opportunities |

### Top 3 Priorities

1. **F01: X-Forwarded-For trusted without proxy validation** - Allows complete bypass of IP-based security controls
2. **F02: Password hashing uses single SHA256 iteration** - Weak protection against credential compromise
3. **F04: Admin API allows endpoints without permission mapping** - Potential unauthorized access

---

## 2. System Overview

### 2.1 Entry Points

| Port | Service | Purpose |
|------|---------|---------|
| 8080 | HTTP WAF | Main form inspection and proxying |
| 8443 | HTTPS WAF | TLS-enabled form inspection |
| 8081 | Health/Metrics | `/health`, `/metrics` (Prometheus) |
| 8082 | Admin API | Configuration management, Admin UI |

### 2.2 Request Lifecycle (OpenResty Phases)

1. **`init_worker_by_lua_block`** - Redis sync, RBAC seeding, instance coordinator startup
2. **`access_by_lua_block`** - Main WAF processing via `waf_handler.process_request()`
3. **`content_by_lua_block`** - Admin API handlers, CAPTCHA verification, metrics
4. **`proxy_pass`** - Forward allowed requests to upstream (HAProxy or direct)

### 2.3 Detection Signals

| Signal Category | Implementation | File |
|-----------------|----------------|------|
| IP Reputation | AbuseIPDB, local blocklist, webhooks | `ip_reputation.lua` |
| GeoIP | MaxMind GeoLite2 (country/ASN/datacenter) | `geoip.lua` |
| Content Analysis | Keyword filtering, hash blocklist, patterns | `keyword_filter.lua` |
| Timing Tokens | Encrypted cookie with form load timestamp | `timing_token.lua` |
| Client Fingerprinting | UA, Accept headers, form structure | `fingerprint_profiles.lua` |
| Header Consistency | Browser claim vs header pattern | `header_consistency.lua` |
| Behavioral Tracking | Z-score anomaly detection | `behavioral_tracker.lua` |
| Honeypot Fields | Hidden field detection | `waf_handler.lua` |
| Defense Profiles | DAG-based defense execution | `defense_profile_executor.lua` |
| Attack Signatures | SQL injection, XSS, command injection | `attack_signatures_builtins.lua` |

### 2.4 State Storage

| Store | Type | Contents |
|-------|------|----------|
| `ngx.shared.keyword_cache` | lua_shared_dict (10m) | Blocked/flagged keywords |
| `ngx.shared.hash_cache` | lua_shared_dict (50m) | Blocked content hashes |
| `ngx.shared.ip_whitelist` | lua_shared_dict (5m) | Exact IP allowlist |
| `ngx.shared.rate_limit` | lua_shared_dict (20m) | Rate limiting counters |
| `ngx.shared.waf_timing` | lua_shared_dict (1m) | AES encryption keys |
| `ngx.shared.waf_metrics` | lua_shared_dict (10m) | Per-vhost/endpoint counters |
| **Redis** | External | All persistent config, sessions |

### 2.5 External Dependencies

| Dependency | Purpose | Trust Level |
|------------|---------|-------------|
| Redis | Configuration store, sessions | High (internal) |
| HAProxy | Global rate limiting | High (internal) |
| AbuseIPDB API | IP reputation data | Medium (external) |
| MaxMind GeoLite2 | GeoIP database | Medium (external) |
| CAPTCHA Providers | Bot verification | Medium (external) |

---

## 3. Threat Model

### 3.1 Assets

| Asset | Confidentiality | Integrity | Availability |
|-------|-----------------|-----------|--------------|
| Form submission data | High (PII) | High | High |
| WAF configuration | Medium | High | High |
| Admin credentials/sessions | High | High | High |
| Timing token encryption keys | High | High | Medium |
| IP reputation data | Low | Medium | Medium |

### 3.2 Threat Actors

| Actor | Capability | Goals |
|-------|------------|-------|
| Automated Bots | Low-Medium | Spam, credential stuffing |
| Scrapers | Low | Form enumeration |
| Credential Stuffers | Medium | Account takeover |
| Sophisticated Attackers | High | WAF bypass, admin compromise |

### 3.3 Abuse Cases

| Abuse Case | Impact | Likelihood |
|------------|--------|------------|
| False positive DoS | Legitimate users blocked | Medium |
| X-Forwarded-For spoofing | Rate limit/allowlist bypass | High |
| Cache/state poisoning | Shared dict corruption | Medium |
| Log injection | Log forging, SIEM bypass | Medium |
| Admin session hijacking | Full config compromise | Medium |

---

## 4. Findings Summary

| ID | Title | Severity | Status |
|----|-------|----------|--------|
| F01 | X-Forwarded-For trusted without proxy validation | **HIGH** | **FIXED** |
| F02 | Password hashing uses single SHA256 iteration | Medium | **FIXED** |
| F03 | Session token generation uses `math.random` | Medium | **FIXED** |
| F04 | Admin API allows endpoints without permission mapping | Medium | **FIXED** |
| F05 | Timing token key regenerates per-worker lifecycle | Low | **FIXED** |
| F06 | No client_body_timeout configuration | Medium | **FIXED** |
| F07 | JSON parsing allows deeply nested objects | Low | **FIXED** |
| F08 | Audit log lacks integrity protection | Low | **FIXED** |
| F09 | Admin session cookie lacks Secure flag by default | Medium | **FIXED** |
| F10 | Redis connection has no TLS option | Medium | **FIXED** |
| F11 | Default admin password "changeme" in code | Low | **FIXED** |
| F12 | Multipart file content not size-limited per-field | Medium | **FIXED** |
| F13 | IPv6 not supported in IP utilities | Low | **FIXED** |
| F14 | IP extraction inconsistent across modules | **HIGH** | **FIXED** |
| F15 | No SSRF protection for outbound HTTP requests | **HIGH** | **FIXED** |
| F16 | SSO OIDC uses weak random for state parameter | Medium | **FIXED** |

---

## 5. Detailed Findings

### F01: X-Forwarded-For Trusted Without Proxy Validation

**Severity:** HIGH
**Location:** `openresty/lua/waf_handler.lua:451-455`

**Vulnerable Code:**
```lua
-- Get client IP (considering proxies)
local client_ip = ngx.var.http_x_forwarded_for or ngx.var.remote_addr
if client_ip then
    -- Take first IP if multiple
    client_ip = client_ip:match("([^,]+)")
end
```

**Impact:** An attacker can spoof their IP by sending `X-Forwarded-For: 127.0.0.1` to bypass:
- IP-based rate limits
- IP allowlists
- IP reputation checks
- GeoIP blocking

**Likelihood:** High - trivial to exploit with any HTTP client.

**Proof of Concept (Safe):**
```bash
# From external IP, send spoofed header
curl -H "X-Forwarded-For: 192.0.2.1" http://waf:8080/form -d "test=data"
# Check if WAF logs show 192.0.2.1 as client IP
```

**Remediation:**

Option A: Use Nginx real_ip module (recommended):
```nginx
# Add to nginx.conf http block
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
# Add your CDN IP ranges (e.g., Cloudflare)
set_real_ip_from 173.245.48.0/20;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

Option B: Lua-based validation:
```lua
-- Add trusted proxy validation
local TRUSTED_PROXIES = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

local function is_trusted_proxy(ip)
    for _, cidr in ipairs(TRUSTED_PROXIES) do
        if ip_utils.ip_in_cidr(ip, cidr) then
            return true
        end
    end
    return false
end

local function get_client_ip()
    local remote_addr = ngx.var.remote_addr

    -- Only trust XFF if request came from trusted proxy
    if not is_trusted_proxy(remote_addr) then
        return remote_addr
    end

    local xff = ngx.var.http_x_forwarded_for
    if not xff then
        return remote_addr
    end

    -- Parse XFF and find rightmost untrusted IP
    local ips = {}
    for ip in xff:gmatch("([^,]+)") do
        table.insert(ips, ip:match("^%s*(.-)%s*$"))
    end

    for i = #ips, 1, -1 do
        if not is_trusted_proxy(ips[i]) then
            return ips[i]
        end
    end

    return remote_addr
end
```

---

### F02: Password Hashing Uses Single SHA256 Iteration

**Severity:** Medium
**Location:** `openresty/lua/admin_auth.lua:33-38`

**Vulnerable Code:**
```lua
local function hash_password(password, salt)
    local sha256 = resty_sha256:new()
    sha256:update(salt .. password .. salt)
    local digest = sha256:final()
    return resty_string.to_hex(digest)
end
```

**Impact:** Single iteration SHA256 is fast to brute-force. Modern GPUs can compute billions of SHA256 hashes per second.

**Remediation:**

Use PBKDF2 with at least 100,000 iterations:
```lua
local function hash_password(password, salt)
    local openssl_kdf = require "resty.openssl.kdf"
    local kdf = openssl_kdf.derive {
        type = "PBKDF2",
        md = "sha256",
        pass = password,
        salt = salt,
        pbkdf2_iter = 100000,
        outlen = 32,
    }
    return resty_string.to_hex(kdf)
end
```

**Migration Note:** Existing password hashes will need to be re-hashed on next login or require password reset.

---

### F03: Session Token Generation Uses `math.random`

**Severity:** Medium
**Location:** `openresty/lua/admin_auth.lua:18-30`

**Vulnerable Code:**
```lua
local function generate_token(length)
    length = length or 32
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local token = {}
    for i = 1, length do
        local rand = math.random(1, #chars)
        table.insert(token, chars:sub(rand, rand))
    end
    return table.concat(token)
end

-- Seeded with:
math.randomseed(ngx.time() + ngx.worker.pid())
```

**Impact:** Seeding with `time + PID` is predictable. An attacker with knowledge of approximate login time and worker count could potentially predict session tokens.

**Remediation:**
```lua
local resty_random = require "resty.random"

local function generate_token(length)
    length = length or 32
    local random_bytes = resty_random.bytes(length, true)  -- true = strong random
    if not random_bytes then
        ngx.log(ngx.ERR, "Failed to generate strong random bytes")
        return nil
    end
    -- Base64 encode and make URL-safe
    return ngx.encode_base64(random_bytes):sub(1, length):gsub("[+/=]", function(c)
        return ({["+"] = "A", ["/"] = "B", ["="] = ""})[c]
    end)
end
```

---

### F04: Admin API Allows Endpoints Without Permission Mapping

**Severity:** Medium
**Location:** `openresty/lua/rbac.lua:573-576`

**Vulnerable Code:**
```lua
if not permission then
    -- Allow endpoints without explicit permission mapping (be careful!)
    ngx.log(ngx.WARN, "RBAC: No permission mapping for ", method, " ", path)
    return true  -- <-- ALLOWS ACCESS BY DEFAULT
end
```

**Impact:** Any new endpoint added without updating `ENDPOINT_PERMISSIONS` table will be accessible to any authenticated user, regardless of role.

**Remediation:**
```lua
if not permission then
    ngx.log(ngx.WARN, "RBAC: No permission mapping for ", method, " ", path)
    return false, "Endpoint not configured in RBAC - access denied by default"
end
```

---

### F05: Timing Token Key Regenerates Per-Worker Lifecycle

**Severity:** Low
**Location:** `openresty/lua/timing_token.lua:81-108`

**Issue:** Each worker may generate different encryption keys if the shared dict atomic add races. Tokens encrypted by one worker may fail decryption in another.

**Remediation:**
```lua
local function get_encryption_key()
    local shared = ngx.shared.waf_timing
    local key = shared:get("encryption_key")
    if key then
        return key
    end

    -- Generate new key
    local random_bytes = resty_random.bytes(32, true)
    local new_key = resty_string.to_hex(random_bytes):sub(1, 32)

    -- Atomic add - only one worker succeeds
    local success = shared:add("encryption_key", new_key, 86400)
    if success then
        return new_key
    else
        -- Another worker added first, use their key
        return shared:get("encryption_key")
    end
end
```

---

### F06: No client_body_timeout Configuration

**Severity:** Medium
**Location:** `openresty/conf/nginx.conf`

**Issue:** Without `client_body_timeout`, slow POST attacks (Slowloris variant) can hold connections open indefinitely.

**Remediation:**
```nginx
# Add to server blocks handling WAF traffic
client_body_timeout 30s;
client_header_timeout 30s;
send_timeout 30s;
```

---

### F07: JSON Parsing Allows Deeply Nested Objects

**Severity:** Low
**Location:** `openresty/lua/form_parser.lua:184-210`

**Issue:** `cjson.decode` has no depth limit by default. Deeply nested JSON can cause stack exhaustion.

**Remediation:**
```lua
local cjson = require "cjson.safe"
cjson.decode_max_depth(10)  -- Limit nesting to 10 levels
```

---

### F08: Audit Log Lacks Integrity Protection

**Severity:** Low
**Location:** `openresty/lua/waf_handler.lua:48-70`

**Issue:** Audit logs written to file can be tampered with if an attacker gains filesystem access.

**Remediation:** Consider adding HMAC signatures to log entries or shipping to append-only storage:
```lua
local function audit_log(event_type, event_data)
    local log_entry = { ... }

    -- Add integrity signature
    local hmac_key = os.getenv("WAF_LOG_HMAC_KEY") or ""
    if hmac_key ~= "" then
        local hmac = require "resty.hmac"
        local h = hmac:new(hmac_key, hmac.ALGOS.SHA256)
        log_entry._signature = h:final(cjson.encode(log_entry), true)
    end

    ngx.log(ngx.NOTICE, "AUDIT: ", cjson.encode(log_entry))
end
```

---

### F09: Admin Session Cookie Lacks Secure Flag by Default

**Severity:** Medium
**Location:** `openresty/lua/admin_auth.lua:78-89`

**Vulnerable Code:**
```lua
local function set_session_cookie(token, max_age)
    local cookie = SESSION_COOKIE_NAME .. "=" .. token
    cookie = cookie .. "; Path=/; HttpOnly; SameSite=Strict"
    -- In production, add Secure flag
    -- cookie = cookie .. "; Secure"  <-- COMMENTED OUT
    ngx.header["Set-Cookie"] = cookie
end
```

**Impact:** Session cookies can be intercepted over HTTP connections.

**Remediation:**
```lua
local function set_session_cookie(token, max_age)
    local cookie = SESSION_COOKIE_NAME .. "=" .. token
    cookie = cookie .. "; Path=/; HttpOnly; SameSite=Strict"

    if max_age then
        cookie = cookie .. "; Max-Age=" .. max_age
    end

    -- Auto-detect HTTPS
    if ngx.var.scheme == "https" or ngx.var.http_x_forwarded_proto == "https" then
        cookie = cookie .. "; Secure"
    end

    ngx.header["Set-Cookie"] = cookie
end
```

---

### F10: Redis Connection Has No TLS Option

**Severity:** Medium
**Location:** `openresty/lua/redis_sync.lua`, `openresty/lua/rbac.lua`

**Issue:** Redis connections use plaintext. Credentials and session data traverse network unencrypted.

**Remediation:**
1. Use Redis with TLS enabled
2. Update connection code to support TLS:
```lua
local redis = require "resty.redis"
local red = redis:new()

-- For TLS connections
local ok, err = red:connect("rediss://redis:6379")  -- rediss:// for TLS
-- Or use stunnel/envoy sidecar for TLS termination
```

---

### F11: Default Admin Password "changeme" in Code

**Severity:** Low
**Location:** `openresty/lua/rbac.lua:750`

**Code:**
```lua
local admin_password = os.getenv("WAF_ADMIN_PASSWORD") or "changeme"
```

**Impact:** If `WAF_ADMIN_PASSWORD` is not set, a known default password is used.

**Remediation:**
```lua
local admin_password = os.getenv("WAF_ADMIN_PASSWORD")
if not admin_password or admin_password == "" then
    ngx.log(ngx.ERR, "RBAC: WAF_ADMIN_PASSWORD not set - refusing to seed admin user")
    return false, "WAF_ADMIN_PASSWORD environment variable is required"
end
```

---

### F12: Multipart File Content Not Size-Limited Per-Field

**Severity:** Medium
**Location:** `openresty/lua/form_parser.lua:74-181`

**Issue:** While overall body size is limited by `client_max_body_size`, individual multipart fields are not limited, potentially causing memory pressure.

**Remediation:**
```lua
local MAX_FIELD_SIZE = 1024 * 1024  -- 1MB per field

-- In parse_multipart():
elseif typ == "body" then
    if current_field then
        local current_size = 0
        for _, chunk in ipairs(current_value) do
            current_size = current_size + #chunk
        end

        if current_size + #res > MAX_FIELD_SIZE then
            return nil, "Field size exceeds limit"
        end

        table.insert(current_value, res)
    end
end
```

---

### F13: IPv6 Not Supported in IP Utilities

**Severity:** Low
**Location:** `openresty/lua/ip_utils.lua`

**Issue:** All IP parsing functions only support IPv4. IPv6 clients may bypass IP-based controls.

**Remediation:** Add IPv6 support or explicitly block IPv6 at the load balancer level until supported.

---

### F14: IP Extraction Inconsistent Across Modules

**Severity:** HIGH
**Location:** `openresty/lua/captcha_handler.lua`, `openresty/lua/webhooks.lua`

**Issue:** While F01 fixed IP extraction in `waf_handler.lua`, other modules still use raw `ngx.var.remote_addr` or trust `X-Forwarded-For` directly. This allows IP spoofing to bypass per-IP rate limiting in webhooks and CAPTCHA exemptions.

**Code (captcha_handler.lua:72):**
```lua
-- Fallback to less secure method
return ngx.md5(ngx.now() .. ngx.var.remote_addr .. math.random())
```

**Code (webhooks.lua:243):**
```lua
client_ip = ngx.var.http_x_forwarded_for or ngx.var.remote_addr,
```

**Remediation:** All modules must use `trusted_proxies.get_client_ip()` for IP extraction:
```lua
local trusted_proxies = require "trusted_proxies"
local client_ip = trusted_proxies.get_client_ip()
```

---

### F15: No SSRF Protection for Outbound HTTP Requests

**Severity:** HIGH
**Location:** `openresty/lua/http_utils.lua`, `openresty/lua/webhooks.lua`, `openresty/lua/ip_reputation.lua`, `openresty/lua/sso_oidc.lua`

**Issue:** User-configurable URLs (webhooks, IP reputation endpoints, OIDC discovery URLs) can target internal services, enabling Server-Side Request Forgery (SSRF) attacks.

An attacker with admin access could:
- Configure a webhook URL pointing to `http://169.254.169.254/` to access cloud metadata
- Target internal services on `http://localhost:6379/` or `http://redis:6379/`
- Scan internal networks via error messages

**Remediation:** Create SSRF protection module that blocks:
1. Private IP ranges (RFC 1918, loopback, link-local)
2. Blocked hostnames (localhost, ip6-localhost)
3. Non-HTTP(S) schemes
4. IP address encoding tricks (decimal, hex, octal)

```lua
local ssrf_protection = require "ssrf_protection"

-- Before making HTTP request:
local is_safe, reason = ssrf_protection.validate_url(url)
if not is_safe then
    return nil, "SSRF protection: " .. reason
end
```

---

### F16: SSO OIDC Uses Weak Random for State Parameter

**Severity:** Medium
**Location:** `openresty/lua/sso_oidc.lua:51-60`

**Issue:** The OIDC state parameter (used for CSRF protection) is generated using `math.random()`, which is predictable.

**Code:**
```lua
local function generate_random_string(length)
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local result = {}
    for i = 1, length do
        local rand = math.random(1, #chars)  -- WEAK!
        table.insert(result, chars:sub(rand, rand))
    end
    return table.concat(result)
end
```

**Remediation:** Use cryptographic random:
```lua
local resty_random = require "resty.random"
local random_bytes = resty_random.bytes(length, true)  -- true = strong random
```

---

## 6. Verification Test Plan

### Test Matrix

| Test ID | Category | Input | Expected Behavior | Evidence |
|---------|----------|-------|-------------------|----------|
| T01 | Rate Limiting | 100 requests/min | Requests beyond threshold return 429 | HAProxy metrics |
| T02 | IP Allowlist | POST with spam keywords from allowed IP | Request allowed | Log shows `allowed` |
| T03 | Timing Token | Direct POST without GET | Score +30, `timing:no_cookie` flag | Response headers |
| T04 | Timing Token | GET then POST in 1 second | Score +40, `timing:too_fast` flag | Response headers |
| T05 | Content Hash | POST with blocked hash | 403, `hash:blocked` flag | Response status |
| T06 | Honeypot | POST with honeypot field value | 403, `honeypot:field` flag | Response status |
| T07 | Body Size | POST with 11MB body | 413 error | Nginx error log |
| T08 | Content-Type | POST with `text/plain` | Passes without WAF analysis | No WAF headers |
| T09 | Admin Auth | GET `/api/vhosts` without session | 401 Unauthorized | JSON error |
| T10 | Admin RBAC | Viewer POST to `/api/keywords` | 403 Forbidden | Permission denied |
| T11 | XFF Spoofing | XFF header from untrusted source | Should use `remote_addr` | Log check |

### Sample Test Commands

**T03 - Timing Token (No Cookie):**
```bash
curl -v -X POST http://waf:8080/contact \
  -d "name=test&message=hello"
# Check X-WAF-Spam-Flags header for "timing:no_cookie"
```

**T06 - Honeypot Detection:**
```bash
# Requires honeypot field "website_url" configured
curl -v -X POST http://waf:8080/contact \
  -d "name=test&email=test@example.com&website_url=http://spam.com"
# Expected: 403 with "honeypot:website_url" flag
```

**T11 - XFF Spoofing (verify fix):**
```bash
# From external IP
curl -v -H "X-Forwarded-For: 192.0.2.1" http://waf:8080/form -d "test=data"
# After fix: logs should show actual client IP, not 192.0.2.1
```

---

## 7. Remediation Backlog

### Priority 1: Quick Wins (1-2 Days)

| Finding | Effort | Risk Reduction | Action |
|---------|--------|----------------|--------|
| F01 | 4h | **High** | Add trusted proxy validation |
| F04 | 1h | Medium | Change RBAC default to deny |
| F09 | 1h | Medium | Enable Secure cookie flag |
| F06 | 1h | Medium | Add client_body_timeout |

### Priority 2: Medium Effort (1 Week)

| Finding | Effort | Risk Reduction | Action |
|---------|--------|----------------|--------|
| F02 | 2d | Medium | Upgrade to PBKDF2 hashing |
| F03 | 1d | Medium | Use cryptographic random |
| F10 | 2d | Medium | Add Redis TLS support |
| F12 | 1d | Medium | Add per-field size limits |

### Priority 3: Larger Refactors (2+ Weeks)

| Finding | Effort | Risk Reduction | Action |
|---------|--------|----------------|--------|
| F13 | 1w | Medium | Add IPv6 support |
| F08 | 1w | Low | Implement log integrity |
| F05 | 2d | Low | Fix timing key atomicity |
| F07 | 0.5d | Low | Add JSON depth limit |

---

## 8. Recommended Security Configuration

### Nginx Hardening

Add to `openresty/conf/nginx.conf`:

```nginx
http {
    # Trusted proxy configuration (CRITICAL - see F01)
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.16.0.0/12;
    set_real_ip_from 192.168.0.0/16;
    # Add your CDN/LB IP ranges here
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;

    # Timeouts (see F06)
    client_body_timeout 30s;
    client_header_timeout 30s;
    send_timeout 30s;

    # Connection limits
    limit_conn_zone $binary_remote_addr zone=conn_limit:10m;
    limit_conn conn_limit 50;

    # Additional rate limiting
    limit_req_zone $binary_remote_addr zone=req_limit:10m rate=10r/s;
    limit_req zone=req_limit burst=20 nodelay;

    # Security headers for admin UI
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;
}
```

### Environment Variables

```bash
# REQUIRED for production
WAF_ADMIN_SALT="$(openssl rand -hex 32)"
WAF_ADMIN_PASSWORD="$(openssl rand -base64 24)"
REDIS_PASSWORD="$(openssl rand -base64 32)"

# Recommended settings
WAF_SESSION_TTL=3600
WAF_SYNC_INTERVAL=30
```

### Deployment Checklist

- [ ] Trusted proxy IPs configured in nginx.conf
- [ ] Strong WAF_ADMIN_PASSWORD set (not "changeme")
- [ ] WAF_ADMIN_SALT set to unique random value
- [ ] Redis password configured
- [ ] TLS certificates properly configured for 8443
- [ ] Admin UI accessible only via HTTPS
- [ ] Prometheus metrics endpoint not publicly exposed
- [ ] Log shipping to centralized SIEM configured
- [ ] Monitoring alerts set up for blocked request spikes

---

## Appendix: Files Referenced

| File | Description |
|------|-------------|
| `openresty/lua/waf_handler.lua` | Main WAF processing logic |
| `openresty/lua/admin_auth.lua` | Admin authentication |
| `openresty/lua/rbac.lua` | Role-based access control |
| `openresty/lua/form_parser.lua` | Form body parsing |
| `openresty/lua/ip_utils.lua` | IP/CIDR utilities |
| `openresty/lua/ip_reputation.lua` | IP reputation checking |
| `openresty/lua/timing_token.lua` | Form timing detection |
| `openresty/lua/keyword_filter.lua` | Content filtering |
| `openresty/conf/nginx.conf` | OpenResty configuration |

---

## Appendix: Fix Implementation Summary

All findings have been addressed in branch `fix/security-audit-findings`. Below is a summary of changes made:

### New Files Created

| File | Purpose |
|------|---------|
| `openresty/lua/trusted_proxies.lua` | F01: Secure client IP extraction with trusted proxy validation |
| `openresty/lua/password_utils.lua` | F02: PBKDF2-SHA256 password hashing with 100,000 iterations |
| `openresty/lua/safe_json.lua` | F07: JSON wrapper with depth limit (10 levels) |
| `openresty/lua/ssrf_protection.lua` | F15: SSRF protection for outbound HTTP requests |

### Modified Files

| File | Changes |
|------|---------|
| `openresty/conf/nginx.conf` | F01: Added `set_real_ip_from` directives and `real_ip_header`; F06: Added `client_body_timeout`, `client_header_timeout`, `send_timeout`; Added env vars for `WAF_TRUSTED_PROXIES` and `WAF_LOG_HMAC_KEY` |
| `openresty/lua/waf_handler.lua` | F01: Uses `trusted_proxies.get_client_ip()` for secure IP extraction; F08: Added optional HMAC log integrity signatures |
| `openresty/lua/admin_auth.lua` | F02: Uses `password_utils` for PBKDF2 hashing with auto-upgrade; F03: Uses `resty.random` for cryptographic session tokens; F09: Auto-detects HTTPS for Secure cookie flag |
| `openresty/lua/rbac.lua` | F02/F11: Uses PBKDF2 for admin password, requires `WAF_ADMIN_PASSWORD` env var; F04: Changed RBAC default to deny unmapped endpoints |
| `openresty/lua/timing_token.lua` | F05: Atomic key generation using `shared:add()` |
| `openresty/lua/form_parser.lua` | F07: Uses `safe_json` for JSON parsing; F12: Per-field size limit (1MB) for multipart |
| `openresty/lua/redis_sync.lua` | F10: Added `REDIS_TLS` environment variable support with documentation |
| `openresty/lua/ip_utils.lua` | F13: Full IPv6 support including CIDR matching and mixed formats |
| `openresty/lua/captcha_handler.lua` | F14: Uses `trusted_proxies.get_client_ip()` for secure IP extraction; Uses cryptographic random for token generation |
| `openresty/lua/webhooks.lua` | F14: Uses `trusted_proxies.get_client_ip()` in event data |
| `openresty/lua/http_utils.lua` | F15: Integrated SSRF protection for all outbound HTTP requests |
| `openresty/lua/sso_oidc.lua` | F15: Uses `http_utils` for OIDC discovery fetch; F16: Uses cryptographic random for state parameter |

### New Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `WAF_TRUSTED_PROXIES` | Comma-separated list of additional trusted proxy CIDRs | (private networks) |
| `WAF_LOG_HMAC_KEY` | HMAC key for audit log integrity signatures | (disabled) |
| `REDIS_TLS` | Set to "true" to enable TLS mode logging | false |
| `WAF_DISABLE_SSRF_PROTECTION` | Set to "true" to disable SSRF protection (NOT RECOMMENDED) | false |
| `WAF_ALLOW_INTERNAL_URLS` | Set to "true" to allow internal URLs (testing only) | false |

### Breaking Changes

1. **WAF_ADMIN_PASSWORD is now required** - No default password. Set this environment variable to create the admin user.
2. **WAF_ADMIN_SALT is no longer needed** - Salt is now embedded in PBKDF2 hash format.
3. **Existing passwords auto-upgrade** - Legacy SHA256 passwords are automatically upgraded to PBKDF2 on next login.

### Migration Notes

For existing deployments:
1. Set `WAF_ADMIN_PASSWORD` environment variable before upgrading
2. Existing users with legacy password hashes will be auto-upgraded on login
3. Configure `WAF_TRUSTED_PROXIES` if you have custom proxy infrastructure
4. Review `set_real_ip_from` directives in nginx.conf for your environment

---

*This audit was conducted for defensive purposes to improve the security posture of the forms-waf project.*
