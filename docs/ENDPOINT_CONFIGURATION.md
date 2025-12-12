# Dynamic Endpoint Configuration - Feasibility Analysis

## Executive Summary

This document evaluates the feasibility of implementing dynamic endpoint configuration for the Forms WAF system. The proposed enhancement would allow:

1. **Selective endpoint filtering** - Configure which endpoints and HTTP methods to protect
2. **Per-endpoint configuration** - Override global thresholds on a per-endpoint basis
3. **Runtime configuration** - Modify rules without restarts via Admin API

**Verdict: Highly Feasible** - The current architecture supports this enhancement with moderate complexity. The two-layer design (OpenResty + HAProxy) and Redis-backed configuration make dynamic endpoint rules a natural extension.

---

## Current State Analysis

### Architecture Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Client    │────▶│  OpenResty  │────▶│   HAProxy   │────▶│   Backend   │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
                           │                   │
                           └───────┬───────────┘
                                   ▼
                           ┌─────────────┐
                           │    Redis    │
                           └─────────────┘
```

### Current Limitations

| Aspect | Current State | Limitation |
|--------|--------------|------------|
| **Endpoint Selection** | All POST/PUT/PATCH requests | Cannot exclude health checks, webhooks, or internal APIs |
| **Thresholds** | Global only | A payment form and comment form have same limits |
| **Keywords** | Global lists | Cannot have stricter rules for public forms |
| **Rate Limits** | Per-IP global | Cannot allow higher rates for authenticated endpoints |
| **Content Types** | Fixed (form, json, multipart) | Cannot configure per endpoint |

### Key Files Affected

| File | Current Role | Required Changes |
|------|-------------|------------------|
| `waf_handler.lua` | Main processing | Endpoint matching, config lookup |
| `waf_config.lua` | Global config | Per-endpoint config resolution |
| `redis_sync.lua` | Syncs keywords/thresholds | Sync endpoint rules |
| `admin_api.lua` | CRUD for global settings | Endpoint management APIs |
| `haproxy.cfg` | Rate limiting | Endpoint-aware ACLs (optional) |

---

## Proposed Solution

### Design Principles

1. **Inheritance Model**: Endpoint configs inherit from global defaults, only overriding specified values
2. **Explicit Opt-In/Out**: Endpoints not matching any rule can be configured to pass-through or apply global rules
3. **Pattern Matching**: Support exact paths, prefix matching, and regex patterns
4. **Method Filtering**: Configure rules per HTTP method (POST, PUT, PATCH, DELETE)
5. **Zero Downtime Updates**: All configuration changes apply without restarts

### Configuration Hierarchy

```
Global Defaults
    └── Endpoint Group (e.g., "public-forms")
            └── Specific Endpoint (e.g., "/api/contact")
                    └── Method Override (e.g., "POST")
```

---

## Technical Architecture

### Endpoint Matching Flow

```
┌────────────────────────────────────────────────────────────────┐
│                    Incoming Request                            │
│              POST /api/contact?ref=123                         │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  1. Extract Request Metadata                                   │
│     • Path: /api/contact                                       │
│     • Method: POST                                             │
│     • Content-Type: application/json                           │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  2. Endpoint Rule Matching (Priority Order)                    │
│     a) Exact match: /api/contact + POST                        │
│     b) Exact path, any method: /api/contact + *                │
│     c) Prefix match: /api/* + POST                             │
│     d) Regex match: ^/api/v[0-9]+/contact$ + POST              │
│     e) Default behavior (global rules or bypass)               │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  3. Resolve Effective Configuration                            │
│     • Merge endpoint config with global defaults               │
│     • Apply group settings if endpoint belongs to group        │
│     • Cache resolved config for performance                    │
└────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌────────────────────────────────────────────────────────────────┐
│  4. Execute WAF Processing with Endpoint Config                │
│     • Skip if endpoint.enabled = false                         │
│     • Apply endpoint-specific thresholds                       │
│     • Use endpoint-specific keyword lists (if defined)         │
│     • Pass endpoint ID to HAProxy for tracking                 │
└────────────────────────────────────────────────────────────────┘
```

### Endpoint Configuration Schema

```json
{
  "id": "contact-form",
  "name": "Contact Form Endpoint",
  "description": "Public contact form - strict filtering",

  "matching": {
    "paths": ["/api/contact", "/api/v1/contact"],
    "path_prefix": null,
    "path_regex": null,
    "methods": ["POST"],
    "content_types": ["application/json", "application/x-www-form-urlencoded"]
  },

  "enabled": true,
  "mode": "blocking",

  "thresholds": {
    "spam_score_block": 60,
    "spam_score_flag": 40,
    "hash_count_block": 5,
    "ip_rate_limit": 10
  },

  "keywords": {
    "inherit_global": true,
    "additional_blocked": ["competitor-name"],
    "additional_flagged": ["urgent:20", "limited-time:15"],
    "excluded_blocked": [],
    "excluded_flagged": []
  },

  "patterns": {
    "inherit_global": true,
    "disabled_patterns": ["phone"],
    "custom_patterns": [
      {"pattern": "coupon[_-]?code", "score": 5, "flag": "promo_hunting"}
    ]
  },

  "rate_limiting": {
    "enabled": true,
    "requests_per_minute": 10,
    "requests_per_hour": 100,
    "burst_limit": 3
  },

  "fields": {
    "required": ["email", "message"],
    "max_length": {"message": 5000},
    "ignore_fields": ["_csrf", "honeypot"]
  },

  "actions": {
    "on_block": "reject",
    "on_flag": "tag",
    "log_level": "info",
    "notify_webhook": null
  },

  "metadata": {
    "group": "public-forms",
    "tags": ["contact", "high-risk"],
    "created_at": "2024-01-15T10:00:00Z",
    "updated_at": "2024-01-15T10:00:00Z"
  }
}
```

### Processing Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| `blocking` | Actively block spam (default) | Public forms |
| `monitoring` | Log but don't block | Testing new endpoints |
| `passthrough` | Skip all WAF checks | Internal APIs, webhooks |
| `strict` | Lower thresholds, no leniency | Payment forms |

---

## Redis Data Schema

### Key Structure

```
waf:endpoints:index                    # Sorted set of endpoint IDs by priority
waf:endpoints:config:{id}              # Hash with endpoint configuration
waf:endpoints:paths:exact              # Hash mapping exact paths to endpoint IDs
waf:endpoints:paths:prefix             # Sorted set of prefix patterns
waf:endpoints:paths:regex              # List of regex patterns with endpoint IDs
waf:endpoints:groups:{group}           # Set of endpoint IDs in group
waf:endpoints:keywords:blocked:{id}    # Per-endpoint blocked keywords
waf:endpoints:keywords:flagged:{id}    # Per-endpoint flagged keywords
waf:endpoints:cache:resolved:{path}    # Cached resolved config (TTL: 60s)
```

### Example Redis Data

```redis
# Endpoint index (priority order - lower = higher priority)
ZADD waf:endpoints:index 10 "contact-form" 20 "newsletter" 100 "api-catchall"

# Exact path mapping
HSET waf:endpoints:paths:exact "/api/contact" "contact-form"
HSET waf:endpoints:paths:exact "/api/v1/contact" "contact-form"
HSET waf:endpoints:paths:exact "/api/newsletter/subscribe" "newsletter"

# Prefix patterns (with priority)
ZADD waf:endpoints:paths:prefix 50 "/api/public/*:public-api"
ZADD waf:endpoints:paths:prefix 100 "/api/*:api-catchall"

# Endpoint configuration
HSET waf:endpoints:config:contact-form \
  name "Contact Form" \
  enabled "true" \
  mode "blocking" \
  paths '"/api/contact","/api/v1/contact"' \
  methods '"POST"' \
  spam_score_block "60" \
  spam_score_flag "40" \
  ip_rate_limit "10" \
  group "public-forms"

# Per-endpoint keywords (additions)
SADD waf:endpoints:keywords:blocked:contact-form "competitor-name"
SADD waf:endpoints:keywords:flagged:contact-form "urgent:20" "act-now:15"
```

---

## Implementation Details

### Phase 1: Core Endpoint Matching (OpenResty)

**New module: `endpoint_matcher.lua`**

```lua
-- Pseudocode for endpoint matching
local _M = {}

-- Cached endpoint rules (synced from Redis)
local endpoint_cache = ngx.shared.endpoint_cache

function _M.match(path, method)
    -- 1. Check exact match first (fastest)
    local exact_key = path .. ":" .. method
    local endpoint_id = endpoint_cache:get("exact:" .. exact_key)
    if endpoint_id then
        return endpoint_id, "exact"
    end

    -- 2. Check exact path, any method
    endpoint_id = endpoint_cache:get("exact:" .. path .. ":*")
    if endpoint_id then
        return endpoint_id, "exact_any"
    end

    -- 3. Check prefix matches (sorted by specificity)
    local prefixes = endpoint_cache:get("prefixes_json")
    if prefixes then
        for _, prefix_entry in ipairs(cjson.decode(prefixes)) do
            if path:sub(1, #prefix_entry.prefix) == prefix_entry.prefix then
                if prefix_entry.method == "*" or prefix_entry.method == method then
                    return prefix_entry.endpoint_id, "prefix"
                end
            end
        end
    end

    -- 4. Check regex patterns (most expensive, checked last)
    local regexes = endpoint_cache:get("regexes_json")
    if regexes then
        for _, regex_entry in ipairs(cjson.decode(regexes)) do
            if ngx.re.match(path, regex_entry.pattern) then
                if regex_entry.method == "*" or regex_entry.method == method then
                    return regex_entry.endpoint_id, "regex"
                end
            end
        end
    end

    -- 5. Return default
    return nil, "none"
end

function _M.get_config(endpoint_id)
    if not endpoint_id then
        return nil  -- Use global config
    end

    local cached = endpoint_cache:get("config:" .. endpoint_id)
    if cached then
        return cjson.decode(cached)
    end

    return nil
end

return _M
```

### Phase 2: Configuration Resolution

**New module: `config_resolver.lua`**

```lua
-- Resolves effective configuration by merging endpoint config with globals
local _M = {}

local waf_config = require "waf_config"

function _M.resolve(endpoint_config)
    local global = waf_config.get_thresholds()

    if not endpoint_config then
        return {
            enabled = true,
            mode = "blocking",
            thresholds = global,
            keywords = {inherit_global = true},
            patterns = {inherit_global = true}
        }
    end

    -- Merge thresholds (endpoint overrides global)
    local thresholds = {}
    for k, v in pairs(global) do
        thresholds[k] = endpoint_config.thresholds and endpoint_config.thresholds[k] or v
    end

    return {
        enabled = endpoint_config.enabled ~= false,
        mode = endpoint_config.mode or "blocking",
        thresholds = thresholds,
        keywords = endpoint_config.keywords or {inherit_global = true},
        patterns = endpoint_config.patterns or {inherit_global = true},
        rate_limiting = endpoint_config.rate_limiting,
        fields = endpoint_config.fields,
        actions = endpoint_config.actions
    }
end

return _M
```

### Phase 3: Modified WAF Handler

**Changes to `waf_handler.lua`**

```lua
local endpoint_matcher = require "endpoint_matcher"
local config_resolver = require "config_resolver"

function _M.process_request()
    local method = ngx.req.get_method()
    local path = ngx.var.uri

    -- Match endpoint
    local endpoint_id, match_type = endpoint_matcher.match(path, method)
    local endpoint_config = endpoint_matcher.get_config(endpoint_id)
    local effective_config = config_resolver.resolve(endpoint_config)

    -- Check if WAF is enabled for this endpoint
    if not effective_config.enabled then
        ngx.header["X-WAF-Endpoint"] = endpoint_id or "none"
        ngx.header["X-WAF-Mode"] = "passthrough"
        return  -- Skip WAF processing
    end

    -- Check mode
    if effective_config.mode == "passthrough" then
        return
    end

    -- ... rest of processing uses effective_config.thresholds ...

    -- Pass endpoint info to HAProxy for endpoint-specific tracking
    ngx.header["X-WAF-Endpoint"] = endpoint_id or "global"
    ngx.header["X-WAF-Mode"] = effective_config.mode
end
```

### Phase 4: Admin API Extensions

**New endpoints for `admin_api.lua`**

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/waf-admin/endpoints` | List all endpoint configurations |
| `GET` | `/waf-admin/endpoints/{id}` | Get specific endpoint config |
| `POST` | `/waf-admin/endpoints` | Create new endpoint config |
| `PUT` | `/waf-admin/endpoints/{id}` | Update endpoint config |
| `DELETE` | `/waf-admin/endpoints/{id}` | Delete endpoint config |
| `POST` | `/waf-admin/endpoints/{id}/enable` | Enable endpoint protection |
| `POST` | `/waf-admin/endpoints/{id}/disable` | Disable endpoint protection |
| `GET` | `/waf-admin/endpoints/match?path=X&method=Y` | Test endpoint matching |
| `GET` | `/waf-admin/endpoints/groups` | List endpoint groups |
| `GET` | `/waf-admin/endpoints/groups/{group}` | Get group members |

### Phase 5: HAProxy Enhancements (Optional)

For endpoint-specific rate limiting at HAProxy level:

```haproxy
# Separate stick-tables per high-traffic endpoint
backend st_form_hashes_contact
    stick-table type string len 64 size 10k expire 30m peers haproxy_peers \
                store gpc0,gpc0_rate(60s)

backend st_form_hashes_newsletter
    stick-table type string len 64 size 10k expire 30m peers haproxy_peers \
                store gpc0,gpc0_rate(60s)

frontend ft_waf
    # Route to endpoint-specific tables based on header
    acl endpoint_contact req.hdr(X-WAF-Endpoint) -m str contact-form
    acl endpoint_newsletter req.hdr(X-WAF-Endpoint) -m str newsletter

    http-request track-sc0 req.hdr(X-Form-Hash) table st_form_hashes_contact \
                 if endpoint_contact has_form_hash
    http-request track-sc0 req.hdr(X-Form-Hash) table st_form_hashes_newsletter \
                 if endpoint_newsletter has_form_hash
```

---

## Security Considerations

### 1. Configuration Validation

**Risk**: Malformed endpoint rules could bypass WAF protection

**Mitigations**:
- Strict JSON schema validation on all endpoint configurations
- Validate regex patterns for ReDoS vulnerabilities (reject catastrophic backtracking)
- Enforce minimum threshold values (e.g., `spam_score_block` cannot be > 1000)
- Audit logging for all configuration changes

```lua
-- Example validation
local function validate_endpoint_config(config)
    local errors = {}

    -- Required fields
    if not config.matching or not config.matching.paths then
        table.insert(errors, "matching.paths is required")
    end

    -- Threshold bounds
    if config.thresholds then
        if config.thresholds.spam_score_block and
           (config.thresholds.spam_score_block < 10 or
            config.thresholds.spam_score_block > 500) then
            table.insert(errors, "spam_score_block must be between 10 and 500")
        end
    end

    -- Regex safety (simple check - production would use more robust validation)
    if config.matching.path_regex then
        local ok, err = pcall(ngx.re.match, "", config.matching.path_regex)
        if not ok then
            table.insert(errors, "Invalid regex pattern: " .. err)
        end
    end

    return #errors == 0, errors
end
```

### 2. Path Traversal Prevention

**Risk**: Attackers could craft paths to match unintended endpoints

**Mitigations**:
- Normalize paths before matching (remove `/../`, `//`, trailing slashes)
- Match against `ngx.var.uri` which is already normalized by nginx
- Reject path patterns containing `..`

### 3. Priority Conflicts

**Risk**: Overlapping patterns could cause unexpected behavior

**Mitigations**:
- Explicit priority ordering in endpoint index
- Warn on overlapping patterns during configuration
- Provide "test match" API endpoint for verification

### 4. Denial of Service via Configuration

**Risk**: Too many regex patterns or complex rules could slow down matching

**Mitigations**:
- Limit number of endpoints (configurable, default: 1000)
- Limit regex patterns per endpoint (default: 10)
- Limit regex complexity (max length: 256 chars)
- Cache resolved configurations aggressively

### 5. Admin API Security

**Risk**: Unauthorized access to endpoint configuration

**Mitigations**:
- Admin API should only be accessible from internal network
- Consider adding authentication (API key, mTLS)
- Rate limit admin API endpoints
- Implement role-based access (read-only vs write)

### 6. Configuration Drift

**Risk**: Inconsistent configuration across OpenResty replicas

**Mitigations**:
- Redis sync ensures all replicas get same configuration
- Configuration versioning (add `version` field, reject stale updates)
- Health check should verify configuration sync status

---

## Performance Impact

### Benchmarks (Estimated)

| Operation | Current | With Endpoint Config | Impact |
|-----------|---------|---------------------|--------|
| Exact path match | - | ~0.05ms | +0.05ms |
| Prefix match (10 prefixes) | - | ~0.1ms | +0.1ms |
| Regex match (5 patterns) | - | ~0.5ms | +0.5ms |
| Config resolution | ~0.01ms | ~0.1ms | +0.09ms |
| **Total overhead** | - | - | **+0.15ms to +0.7ms** |

### Optimization Strategies

1. **Aggressive Caching**: Cache resolved endpoint configs (TTL: 60s)
2. **Exact Match First**: 80%+ of requests should hit exact match (O(1) lookup)
3. **Prefix Trie**: For large numbers of prefixes, use trie structure
4. **Compiled Regex**: Pre-compile regex patterns on sync
5. **LRU Cache**: Keep hot endpoint configs in Lua memory

### Memory Impact

| Component | Additional Memory |
|-----------|------------------|
| Endpoint rules (100 endpoints) | ~50KB |
| Path index (1000 paths) | ~100KB |
| Resolved config cache (500 entries) | ~250KB |
| **Total** | **~400KB** |

---

## Migration Path

### Phase 1: Foundation (Week 1)
- Implement endpoint matching module
- Add Redis schema for endpoints
- Create basic Admin API endpoints

### Phase 2: Integration (Week 2)
- Integrate endpoint matching into waf_handler
- Implement configuration resolution
- Add sync logic to redis_sync

### Phase 3: Testing (Week 3)
- Comprehensive unit tests
- Integration tests with various patterns
- Performance benchmarking
- Security testing (fuzzing patterns)

### Phase 4: Rollout (Week 4)
- Deploy with default "global" behavior
- Gradually add endpoint configurations
- Monitor performance metrics

### Backward Compatibility

The implementation maintains full backward compatibility:

1. **No endpoint rules defined**: System behaves exactly as current (all POST/PUT/PATCH filtered)
2. **Existing Redis keys**: Unchanged - global keywords/thresholds still work
3. **Existing Admin API**: All current endpoints continue to function
4. **Configuration migration**: Not required - new features are opt-in

---

## Recommendations

### Immediate (High Value, Low Effort)

1. **Implement passthrough list**: Simple list of paths to skip WAF entirely
   - Covers 80% of use case (health checks, webhooks, internal APIs)
   - Minimal complexity: just a Redis SET checked before processing

2. **Method filtering**: Add configurable methods list to global config
   - Example: Only filter POST (not PUT/PATCH) by default

### Short-Term (Medium Effort)

3. **Full endpoint configuration**: Complete implementation as described
   - Start with exact path matching only (defer regex)
   - Add prefix matching in subsequent iteration

### Long-Term (Higher Effort)

4. **HAProxy integration**: Endpoint-specific rate limiting at HAProxy level
5. **Endpoint groups**: Group-based configuration inheritance
6. **API versioning**: Support for `/v1/contact` and `/v2/contact` with same rules

---

## Conclusion

Dynamic endpoint configuration is **highly feasible** and represents a natural evolution of the Forms WAF system. The current architecture (Redis-backed configuration, Lua processing, shared dictionaries) provides all the building blocks needed.

**Recommended approach**: Start with the "passthrough list" implementation as a quick win, then expand to full endpoint configuration based on actual usage patterns and requirements.

### Effort Estimate

| Component | Complexity | Effort |
|-----------|------------|--------|
| Passthrough list (quick win) | Low | 1-2 days |
| Endpoint matching module | Medium | 3-4 days |
| Config resolution | Low | 1-2 days |
| Admin API extensions | Medium | 2-3 days |
| Redis sync updates | Low | 1 day |
| HAProxy integration | Medium | 2-3 days |
| Testing & documentation | Medium | 3-4 days |
| **Total** | | **13-19 days** |

---

## Appendix: Quick Win - Passthrough List

For immediate value, implement a simple passthrough list:

```redis
# Redis key
SADD waf:passthrough:paths "/health" "/ready" "/metrics" "/api/webhooks/*"
```

```lua
-- In waf_handler.lua, add at the start of process_request()
local function is_passthrough(path)
    local passthrough = ngx.shared.config_cache:get("passthrough_paths")
    if not passthrough then return false end

    for pattern in passthrough:gmatch("[^|]+") do
        if pattern:match("%*$") then
            -- Prefix match
            local prefix = pattern:sub(1, -2)
            if path:sub(1, #prefix) == prefix then
                return true
            end
        else
            -- Exact match
            if path == pattern then
                return true
            end
        end
    end
    return false
end

-- At start of process_request()
if is_passthrough(ngx.var.uri) then
    ngx.header["X-WAF-Passthrough"] = "true"
    return
end
```

This provides immediate value with minimal implementation effort.
