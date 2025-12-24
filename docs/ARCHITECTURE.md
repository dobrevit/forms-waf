# Forms WAF - Spam Protection Architecture

## Overview

This system provides a multi-layer spam protection mechanism for web forms using:
1. **OpenResty** - Form parsing, defense profile execution, content hashing, keyword filtering, vhost/endpoint resolution
2. **HAProxy** - Global rate limiting with stick-tables and peer synchronization
3. **Redis** - Dynamic configuration for keywords, blocklists, vhosts, endpoints, defense profiles, and attack signatures
4. **Admin UI** - React-based dashboard for configuration management

### Key Features

- **Defense Profiles**: DAG-based execution engine for flexible threat detection flows
- **Attack Signatures**: Reusable pattern libraries for known attack vectors
- **Defense Lines**: Combine profiles with signatures for specialized protection
- **Multi-Profile Support**: Run multiple profiles in parallel with aggregation
- **Fingerprint Tracking**: Client fingerprinting with HAProxy stick-table coordination

## Architecture Diagram

```
                                    ┌─────────────────────────────────────────────────────────┐
                                    │                    Kubernetes Cluster                    │
                                    │                                                         │
┌──────────┐    ┌──────────────────┐│  ┌─────────────────────────────────────────────────┐   │
│          │    │                  ││  │              OpenResty (DaemonSet/Deployment)    │   │
│  Client  │───▶│  Ingress/LB      │├─▶│  ┌─────────────────────────────────────────┐    │   │
│          │    │  (NodePort/LB)   ││  │  │  Lua Modules:                           │    │   │
└──────────┘    └──────────────────┘│  │  │  - form_parser.lua (parse multipart/    │    │   │
                                    │  │  │    urlencoded forms)                    │    │   │
                                    │  │  │  - content_hasher.lua (SHA256 hashing)  │    │   │
                                    │  │  │  - keyword_filter.lua (Redis-backed     │    │   │
                                    │  │  │    keyword scanning)                    │    │   │
                                    │  │  │  - rate_limiter.lua (pre-check)         │    │   │
                                    │  │  └─────────────────────────────────────────┘    │   │
                                    │  │                        │                         │   │
                                    │  │                        │ X-Form-Hash header      │   │
                                    │  │                        │ X-Spam-Score header     │   │
                                    │  │                        │ X-Client-IP header      │   │
                                    │  │                        ▼                         │   │
                                    │  └─────────────────────────────────────────────────┘   │
                                    │                           │                             │
                                    │                           ▼                             │
                                    │  ┌─────────────────────────────────────────────────┐   │
                                    │  │           HAProxy (StatefulSet with Peering)     │   │
                                    │  │                                                  │   │
                                    │  │  ┌────────────────────────────────────────────┐ │   │
                                    │  │  │  Stick Tables (synchronized across peers): │ │   │
                                    │  │  │  - form_hashes: track form content hashes  │ │   │
                                    │  │  │  - client_ips: track per-IP submissions    │ │   │
                                    │  │  │  - spam_scores: aggregate spam indicators  │ │   │
                                    │  │  └────────────────────────────────────────────┘ │   │
                                    │  │                                                  │   │
                                    │  │  haproxy-0 ◀──────▶ haproxy-1 ◀──────▶ haproxy-2│   │
                                    │  │     (peer sync via stick-table replication)     │   │
                                    │  └─────────────────────────────────────────────────┘   │
                                    │                           │                             │
                                    │                           ▼                             │
                                    │  ┌─────────────────────────────────────────────────┐   │
                                    │  │              Backend Application                 │   │
                                    │  └─────────────────────────────────────────────────┘   │
                                    │                                                         │
                                    │  ┌─────────────────────────────────────────────────┐   │
                                    │  │              Redis (Configuration Store)         │   │
                                    │  │                                                  │   │
                                    │  │  Keys:                                          │   │
                                    │  │  - waf:keywords:blocked (SET)                   │   │
                                    │  │  - waf:keywords:flagged (SET)                   │   │
                                    │  │  - waf:hashes:blocked (SET)                     │   │
                                    │  │  - waf:config:thresholds (HASH)                 │   │
                                    │  │  - waf:whitelist:ips (SET)                      │   │
                                    │  └─────────────────────────────────────────────────┘   │
                                    │                                                         │
                                    └─────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Request Context Resolution

```
Incoming Request
        │
        ▼
┌───────────────────────┐
│ Virtual Host Matching │ ◀── Match Host header against vhost configs
│  (vhost_matcher.lua)  │     Priority: Exact → Wildcard → Default
└───────────────────────┘
        │
        ▼
┌───────────────────────┐
│  Endpoint Matching    │ ◀── Match path/method against endpoint configs
│ (endpoint_matcher.lua)│     Priority: Vhost-specific → Global → Default
└───────────────────────┘
        │
        ▼
┌───────────────────────┐
│  Context Resolution   │ ◀── Merge vhost + endpoint + global configs
│ (vhost_resolver.lua)  │     Determine effective thresholds, mode, routing
└───────────────────────┘
        │
        ▼
   WAF Processing (if mode != passthrough)
```

### 2. WAF Processing in OpenResty

```
Request with Context
        │
        ▼
┌───────────────────┐
│ Parse Form Data   │ ◀── Handles multipart/form-data and application/x-www-form-urlencoded
│ (form_parser.lua) │
└───────────────────┘
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│           Defense Profile Execution Layer                    │
│      (defense_profile_multi_executor.lua)                   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Multi-Profile Executor (parallel)                   │   │
│  │                                                     │   │
│  │  Profile 1 ──┐                                      │   │
│  │  Profile 2 ──┼── Aggregation (OR/AND/MAJORITY) ───▶│   │
│  │  Profile 3 ──┘                                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Defense Lines (optional)                             │   │
│  │ Profile + Attack Signatures merged                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Defense Mechanisms Executed:                               │
│  - IP Allowlist, GeoIP, IP Reputation                      │
│  - Timing Token, Behavioral, Honeypot                      │
│  - Keyword Filter, Content Hash, Expected Fields           │
│  - Pattern Scan, Disposable Email, Field Anomalies         │
│  - Fingerprint, Header Consistency, Rate Limiter           │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
┌───────────────────┐
│ Add WAF Headers   │
│ X-WAF-Form-Hash   │
│ X-WAF-Spam-Score  │
│ X-WAF-Client-IP   │
│ X-WAF-Spam-Flags  │
│ X-WAF-Fingerprint │
│ X-WAF-Vhost       │
│ X-WAF-Endpoint    │
└───────────────────┘
        │
        ▼
   Forward to HAProxy
```

### 3. HAProxy Stick-Table Processing

```
┌─────────────────────────────────────────────────────────────┐
│                    HAProxy Processing                        │
│                                                             │
│  1. Extract X-Form-Hash header                              │
│  2. Check stick-table for hash                              │
│     - If seen > N times globally → BLOCK                    │
│                                                             │
│  3. Extract X-Spam-Score header                             │
│     - If score > threshold → BLOCK                          │
│                                                             │
│  4. Track client IP in stick-table                          │
│     - If submissions > rate limit → BLOCK                   │
│                                                             │
│  5. Cross-reference: same hash from different IPs?          │
│     - If hash seen from > M unique IPs → BLOCK              │
│                                                             │
│  6. All checks pass → Forward to backend                    │
└─────────────────────────────────────────────────────────────┘
```

### Header Flow Between OpenResty and HAProxy

All headers use the standardized `X-WAF-` prefix for consistency.

```
OpenResty → HAProxy Request Headers:
─────────────────────────────────────────────────────────────────
X-WAF-Form-Hash              Content hash for duplicate detection (SHA256)
X-WAF-Spam-Score             Calculated spam score (integer 0-100+)
X-WAF-Spam-Flags             Comma-separated detection flags
X-WAF-Client-IP              Resolved client IP address
X-WAF-Submission-Fingerprint Client fingerprint (16 chars)
X-WAF-Fingerprint-Profile    Matched fingerprint profile ID
X-WAF-Mode                   blocking/monitoring/passthrough/strict
X-WAF-Debug                  on/off (expose debug headers)
X-WAF-Vhost                  Matched virtual host ID
X-WAF-Endpoint               Matched endpoint ID
X-Blocked                    true/false (already blocked by OpenResty)

Rate Limiting Headers:
X-WAF-Rate-Limit             on/off (enable HAProxy rate limiting)
X-WAF-Rate-Limit-Value       Dynamic IP rate limit (requests/min)

Dynamic Threshold Headers:
X-WAF-Spam-Threshold         Spam score block threshold (default: 80)
X-WAF-Hash-Rate-Threshold    Hash flood rate threshold (default: 10)
X-WAF-IP-Spam-Threshold      Cumulative IP spam score limit (default: 500)
X-WAF-Fingerprint-Threshold  Fingerprint rate limit (default: 20)

HAProxy → Backend Headers (debug mode only):
─────────────────────────────────────────────────────────────────
X-WAF-Hash-Count             Form hash submission count
X-WAF-Hash-Rate              Form hash rate per minute
X-WAF-IP-Rate                Client IP request rate
X-WAF-Fingerprint-Rate       Fingerprint rate per minute
X-WAF-Block-Rule-*           Which HAProxy rule blocked (if any)
```

## Stick-Table Design

### form_hashes table
- **Key**: SHA256 hash of form content
- **Tracked**:
  - `gpc0`: submission count
  - `gpc1`: unique source IPs (approximated)
  - `conn_rate(60s)`: submissions per minute

### client_ips table
- **Key**: Client IP address
- **Tracked**:
  - `http_req_rate(60s)`: requests per minute
  - `http_req_cnt`: total request count
  - `gpc0`: spam score accumulator
  - `gpc1`: blocked count

## Redis Data Structures

```redis
# Blocked keywords - immediate rejection
SADD waf:keywords:blocked "viagra" "casino" "crypto-investment"

# Flagged keywords - adds to spam score (keyword:score format)
SADD waf:keywords:flagged "free:10" "winner:15" "click here:20" "urgent:10"

# Blocked hashes - known spam content
SADD waf:hashes:blocked "abc123..." "def456..."

# Configuration thresholds
HSET waf:config:thresholds spam_score_block 80
HSET waf:config:thresholds spam_score_flag 50
HSET waf:config:thresholds hash_count_block 10
HSET waf:config:thresholds ip_rate_limit 30
HSET waf:config:thresholds ip_daily_limit 500
HSET waf:config:thresholds hash_unique_ips_block 5

# Global routing configuration
HSET waf:config:routing haproxy_upstream "haproxy:80"
HSET waf:config:routing haproxy_timeout 30

# Whitelisted IPs
SADD waf:whitelist:ips "10.0.0.0/8" "192.168.1.100"

# Virtual hosts
ZADD waf:vhosts:index 10 "example-com" 100 "_default"
SET waf:vhosts:config:example-com '{"id":"example-com","hostnames":["example.com","*.example.com"],...}'
HSET waf:vhosts:hosts:exact "example.com" "example-com"
ZADD waf:vhosts:hosts:wildcard 10 "*.example.com:example-com"

# Endpoints
ZADD waf:endpoints:index 10 "contact-form" 100 "api-catchall"
SET waf:endpoints:config:contact-form '{"id":"contact-form","matching":{"paths":["/contact"]},...}'
HSET waf:endpoints:paths:exact "/contact:POST" "contact-form"

# Defense Profiles
ZADD waf:defense_profiles:index 100 "balanced-web" 50 "strict-api"
SET waf:defense_profiles:config:balanced-web '{"id":"balanced-web","graph":{...},...}'
SET waf:defense_profiles:builtin_version "3"

# Attack Signatures
ZADD waf:attack_signatures:index 50 "builtin_wordpress_login" 70 "builtin_contact_form_spam"
SET waf:attack_signatures:config:builtin_wordpress_login '{"id":"builtin_wordpress_login","signatures":{...}}'
SET waf:attack_signatures:builtin_version "1"

# Signature Stats
SET waf:signature_stats:builtin_wordpress_login:total "1234"
SET waf:signature_stats:builtin_wordpress_login:last_match "1705312200"

# Fingerprint Profiles
ZADD waf:fingerprint_profiles:index 10 "default" 20 "strict"
SET waf:fingerprint_profiles:config:default '{"id":"default","patterns":[...]}'
```

## Configuration Hierarchy

```
Global Defaults (waf:config:*)
    │
    ├── Defense Profiles (waf:defense_profiles:*)
    │       └── Attack Signatures (waf:attack_signatures:*)
    │
    ├── Virtual Host Override (waf:vhosts:config:{id})
    │       │
    │       ├── Vhost Defense Profiles
    │       └── Vhost-Specific Endpoint (waf:vhosts:endpoints:{vhost_id}:*)
    │               └── Endpoint Defense Profiles + Defense Lines
    │
    └── Global Endpoint (waf:endpoints:*)
            └── Endpoint Defense Profiles + Defense Lines

Resolution Order:
1. Vhost-specific endpoint (if vhost matched + endpoint matched)
2. Global endpoint (if endpoint matched)
3. Vhost defaults (if vhost matched)
4. Global defaults

Defense Profile Resolution:
1. Endpoint defense_profiles (if configured)
2. Vhost defense_profiles (if configured)
3. Default profile (balanced-web)
```

## Deployment Options

### Local Development (Docker Compose)
- Single instance of each component
- Hot-reload for Lua scripts
- Redis Commander for easy data management

### Kubernetes (Helm Chart)
- OpenResty as DaemonSet or Deployment with HPA
- HAProxy as StatefulSet with peer discovery
- Redis as single instance or cluster
- ConfigMaps for configuration
- Secrets for sensitive data

### Kubernetes (kd templates)
- Simpler alternative to Helm
- Environment variable substitution
- Good for CI/CD pipelines

## Security Considerations

1. **Rate Limiting Bypass**: Multiple layers (OpenResty + HAProxy) prevent single-point bypass
2. **Hash Collision**: SHA256 provides sufficient collision resistance
3. **Redis Security**: Use authentication and network policies in production
4. **Peer Communication**: HAProxy peers should use TLS in production
5. **Header Injection**: Validate/sanitize headers between components

## Performance Tuning

1. **OpenResty**:
   - Adjust `lua_shared_dict` sizes for caching
   - Redis connection pooling
   - Async keyword list refresh

2. **HAProxy**:
   - Stick-table size based on expected unique hashes
   - Peer sync interval tuning
   - Connection limits

3. **Redis**:
   - Consider Redis Cluster for high availability
   - Use pipelining for batch operations

4. **Defense Profiles**:
   - Enable short-circuit to skip remaining profiles after block
   - Use parallel execution for multi-profile setups
   - Monitor execution times via waf_timing shared dict
   - Limit profile complexity to stay under 100ms

## Lua Module Architecture

### Module Dependency Graph

```
                              ┌─────────────────────────────────────┐
                              │          init_worker.lua            │
                              │  (Starts background timers)         │
                              └───────────────┬─────────────────────┘
                                              │
                 ┌────────────────────────────┼────────────────────────────┐
                 │                            │                            │
                 ▼                            ▼                            ▼
┌──────────────────────────┐  ┌──────────────────────────┐  ┌──────────────────────────┐
│    redis_sync.lua        │  │ instance_coordinator.lua │  │      rbac.lua            │
│  (30s config sync)       │  │  (15s heartbeat)         │  │ (seed roles/admin)       │
└──────────────────────────┘  │  (10s leader maintenance)│  └──────────────────────────┘
                              │  (30s metrics push)      │
                              └──────────────────────────┘
```

### Request Processing Pipeline

```
waf_handler.lua (Main Orchestrator)
│
├── Step 0: Context Resolution
│   ├── vhost_matcher.lua ──► vhost_resolver.lua
│   └── endpoint_matcher.lua ──► config_resolver.lua
│
├── Step 1: Defense Profile Execution (NEW)
│   └── defense_profile_multi_executor.lua
│       ├── Parallel profile execution
│       ├── Score/decision aggregation
│       └── Defense Lines with attack signatures
│
├── Step 2: Early Checks (before parsing)
│   ├── ip_utils.lua (IP whitelist check)
│   ├── geoip.lua (country/ASN restrictions)
│   └── ip_reputation.lua (AbuseIPDB, blocklist)
│
├── Step 3: Form Parsing
│   └── form_parser.lua (multipart, urlencoded, JSON)
│
├── Step 4: Content Analysis
│   ├── content_hasher.lua (SHA256 generation)
│   ├── keyword_filter.lua (blocked/flagged keywords)
│   └── disposable_domains.lua (temp email detection)
│
├── Step 5: Bot Detection
│   ├── timing_token.lua (form fill timing)
│   └── behavioral_tracker.lua (anomaly detection)
│
├── Step 6: Field Validation
│   ├── Expected fields check
│   ├── Required fields check
│   └── Honeypot detection
│
├── Step 7: Score Evaluation
│   ├── Sum all spam scores
│   ├── Check thresholds
│   └── CAPTCHA check (captcha_handler.lua)
│
├── Step 8: Recording
│   ├── metrics.lua (increment counters)
│   ├── field_learner.lua (learn new fields)
│   └── webhooks.lua (send notifications)
│
└── Response
    ├── Block (403 JSON)
    └── Allow (forward to HAProxy)
```

### Admin API Layer

```
admin_api.lua (Router)
│
├── Authentication
│   ├── admin_auth.lua (session management)
│   └── rbac.lua (permission checking)
│
└── api_handlers/ (20 Modular Handlers)
    ├── system.lua ────────► /status, /metrics, /sync
    ├── users.lua ─────────► /users/*
    ├── vhosts.lua ────────► /vhosts/*
    ├── endpoints.lua ─────► /endpoints/*
    ├── keywords.lua ──────► /keywords/*
    ├── hashes.lua ────────► /hashes/*
    ├── whitelist.lua ─────► /whitelist/*
    ├── timing.lua ────────► /timing/*
    ├── behavioral.lua ────► /behavioral/*
    ├── geoip.lua ─────────► /geoip/*
    ├── reputation.lua ────► /reputation/*
    ├── captcha.lua ───────► /captcha/*
    ├── webhooks.lua ──────► /webhooks/*
    ├── bulk.lua ──────────► /bulk/*
    ├── cluster.lua ───────► /cluster/*
    ├── config.lua ────────► /config/*
    ├── providers.lua ─────► /auth/providers/*
    ├── defense_profiles.lua ► /defense-profiles/*
    ├── attack_signatures.lua ► /attack-signatures/*
    └── utils.lua ─────────► Shared utilities
```

### Background Services

```
┌──────────────────────────────────────────────────────────────────┐
│                      Background Timers                            │
│                    (Started in init_worker)                       │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  redis_sync (every 30s):                                         │
│  ├── Pull keywords from Redis                                    │
│  ├── Pull hashes from Redis                                      │
│  ├── Pull vhost/endpoint configs                                 │
│  ├── Pull defense profiles and attack signatures                 │
│  ├── Pull security configs (timing, geoip, reputation)           │
│  └── Update local caches (shared dictionaries)                   │
│                                                                  │
│  instance_coordinator.heartbeat (every 15s):                     │
│  ├── Update heartbeat key in Redis                               │
│  └── Push local metrics to Redis (every 30s)                     │
│                                                                  │
│  instance_coordinator.leader_maintenance (every 10s, leader only):│
│  ├── Renew leader TTL                                            │
│  ├── Check instance health                                       │
│  ├── Remove stale instances                                      │
│  ├── Aggregate global metrics                                    │
│  └── Run registered leader tasks                                 │
│                                                                  │
│  field_learner.flush (every 10s):                                │
│  ├── Batch collected fields                                      │
│  └── Write to Redis (10% sampling for high traffic)              │
│                                                                  │
│  webhooks.batch_sender (as needed):                              │
│  └── Send queued webhook events                                  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

## HAProxy Integration Details

### Two-Stage Architecture

OpenResty performs intelligent analysis, HAProxy provides global rate limiting:

```
┌──────────────────────────────────────────────────────────────────┐
│                        OpenResty                                  │
│                                                                  │
│  Computes per-request:                                           │
│  - X-WAF-Form-Hash: SHA256 of normalized content                 │
│  - X-WAF-Spam-Score: 0-100+ based on all detection rules         │
│  - X-WAF-Client-IP: Resolved client IP                           │
│  - X-WAF-Submission-Fingerprint: Client fingerprint              │
│  - X-WAF-Mode: blocking/monitoring/passthrough                   │
│  - X-Blocked: true/false (early block decisions)                 │
│                                                                  │
└─────────────────────────────┬────────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────────┐
│                         HAProxy                                   │
│                                                                  │
│  Stage 1 (ft_waf): Main WAF checks                               │
│  ├── Read X-WAF-Form-Hash ──► Track in st_form_hashes            │
│  ├── Read X-WAF-Spam-Score ──► Track cumulative in st_spam_scores│
│  ├── Read X-WAF-Client-IP ──► Track rate in st_client_ips        │
│  └── ACL checks:                                                 │
│      - blocked_by_openresty? ──► 403                             │
│      - spam_score >= threshold? ──► 403                          │
│      - hash_rate > threshold? ──► 429                            │
│      - ip_rate > threshold? ──► 429                              │
│                                                                  │
│  Stage 2 (ft_fingerprint): Fingerprint tracking                  │
│  ├── Read X-WAF-Submission-Fingerprint                           │
│  ├── Track in st_fingerprints                                    │
│  └── fingerprint_rate > threshold? ──► 429                       │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Stick-Tables with Peer Synchronization

```
┌────────────────────┐     ┌────────────────────┐     ┌────────────────────┐
│    haproxy-0       │     │    haproxy-1       │     │    haproxy-2       │
│                    │     │                    │     │                    │
│  st_form_hashes    │◀───▶│  st_form_hashes    │◀───▶│  st_form_hashes    │
│  st_client_ips     │     │  st_client_ips     │     │  st_client_ips     │
│  st_spam_scores    │     │  st_spam_scores    │     │  st_spam_scores    │
│  st_fingerprints   │     │  st_fingerprints   │     │  st_fingerprints   │
│                    │     │                    │     │                    │
└─────────┬──────────┘     └─────────┬──────────┘     └─────────┬──────────┘
          │                          │                          │
          └──────────────────────────┼──────────────────────────┘
                                     │
                               Port 10000
                           (Peer sync protocol)
```

**Stick-Table Details:**

| Table | Key | Size | Expire | Counters |
|-------|-----|------|--------|----------|
| st_form_hashes | SHA256 (64 chars) | 100k | 1 hour | gpc0 (count), gpc0_rate(60s), gpc1 (flag) |
| st_client_ips | IP (45 chars) | 50k | 1 hour | http_req_rate(60s), http_req_cnt, gpc0 |
| st_spam_scores | IP (45 chars) | 50k | 24 hours | gpc0 (cumulative score), gpc1 |
| st_fingerprints | Hash (16 chars) | 100k | 1 hour | http_req_rate(60s), gpc0 |

## Cross-Component Communication

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Redis                                           │
│                                                                             │
│  Configuration (sync every 30s):                                            │
│  ├── waf:keywords:* ────────► keyword_filter.lua                            │
│  ├── waf:hashes:* ──────────► content_hasher.lua                            │
│  ├── waf:vhosts:* ──────────► vhost_resolver.lua                            │
│  ├── waf:endpoints:* ───────► endpoint_matcher.lua                          │
│  ├── waf:defense_profiles:* ► defense_profile_executor.lua                  │
│  ├── waf:attack_signatures:* ► attack_signatures_store.lua                  │
│  ├── waf:config:* ──────────► waf_config.lua                                │
│  └── waf:whitelist:* ───────► ip_utils.lua                                  │
│                                                                             │
│  Cluster State (real-time):                                                 │
│  ├── waf:cluster:instances ──► Instance registry                            │
│  ├── waf:cluster:leader ─────► Leader election key                          │
│  └── waf:metrics:* ──────────► Metrics aggregation                          │
│                                                                             │
│  Auth & Sessions:                                                           │
│  ├── waf:admin:users:* ─────► User records                                  │
│  ├── waf:auth:sessions:* ───► Session tokens                                │
│  └── waf:auth:roles:* ──────► Role definitions                              │
│                                                                             │
│  Behavioral Tracking:                                                       │
│  └── waf:behavioral:* ──────► Flow statistics, baselines                    │
│                                                                             │
│  Field Learning:                                                            │
│  └── waf:learning:* ────────► Discovered form fields                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Related Documentation

- [Defense Profiles](DEFENSE_PROFILES.md) - DAG-based execution engine, node types, built-in profiles
- [Attack Signatures](ATTACK_SIGNATURES.md) - Pattern matching, built-in signatures, defense lines
- [Endpoint Configuration](ENDPOINT_CONFIGURATION.md) - Endpoint matching, per-endpoint settings
- [API Handlers](API_HANDLERS.md) - Admin API modular handlers
- [Behavioral Tracking](BEHAVIORAL_TRACKING.md) - Anomaly detection system
- [Cluster Coordination](CLUSTER_COORDINATION.md) - Leader election and instance management
- [Fingerprint Profiles](FINGERPRINT_PROFILES.md) - Client fingerprinting system
- [Metrics Aggregation](METRICS_AGGREGATION.md) - Cluster-wide metrics
- [RBAC](RBAC.md) - Role-based access control for Admin API
- [SSO Setup](SSO_OIDC_SETUP.md) - Single sign-on configuration
- [User Guide](guide/USER_GUIDE.md) - Complete user guide
- [Configuration Reference](guide/CONFIGURATION_REFERENCE.md) - All configuration options
- [Attack Playbook](guide/ATTACK_PLAYBOOK.md) - Defense strategies for common attacks
