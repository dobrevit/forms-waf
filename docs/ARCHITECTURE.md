# Forms WAF - Spam Protection Architecture

## Overview

This system provides a multi-layer spam protection mechanism for web forms using:
1. **OpenResty** - Form parsing, content hashing, keyword filtering, vhost/endpoint resolution
2. **HAProxy** - Global rate limiting with stick-tables and peer synchronization
3. **Redis** - Dynamic configuration for keywords, blocklists, vhosts, and endpoints
4. **Admin UI** - React-based dashboard for configuration management

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
┌───────────────────┐
│ Keyword Scanning  │ ◀── Checks content against Redis keyword lists
│(keyword_filter)   │     Returns spam_score (0-100) and matched keywords
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Content Hashing   │ ◀── SHA256 hash of normalized form content
│(content_hasher)   │     Used for duplicate/flood detection
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Add Headers       │
│ X-Form-Hash       │
│ X-Spam-Score      │
│ X-Client-IP       │
│ X-Spam-Flags      │
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
```

## Configuration Hierarchy

```
Global Defaults (waf:config:*)
    │
    ├── Virtual Host Override (waf:vhosts:config:{id})
    │       │
    │       └── Vhost-Specific Endpoint (waf:vhosts:endpoints:{vhost_id}:*)
    │
    └── Global Endpoint (waf:endpoints:*)

Resolution Order:
1. Vhost-specific endpoint (if vhost matched + endpoint matched)
2. Global endpoint (if endpoint matched)
3. Vhost defaults (if vhost matched)
4. Global defaults
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
