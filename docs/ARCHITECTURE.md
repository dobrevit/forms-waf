# Forms WAF - Spam Protection Architecture

## Overview

This system provides a multi-layer spam protection mechanism for web forms using:
1. **OpenResty** - Form parsing, content hashing, keyword filtering
2. **HAProxy** - Global rate limiting with stick-tables and peer synchronization
3. **Redis** - Dynamic configuration for keywords and blocklists

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

### 1. Request Processing in OpenResty

```
Incoming POST Request
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
└───────────────────┘
        │
        ▼
   Forward to HAProxy
```

### 2. HAProxy Stick-Table Processing

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

# Flagged keywords - adds to spam score
SADD waf:keywords:flagged "free" "winner" "click here" "urgent"

# Blocked hashes - known spam content
SADD waf:hashes:blocked "abc123..." "def456..."

# Configuration thresholds
HSET waf:config:thresholds spam_score_block 80
HSET waf:config:thresholds spam_score_flag 50
HSET waf:config:thresholds hash_count_block 10
HSET waf:config:thresholds ip_rate_limit 30

# Whitelisted IPs
SADD waf:whitelist:ips "10.0.0.0/8" "192.168.1.100"
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
