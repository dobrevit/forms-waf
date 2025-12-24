# Configuration Reference

Complete reference for all Forms WAF configuration options.

---

## Table of Contents

1. [Environment Variables](#environment-variables)
2. [Global Thresholds](#global-thresholds)
3. [Virtual Host Configuration](#virtual-host-configuration)
4. [Endpoint Configuration](#endpoint-configuration)
5. [Security Features](#security-features)
6. [Timing Token Configuration](#timing-token-configuration)
7. [GeoIP Configuration](#geoip-configuration)
8. [IP Reputation Configuration](#ip-reputation-configuration)
9. [CAPTCHA Configuration](#captcha-configuration)
10. [Behavioral Tracking Configuration](#behavioral-tracking-configuration)
11. [Fingerprint Profiles Configuration](#fingerprint-profiles-configuration)
12. [Defense Profiles Configuration](#defense-profiles-configuration)
13. [Webhooks Configuration](#webhooks-configuration)
14. [Scoring Reference](#scoring-reference)

---

## Environment Variables

### OpenResty Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | `redis` | Redis server hostname |
| `REDIS_PORT` | `6379` | Redis server port |
| `REDIS_PASSWORD` | `` | Redis authentication password |
| `WAF_SYNC_INTERVAL` | `30` | Config sync interval in seconds |
| `HAPROXY_UPSTREAM` | `haproxy:8080` | HAProxy HTTP endpoint |
| `HAPROXY_UPSTREAM_SSL` | `haproxy:8443` | HAProxy HTTPS endpoint |
| `UPSTREAM_SSL` | `false` | Use HTTPS for HAProxy |
| `HAPROXY_TIMEOUT` | `30` | HAProxy connection timeout |
| `EXPOSE_WAF_HEADERS` | `false` | Expose debug headers globally |

### Admin User Seeding

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_SEED_ENABLED` | `true` | Enable admin user seeding |
| `ADMIN_SEED_USERNAME` | `admin` | Default admin username |
| `ADMIN_SEED_PASSWORD` | `changeme` | Default admin password |
| `ADMIN_SEED_SALT` | (auto) | Password hashing salt |

### HAProxy Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KUBERNETES_MODE` | `false` | Enable Kubernetes peer discovery |
| `PEER_PORT` | `10000` | HAProxy peer sync port |
| `BACKEND_SERVERS` | `backend:8080` | Backend server list |

---

## Global Thresholds

Stored in Redis key: `waf:config:thresholds`

```json
{
  "spam_score_block": 80,
  "spam_score_flag": 50,
  "hash_count_block": 10,
  "ip_rate_limit": 30,
  "ip_daily_limit": 500,
  "fingerprint_rate_limit": 20,
  "ip_spam_score_threshold": 500
}
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `spam_score_block` | number | 80 | Block when score >= this |
| `spam_score_flag` | number | 50 | Flag to HAProxy when score >= this |
| `hash_count_block` | number | 10 | Block duplicate hash after N submissions/min |
| `ip_rate_limit` | number | 30 | Max requests per IP per minute |
| `ip_daily_limit` | number | 500 | Max requests per IP per day |
| `fingerprint_rate_limit` | number | 20 | Max requests per fingerprint per minute |
| `ip_spam_score_threshold` | number | 500 | Cumulative spam score limit per IP (24h) |

### Rate Limiting vs Score-Based Blocking

The WAF uses two different approaches to blocking that are often confused:

#### Request Count Limits (Rate Limiting)
These thresholds limit the **NUMBER of requests** regardless of content quality:

| Setting | Description | Scope |
|---------|-------------|-------|
| `ip_rate_limit` | Max requests per minute per IP | 1-minute window |
| `ip_daily_limit` | Max requests per day per IP | 24-hour window |
| `fingerprint_rate_limit` | Max requests per minute per fingerprint | 1-minute window |

#### Score-Based Limits
These thresholds work with **SPAM SCORES** (points assigned to suspicious content):

| Setting | Description | Scope |
|---------|-------------|-------|
| `spam_score_block` | Block if request score >= threshold | Per-request |
| `spam_score_flag` | Flag if request score >= threshold | Per-request |
| `ip_spam_score_threshold` | Block IP when **cumulative** score exceeds threshold | 24-hour rolling |

**Example:** An IP sending 10 requests with spam_score=60 each:
- Passes `spam_score_block=80` (each request is under 80)
- Accumulates 600 points toward `ip_spam_score_threshold`
- Gets blocked by `ip_spam_score_threshold=500` on the 9th request

This catches "low and slow" attacks where individual requests appear legitimate but the pattern is abusive.

### Recommended Ranges

| Environment | `spam_score_block` | `spam_score_flag` | `ip_spam_score_threshold` |
|-------------|-------------------|-------------------|---------------------------|
| Lenient | 100 | 70 | 750 |
| Default | 80 | 50 | 500 |
| Strict | 60 | 30 | 375 |
| Maximum | 40 | 20 | 250 |

---

## Virtual Host Configuration

Stored in Redis keys:
- Index: `waf:vhosts:index` (hash: vhost_id -> hostnames)
- Config: `waf:vhosts:config:{vhost_id}` (JSON)

### Complete Schema

```yaml
id: string                    # Unique identifier (required)
name: string                  # Display name
description: string           # Description
enabled: boolean              # Enable/disable vhost
hostnames: string[]           # Matching hostnames (supports wildcards)
priority: number              # Match priority (higher = first)

waf:
  enabled: boolean            # Enable WAF for this vhost
  mode: string                # "blocking" | "monitoring" | "passthrough" | "strict"
  debug_headers: boolean      # Expose X-WAF-* headers

routing:
  use_haproxy: boolean        # Route through HAProxy
  haproxy_backend: string     # HAProxy backend name
  upstream:                   # Direct upstream (if not using HAProxy)
    servers: string[]         # ["10.0.1.1:8080", "10.0.1.2:8080"]
    ssl: boolean              # Use HTTPS
    ssl_verify: boolean       # Verify SSL certificate

thresholds:
  spam_score_block: number    # Override global
  spam_score_flag: number     # Override global
  inherit_global: boolean     # Inherit from global (default: true)

keywords:
  inherit_global: boolean     # Inherit global keywords
  additional_blocked: string[]# Vhost-specific blocked keywords
  additional_flagged: string[]# Vhost-specific flagged (format: "keyword:score")
  excluded_blocked: string[]  # Exclude from global blocked
  excluded_flagged: string[]  # Exclude from global flagged

security:
  honeypot_fields: string[]   # Hidden fields to detect bots
  honeypot_action: string     # "block" | "flag"
  honeypot_score: number      # Score if action is "flag"
  check_disposable_email: boolean
  disposable_email_action: string  # "block" | "flag" | "ignore"
  disposable_email_score: number
  check_field_anomalies: boolean
  timing_token_enabled: boolean   # Override global timing

timing:                       # Vhost-specific timing config
  enabled: boolean
  start_paths: string[]       # Paths that set timing cookie
  end_paths: string[]         # Paths that validate timing
  path_match_mode: string     # "exact" | "prefix" | "regex"
  min_time_block: number      # Seconds
  min_time_flag: number       # Seconds
  score_no_cookie: number
  score_too_fast: number
  score_suspicious: number
  cookie_ttl: number          # Cookie max age in seconds

rate_limiting:
  enabled: boolean
  requests_per_minute: number

fields:
  ignore: string[]            # Fields to exclude from scanning
  required:                   # Required field validation
    - name: string
      type: string            # "string" | "email" | "number"
      min_length: number
      max_length: number
      pattern: string         # Regex pattern
  expected: string[]          # Optional expected fields
  hash:
    enabled: boolean
    fields: string[]          # Fields to include in hash

behavioral:                   # See Behavioral section
  enabled: boolean
  flows: Flow[]
  tracking: TrackingConfig
  baselines: BaselineConfig
  anomaly_detection: AnomalyConfig

captcha:                      # See CAPTCHA section
  enabled: boolean
  provider: string
  trigger_on_block: boolean
  trigger_score: number

endpoints: Endpoint[]         # Endpoint-specific configs
```

### Example Configurations

#### Basic Vhost

```yaml
id: "example-site"
name: "Example Website"
enabled: true
hostnames:
  - "example.com"
  - "www.example.com"

waf:
  enabled: true
  mode: "blocking"

thresholds:
  spam_score_block: 80
  spam_score_flag: 50

security:
  honeypot_fields: ["website"]
  check_disposable_email: true
```

#### Wildcard Matching

```yaml
id: "customer-sites"
hostnames:
  - "*.customers.example.com"
priority: 90  # Lower than exact matches
```

#### Strict Security

```yaml
id: "payment-forms"
waf:
  mode: "strict"

thresholds:
  spam_score_block: 50
  spam_score_flag: 25

security:
  honeypot_fields: ["website", "fax", "extension"]
  honeypot_action: "block"
  check_disposable_email: true
  disposable_email_action: "block"

captcha:
  enabled: true
  trigger_on_block: true
```

---

## Endpoint Configuration

Endpoints provide path-specific overrides within a vhost.

### Schema

```yaml
id: string                    # Unique within vhost
name: string                  # Display name
enabled: boolean

matching:
  paths: string[]             # Path patterns
  methods: string[]           # HTTP methods ["POST", "PUT"]
  content_types: string[]     # Content type patterns
  path_match_mode: string     # "exact" | "prefix" | "regex"

thresholds:
  spam_score_block: number
  spam_score_flag: number
  inherit_vhost: boolean      # Inherit from vhost

security:
  timing_token_enabled: boolean
  check_field_anomalies: boolean
  honeypot_fields: string[]
  # ... all security options

keywords:
  inherit_vhost: boolean
  additional_blocked: string[]
  additional_flagged: string[]
  excluded_blocked: string[]
  excluded_flagged: string[]

patterns:
  inherit_global: boolean
  disabled: string[]          # Disable specific patterns
  custom:                     # Add custom patterns
    - pattern: string
      score: number
      flag: string

fields:
  ignore: string[]
  required: FieldValidation[]
  expected: string[]
  hash:
    enabled: boolean
    fields: string[]
  unexpected_action: string   # "flag" | "block" | "filter" | "ignore"

geoip:                        # Override vhost GeoIP
  enabled: boolean
  blocked_countries: string[]
  allowed_countries: string[]
```

### Example

```yaml
endpoints:
  - id: "contact-submit"
    name: "Contact Form Submission"
    matching:
      paths: ["/contact/submit", "/contact"]
      methods: ["POST"]
      path_match_mode: "exact"

    thresholds:
      spam_score_block: 60

    security:
      honeypot_fields: ["website", "company_fax"]
      honeypot_action: "block"

    fields:
      required:
        - name: "email"
          type: "email"
        - name: "message"
          min_length: 10
      ignore:
        - "csrf_token"
```

---

## Security Features

### Honeypot Configuration

```yaml
security:
  honeypot_fields:
    - "website"        # Hidden "Website" field
    - "homepage"       # Hidden "Homepage" field
    - "fax"            # Hidden "Fax" field
    - "phone_ext"      # Hidden "Extension" field

  honeypot_action: "block"  # "block" or "flag"
  honeypot_score: 50        # If action is "flag"
```

### Disposable Email Detection

```yaml
security:
  check_disposable_email: true
  disposable_email_action: "block"  # "block" | "flag" | "ignore"
  disposable_email_score: 10        # If action is "flag"
```

Built-in database includes 1000+ disposable domains.

### Field Anomaly Detection

```yaml
security:
  check_field_anomalies: true  # Default: true
```

Detects:
- All fields same length
- Sequential patterns (aaa, 123)
- All caps fields
- Test data patterns
- Long fields without spaces

### Field Validation

```yaml
fields:
  required:
    - name: "email"
      type: "email"           # Validates email format

    - name: "name"
      type: "string"
      min_length: 2
      max_length: 100

    - name: "age"
      type: "number"
      min_value: 18
      max_value: 120

    - name: "phone"
      type: "string"
      pattern: "^\\+?[0-9\\s-]+$"  # Regex pattern
```

### Ignored Fields

```yaml
fields:
  ignore:
    - "csrf_token"
    - "_token"
    - "captcha_response"
    - "password"
    - "credit_card"
    - "cc_cvv"
```

### Expected Fields

```yaml
fields:
  expected:
    - "name"
    - "email"
    - "message"

  # Combined with required for full field set
  unexpected_action: "flag"   # "flag" | "block" | "filter" | "ignore"
```

---

## Timing Token Configuration

Stored in Redis key: `waf:config:timing_token`

### Schema

```yaml
enabled: boolean              # Enable timing tokens
cookie_name: string           # Cookie name prefix (default: "_waf_timing")
cookie_ttl: number            # Max validity in seconds (default: 3600)
secret_key: string            # Encryption key (auto-generated if not set)

# Time thresholds
min_time_block: number        # Block under this (seconds, default: 2)
min_time_flag: number         # Flag under this (seconds, default: 5)

# Score additions
score_no_cookie: number       # No timing cookie (default: 30)
score_too_fast: number        # Under min_time_block (default: 40)
score_suspicious: number      # Under min_time_flag (default: 20)

# Path matching
start_paths: string[]         # Paths that set cookie (empty = all)
end_paths: string[]           # Paths that validate (empty = all)
path_match_mode: string       # "exact" | "prefix" | "regex"
```

### Example

```yaml
timing:
  enabled: true
  min_time_block: 3
  min_time_flag: 8
  score_no_cookie: 35
  score_too_fast: 45
  score_suspicious: 25

  start_paths:
    - "/contact"
    - "/signup"
    - "/register"

  end_paths:
    - "/contact/submit"
    - "/signup/complete"
    - "/register"

  path_match_mode: "prefix"
```

---

## GeoIP Configuration

Stored in Redis key: `waf:config:geoip`

### Schema

```yaml
enabled: boolean

# Database paths
country_db_path: string       # Default: /usr/share/GeoIP/GeoLite2-Country.mmdb
asn_db_path: string           # Default: /usr/share/GeoIP/GeoLite2-ASN.mmdb

# Country controls
blocked_countries: string[]   # ISO codes to block (e.g., ["RU", "CN"])
allowed_countries: string[]   # Whitelist mode (if set, only these allowed)
flagged_countries: string[]   # Add score but don't block
flagged_country_score: number # Score for flagged countries (default: 15)

# ASN controls
blocked_asns: number[]        # ASN numbers to block
flagged_asns: number[]        # ASNs to flag
flagged_asn_score: number     # Score for flagged ASNs (default: 20)

# Datacenter detection
datacenter_asns: object       # {asn: "provider name"}
block_datacenters: boolean    # Block all datacenter IPs
flag_datacenters: boolean     # Flag datacenter IPs (default: true)
datacenter_score: number      # Score for datacenters (default: 25)

default_action: string        # "allow" | "block" | "flag"
```

### Built-in Datacenter ASNs

```yaml
# Pre-configured datacenter ASNs
datacenter_asns:
  16509: "Amazon"
  14618: "Amazon"
  15169: "Google"
  396982: "Google Cloud"
  8075: "Microsoft Azure"
  13335: "Cloudflare"
  54113: "Fastly"
  20940: "Akamai"
  16276: "OVH"
  24940: "Hetzner"
  14061: "DigitalOcean"
  63949: "Linode"
  20473: "Vultr"
  # ... more in geoip.lua
```

### Example

```yaml
geoip:
  enabled: true

  blocked_countries:
    - "KP"  # North Korea
    - "IR"  # Iran

  flagged_countries:
    - "RU"
    - "UA"
    - "RO"
  flagged_country_score: 20

  blocked_asns:
    - 9009    # M247 (VPN infrastructure)

  flag_datacenters: true
  datacenter_score: 30
```

---

## IP Reputation Configuration

Stored in Redis key: `waf:config:ip_reputation`

### Schema

```yaml
enabled: boolean

# Cache settings
cache_ttl: number             # Cache bad reputation (default: 86400)
cache_negative_ttl: number    # Cache clean results (default: 3600)

# AbuseIPDB provider
abuseipdb:
  enabled: boolean
  api_key: string             # Required if enabled
  min_confidence: number      # Min score to flag (default: 25)
  max_age_days: number        # Only consider recent reports (default: 90)
  score_multiplier: number    # Multiply AbuseIPDB score (default: 0.5)

# Local blocklist
local_blocklist:
  enabled: boolean            # Default: true
  redis_key: string           # Default: "waf:reputation:blocked_ips"

# Custom webhook
webhook:
  enabled: boolean
  url: string
  timeout: number             # Milliseconds (default: 2000)
  headers: object             # Custom headers

# Score thresholds
block_score: number           # Block if >= this (default: 80)
flag_score: number            # Flag if >= this (default: 50)
flag_score_addition: number   # Add this to spam score (default: 30)
```

### Example

```yaml
ip_reputation:
  enabled: true

  abuseipdb:
    enabled: true
    api_key: "your-abuseipdb-api-key"
    min_confidence: 30
    max_age_days: 60

  local_blocklist:
    enabled: true

  block_score: 70
  flag_score: 40
  flag_score_addition: 25
```

---

## CAPTCHA Configuration

Stored in Redis key: `waf:config:captcha`

### Schema

```yaml
enabled: boolean

# Provider selection
provider: string              # "recaptcha_v2" | "recaptcha_v3" | "hcaptcha" | "turnstile"

# Provider credentials
site_key: string              # Public key
secret_key: string            # Server key

# Trigger conditions
trigger_on_block: boolean     # Show CAPTCHA instead of blocking
trigger_score: number         # Show when spam_score >= this
trigger_on_flagged: boolean   # Show for flagged requests

# Trust tokens
trust_token_enabled: boolean  # Issue token after solving
trust_token_ttl: number       # Token validity (default: 3600)

# Provider-specific
recaptcha_v3:
  min_score: number           # 0.0-1.0 threshold (default: 0.5)
  action: string              # Action name for verification

hcaptcha:
  theme: string               # "light" | "dark"
  size: string                # "normal" | "compact"

turnstile:
  theme: string               # "light" | "dark" | "auto"
  size: string                # "normal" | "compact"
```

### Example

```yaml
captcha:
  enabled: true
  provider: "turnstile"

  site_key: "0x4AAAAAAA..."
  secret_key: "0x4AAAAAAA..."

  trigger_on_block: true
  trigger_score: 60

  trust_token_enabled: true
  trust_token_ttl: 7200       # 2 hours
```

---

## Behavioral Tracking Configuration

Configured per-vhost in `vhost.behavioral`.

### Schema

```yaml
behavioral:
  enabled: boolean

  # Flow definitions
  flows:
    - name: string            # Flow identifier
      start_paths: string[]   # Entry point paths
      start_methods: string[] # Entry methods (default: ["GET"])
      end_paths: string[]     # Submission paths
      end_methods: string[]   # Submission methods (default: ["POST"])
      path_match_mode: string # "exact" | "prefix" | "regex"

  # What to track
  tracking:
    submission_counts: boolean    # Total submissions (default: true)
    fill_duration: boolean        # Time to fill form (default: true)
    unique_ips: boolean           # Unique IP count (default: true)
    avg_spam_score: boolean       # Average spam score (default: true)

  # Baseline calculation
  baselines:
    learning_period_days: number  # Days of data for baseline (default: 14)
    min_samples: number           # Minimum samples needed (default: 100)
    recalculate_interval: number  # Seconds between recalcs (default: 3600)

  # Anomaly detection
  anomaly_detection:
    enabled: boolean
    std_dev_threshold: number     # Z-score threshold (default: 2.0)
    action: string                # "score" | "log" | "block"
    score_addition: number        # Score to add (default: 15)
```

### Example

```yaml
behavioral:
  enabled: true

  flows:
    - name: "contact-flow"
      start_paths: ["/contact"]
      end_paths: ["/contact/submit", "/contact"]
      path_match_mode: "exact"

    - name: "signup-flow"
      start_paths: ["/signup", "/register"]
      end_paths: ["/signup/complete", "/register"]
      path_match_mode: "prefix"

  tracking:
    submission_counts: true
    fill_duration: true
    unique_ips: true

  baselines:
    learning_period_days: 14
    min_samples: 50

  anomaly_detection:
    enabled: true
    std_dev_threshold: 2.0
    action: "score"
    score_addition: 20
```

---

## Defense Profiles Configuration

Defense profiles provide DAG-based execution of defense mechanisms. For complete documentation including node types, operators, and custom profile creation, see [Defense Profiles](../DEFENSE_PROFILES.md).

**Stored in Redis keys:**
- `waf:defense_profiles:index` - Sorted set of profile IDs by priority
- `waf:defense_profiles:config:<id>` - Individual profile configurations
- `waf:defense_profiles:builtin_version` - Builtin version tracking

### Attaching Profiles to Endpoints

```yaml
endpoints:
  - id: contact-form
    defense_profiles:
      enabled: true
      profiles:
        - id: balanced-web
          priority: 100
          weight: 1.0
      aggregation: "OR"           # OR | AND | MAJORITY
      score_aggregation: "SUM"    # SUM | MAX | WEIGHTED_AVG
      short_circuit: true         # Stop after first block
```

### Defense Lines (Profiles + Attack Signatures)

```yaml
endpoints:
  - id: wp-login
    defense_lines:
      - enabled: true
        profile_id: strict-api
        signature_ids:
          - builtin_wordpress_login
          - builtin_credential_stuffing
```

For attack signature configuration, see [Attack Signatures](../ATTACK_SIGNATURES.md).

---

## Fingerprint Profiles Configuration

Stored in Redis keys:
- `waf:fingerprint:profiles:index` - Sorted set of profile IDs by priority
- `waf:fingerprint:profiles:config:<id>` - Individual profile configurations
- `waf:fingerprint:profiles:builtin` - Set of built-in profile IDs

### Profile Schema

```yaml
id: string                    # Unique identifier
name: string                  # Display name
description: string           # Optional description
enabled: boolean              # Enable/disable profile (default: true)
builtin: boolean              # Read-only, indicates built-in profile
priority: number              # Lower = higher priority (default: 500)
action: string                # allow, block, flag, ignore (default: allow)
score: number                 # Spam score to add on match (default: 0)

matching:
  match_mode: string          # all (AND) or any (OR)
  conditions:                 # Array of conditions
    - header: string          # HTTP header name
      condition: string       # present, absent, matches, not_matches
      pattern: string         # Regex pattern (for matches/not_matches)

fingerprint_headers:
  headers: string[]           # Headers to include in fingerprint
  normalize: boolean          # Lowercase and trim (default: true)
  max_length: number          # Truncate values (default: 100)
  include_field_names: boolean # Include header names in hash (default: true)

rate_limiting:
  enabled: boolean            # Enable per-fingerprint rate limiting
  fingerprint_rate_limit: number # Max requests per fingerprint per minute
```

### Endpoint/Vhost Fingerprint Configuration

```yaml
fingerprint_profiles:
  enabled: boolean            # Enable fingerprinting for this endpoint
  profiles: string[]          # Profile IDs to use (null = all enabled)
  no_match_action: string     # use_default, allow, block, flag
  no_match_score: number      # Score to add when no profile matches
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | boolean | true | Enable fingerprint profile matching |
| `profiles` | string[] | null | Limit to specific profiles (null = all) |
| `no_match_action` | string | use_default | Action when no profile matches |
| `no_match_score` | number | 15 | Score to add when no match (if use_default) |

### Built-in Profiles

| Profile ID | Priority | Action | Description |
|------------|----------|--------|-------------|
| `known-bot` | 50 | ignore | Search engine crawlers (Googlebot, Bingbot, etc.) |
| `modern-browser` | 100 | allow | Standard browsers with full headers |
| `headless-browser` | 120 | flag (+25) | Automation tools (Puppeteer, Selenium) |
| `suspicious-bot` | 150 | flag (+30) | Scripts (curl, wget, python-requests) |
| `legacy-browser` | 200 | allow (+5) | Older browsers with minimal headers |
| `no-user-agent` | 300 | flag (+40) | Requests missing User-Agent header |

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/fingerprint-profiles` | List all profiles |
| POST | `/fingerprint-profiles` | Create custom profile |
| GET | `/fingerprint-profiles/:id` | Get profile by ID |
| PUT | `/fingerprint-profiles/:id` | Update profile |
| DELETE | `/fingerprint-profiles/:id` | Delete custom profile |
| POST | `/fingerprint-profiles/test` | Test headers against profiles |
| POST | `/fingerprint-profiles/reset-builtin` | Reset built-ins to defaults |

---

## Webhooks Configuration

Stored in Redis key: `waf:config:webhooks`

### Schema

```yaml
enabled: boolean
url: string                   # Webhook endpoint

# Events to notify
notify_on:
  - "blocked"                 # Request blocked
  - "honeypot_triggered"      # Honeypot field filled
  - "captcha_challenge"       # CAPTCHA shown
  - "captcha_failed"          # CAPTCHA verification failed
  - "disposable_email"        # Disposable email detected

# Payload options
include_form_data: boolean    # Include form values (privacy!)
include_headers: boolean      # Include request headers
include_geo_info: boolean     # Include GeoIP data
include_reputation: boolean   # Include IP reputation

# Rate limiting
max_per_minute: number        # Max notifications per minute
timeout: number               # Request timeout in ms

# Authentication
headers:
  Authorization: string       # Custom auth header
  X-Custom-Header: string
```

### Webhook Payload Format

```json
{
  "timestamp": "2024-12-20T10:30:00Z",
  "event_type": "blocked",
  "request_id": "abc123",
  "vhost_id": "my-site",
  "endpoint_id": "contact-form",

  "client": {
    "ip": "1.2.3.4",
    "user_agent": "Mozilla/5.0...",
    "referer": "https://example.com/"
  },

  "request": {
    "host": "example.com",
    "path": "/contact/submit",
    "method": "POST"
  },

  "waf": {
    "spam_score": 85,
    "spam_flags": ["timing:no_cookie", "pattern:url:3"],
    "block_reason": "spam_score_exceeded",
    "form_hash": "a1b2c3d4..."
  },

  "geo": {
    "country_code": "RU",
    "asn": 12345,
    "is_datacenter": false
  }
}
```

---

## Scoring Reference

### Complete Score Table

| Category | Detection | Score | Notes |
|----------|-----------|-------|-------|
| **Timing** | No cookie | +30 | Direct POST |
| | Too fast (<2s) | +40 | Bot speed |
| | Suspicious (<5s) | +20 | Fast human |
| **Content** | Flagged keyword | +10 | Per keyword |
| | URL in content | +10 | Per URL (max 5) |
| | BBCode URL | +20 | Forum spam |
| | HTML link | +20 | Injection |
| | URL shortener | +15 | Per shortener |
| | Suspicious TLD | +10 | Per URL |
| | Email in content | +5 | Per email |
| | Excessive caps | +5 | Per match |
| | Phone number | +3 | Per match |
| | Crypto wallet | +15 | Per address |
| | Repetitive chars | +5 | Per match |
| | XSS attempt | +30 | Script injection |
| | IP-based URL | +20 | Suspicious |
| | Many URLs (>3) | +10 | Per extra |
| | Long content | +10 | >5000 chars |
| | Short + URL | +15 | Spam pattern |
| **Fields** | Same length | +15 | All fields equal |
| | Sequential | +5 | Per field |
| | All caps | +5 | Per field |
| | Test data | +8 | Per field |
| | No spaces | +10 | Long field |
| | Unexpected | +5 | Per field |
| **Honeypot** | Field filled | +50 | Or block |
| **GeoIP** | Flagged country | +15 | Configurable |
| | Flagged ASN | +20 | Configurable |
| | Datacenter IP | +25 | Configurable |
| **Reputation** | Flagged IP | +30 | Configurable |
| **Behavioral** | Anomaly | +15 | Z-score > threshold |

### Instant Blocks (No Score)

| Detection | Condition |
|-----------|-----------|
| Blocked keyword | Any match in content |
| Blocked hash | Content hash in blocklist |
| Blocked country | IP from blocked country |
| Blocked ASN | IP from blocked ASN |
| IP blocklist | IP in reputation blocklist |
| Honeypot (block mode) | Honeypot field filled |
| Disposable email (block) | Temp email detected |

---

## Redis Key Reference

### Configuration Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:config:thresholds` | hash | Global thresholds |
| `waf:config:timing_token` | string (JSON) | Timing config |
| `waf:config:geoip` | string (JSON) | GeoIP config |
| `waf:config:ip_reputation` | string (JSON) | Reputation config |
| `waf:config:captcha` | string (JSON) | CAPTCHA config |
| `waf:config:webhooks` | string (JSON) | Webhook config |
| `waf:config:routing` | string (JSON) | Global routing |

### Vhost Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:vhosts:index` | hash | vhost_id -> hostnames |
| `waf:vhosts:config:{id}` | string (JSON) | Vhost config |
| `waf:vhosts:endpoints:{id}` | string (JSON) | Endpoint configs |

### Keyword Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:keywords:blocked` | set | Blocked keywords |
| `waf:keywords:flagged` | hash | keyword -> score |
| `waf:hashes:blocked` | set | Blocked content hashes |

### Whitelist Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:whitelist:ips` | set | Whitelisted IPs/CIDRs |
| `waf:whitelist:cidrs` | string (JSON) | CIDR ranges |

### Reputation Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:reputation:blocked_ips` | set | Local IP blocklist |
| `waf:reputation:cache:{ip}` | string (JSON) | Cached lookup |

### Metrics Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:metrics:instance:{id}` | hash | Instance metrics |
| `waf:metrics:global` | hash | Aggregated metrics |

### Cluster Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:cluster:instances` | hash | Instance registry |
| `waf:cluster:leader` | string | Current leader ID |
| `waf:cluster:instance:{id}:heartbeat` | string | Heartbeat timestamp |

---

## See Also

- [User Guide](USER_GUIDE.md) - Comprehensive usage guide
- [Attack Playbook](ATTACK_PLAYBOOK.md) - Incident response
- [API Handlers](../API_HANDLERS.md) - Admin API reference
- [Architecture](../ARCHITECTURE.md) - System design
