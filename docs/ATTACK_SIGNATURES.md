# Attack Signatures System

## Overview

Attack Signatures are reusable rule sets that enhance defense profiles with specific threat detection patterns. They allow you to define blocking/flagging rules for known attack vectors without modifying the underlying defense profile logic.

Key features:
- **Modular patterns**: Define patterns separately from execution logic
- **Defense-specific sections**: Target rules to specific defense mechanisms
- **Priority-based merging**: Multiple signatures combine predictably
- **Built-in signatures**: Pre-configured for common threats (WordPress, API abuse, etc.)
- **Stats tracking**: Monitor signature match rates and effectiveness

## Architecture

### How Signatures Work with Defense Lines

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                          Defense Line Execution                              │
│                                                                             │
│  ┌──────────────────┐                                                       │
│  │ Defense Line     │                                                       │
│  │ - profile_id     │                                                       │
│  │ - signature_ids  │                                                       │
│  └────────┬─────────┘                                                       │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────────────────────────────────────────────────┐           │
│  │               Signature Resolution                            │           │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐                       │           │
│  │  │Sig 1    │  │Sig 2    │  │Sig 3    │  (sorted by priority) │           │
│  │  │pri: 50  │  │pri: 60  │  │pri: 70  │                       │           │
│  │  └─────────┘  └─────────┘  └─────────┘                       │           │
│  └──────────────────────────────────────────────────────────────┘           │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────────────────────────────────────────────────┐           │
│  │            Merge Signatures into Profile                      │           │
│  │                                                               │           │
│  │  For each defense node in profile:                           │           │
│  │    1. Collect matching sections from all signatures           │           │
│  │    2. Merge patterns (blocked_keywords, flagged_patterns...) │           │
│  │    3. Inject merged config into node.config.signature_patterns│           │
│  │                                                               │           │
│  └──────────────────────────────────────────────────────────────┘           │
│           │                                                                  │
│           ▼                                                                  │
│  ┌──────────────────────────────────────────────────────────────┐           │
│  │         Execute Modified Profile                              │           │
│  │                                                               │           │
│  │  Defense nodes check signature_patterns:                      │           │
│  │  - keyword_filter: checks blocked_keywords, flagged_keywords │           │
│  │  - fingerprint: checks blocked_user_agents, flagged_user_agents│          │
│  │  - expected_fields: checks required_fields, forbidden_fields │           │
│  │                                                               │           │
│  └──────────────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Signature Structure

### Complete Schema

```json
{
  "id": "custom_signature",
  "name": "Custom Signature Name",
  "description": "Description for UI and documentation",
  "enabled": true,
  "builtin": false,
  "priority": 100,

  "signatures": {
    "fingerprint": {
      "blocked_user_agents": ["BadBot", "Scraper"],
      "flagged_user_agents": [
        {"pattern": "python%-requests", "score": 20}
      ],
      "blocked_fingerprints": ["abc123"],
      "required_fingerprint_fields": ["user-agent"]
    },

    "keyword_filter": {
      "blocked_keywords": ["spam-word", "bad-phrase"],
      "flagged_keywords": [
        {"keyword": "suspicious", "score": 15}
      ],
      "blocked_patterns": ["<script>.*</script>"],
      "flagged_patterns": [
        {"pattern": "https?://[^%s]+%.ru/", "score": 25}
      ]
    },

    "expected_fields": {
      "required_fields": ["email", "name"],
      "forbidden_fields": ["cmd", "exec"],
      "optional_fields": ["phone"],
      "max_extra_fields": 5
    },

    "rate_limiter": {
      "requests_per_minute": 10,
      "requests_per_hour": 100,
      "burst_limit": 3
    }

    // ... more defense sections
  },

  "tags": ["custom", "web", "forms"]
}
```

### Defense Sections

Each signature can have sections targeting specific defense mechanisms:

| Section | Defense | Purpose |
|---------|---------|---------|
| `ip_allowlist` | ip_allowlist | Add allowed IPs/CIDRs |
| `geoip` | geoip | Block/flag countries, regions |
| `ip_reputation` | ip_reputation | Block CIDRs, ASNs |
| `timing_token` | timing_token | Time bounds |
| `behavioral` | behavioral | Interaction requirements |
| `honeypot` | honeypot | Custom honeypot fields |
| `keyword_filter` | keyword_filter | Keywords and patterns |
| `content_hash` | content_hash | Known spam hashes |
| `expected_fields` | expected_fields | Field validation |
| `pattern_scan` | pattern_scan | Content patterns |
| `disposable_email` | disposable_email | Email domain blocks |
| `field_anomalies` | field_anomalies | Field value rules |
| `fingerprint` | fingerprint | UA patterns, fingerprints |
| `header_consistency` | header_consistency | Required/forbidden headers |
| `rate_limiter` | rate_limiter | Rate limits |

### Section Details

#### fingerprint

```json
{
  "fingerprint": {
    "blocked_user_agents": [
      "WPScan",
      "nikto",
      "sqlmap"
    ],
    "flagged_user_agents": [
      {"pattern": "python%-requests", "score": 25},
      {"pattern": "^curl/", "score": 15}
    ],
    "blocked_fingerprints": ["known-bad-fp-hash"],
    "flagged_fingerprints": [
      {"fingerprint": "suspicious-fp", "score": 30}
    ],
    "required_fingerprint_fields": ["user-agent", "accept-language"]
  }
}
```

#### keyword_filter

```json
{
  "keyword_filter": {
    "blocked_keywords": [
      "<?php",
      "eval(",
      "base64_decode("
    ],
    "flagged_keywords": [
      {"keyword": "casino", "score": 40},
      {"keyword": "viagra", "score": 40},
      {"keyword": "click here", "score": 15}
    ],
    "blocked_patterns": [
      "\\[url=",
      "<a href="
    ],
    "flagged_patterns": [
      {"pattern": "https?://bit%.ly/", "score": 15},
      {"pattern": "\\$%d+", "score": 15}
    ]
  }
}
```

#### expected_fields

```json
{
  "expected_fields": {
    "required_fields": ["log", "pwd"],
    "forbidden_fields": ["cmd", "exec", "shell"],
    "optional_fields": ["rememberme", "redirect_to"],
    "max_extra_fields": 5
  }
}
```

#### rate_limiter

```json
{
  "rate_limiter": {
    "requests_per_second": 10,
    "requests_per_minute": 100,
    "requests_per_hour": 1000,
    "burst_limit": 20,
    "by_field": "user_id"
  }
}
```

#### disposable_email

```json
{
  "disposable_email": {
    "blocked_domains": [
      "tempmail.com",
      "guerrillamail.com",
      "mailinator.com"
    ],
    "allowed_domains": ["company.com"],
    "blocked_patterns": ["%+.*@"],
    "flagged_domains": [
      {"domain": "protonmail.com", "score": 5}
    ]
  }
}
```

#### behavioral

```json
{
  "behavioral": {
    "min_time_on_page_ms": 3000,
    "max_time_on_page_ms": 3600000,
    "require_mouse_movement": true,
    "require_keyboard_input": true,
    "require_scroll": true,
    "min_interaction_score": 10
  }
}
```

#### header_consistency

```json
{
  "header_consistency": {
    "required_headers": ["User-Agent", "Accept"],
    "forbidden_headers": ["X-Scanner", "X-Attack"],
    "header_rules": [
      {"header": "Content-Type", "pattern": "application/json"}
    ]
  }
}
```

## Built-in Signatures

### 1. WordPress Login Protection
**ID:** `builtin_wordpress_login` | **Priority:** 50

Blocks WordPress scanning tools, brute force bots, and credential stuffing attacks.

**Defenses used:**
- `fingerprint`: Block WPScan, nikto, sqlmap
- `keyword_filter`: Block PHP injection attempts
- `expected_fields`: Require log/pwd fields
- `rate_limiter`: 5/min, 30/hour
- `header_consistency`: Require User-Agent

### 2. WordPress Registration Spam
**ID:** `builtin_wordpress_register` | **Priority:** 50

Blocks automated registration bots and spam signups.

**Defenses used:**
- `fingerprint`: Block headless browsers
- `keyword_filter`: Spam content indicators
- `disposable_email`: Block temp email domains
- `pattern_scan`: Suspicious URLs
- `behavioral`: Require human interaction
- `rate_limiter`: 3/min, 10/hour

### 3. WordPress XML-RPC Protection
**ID:** `builtin_wordpress_xmlrpc` | **Priority:** 40

Protects against XML-RPC abuse, pingback attacks, and DDoS amplification.

**Defenses used:**
- `keyword_filter`: Block dangerous methods (system.multicall, pingback.ping)
- `pattern_scan`: Detect brute force patterns
- `rate_limiter`: 10/min, 60/hour
- `header_consistency`: Require Content-Type

### 4. WordPress Comment Spam
**ID:** `builtin_wordpress_comments` | **Priority:** 60

Blocks automated comment spam and trackback abuse.

**Defenses used:**
- `keyword_filter`: Spam indicators (casino, viagra, etc.)
- `pattern_scan`: Multiple URLs, repeated text
- `behavioral`: Require article reading time
- `honeypot`: Custom comment honeypot fields
- `rate_limiter`: 5/min, 20/hour

### 5. Contact Form Spam Protection
**ID:** `builtin_contact_form_spam` | **Priority:** 70

Generic protection for contact forms.

**Defenses used:**
- `keyword_filter`: SEO spam, sales pitches
- `pattern_scan`: URLs, money mentions
- `disposable_email`: Block temp domains
- `behavioral`: Require page interaction
- `honeypot`: Generic form honeypots
- `rate_limiter`: 3/min, 15/hour

### 6. API Abuse Protection
**ID:** `builtin_api_abuse` | **Priority:** 30

Protects API endpoints from scraping and enumeration.

**Defenses used:**
- `fingerprint`: Flag automation tools
- `rate_limiter`: 10/sec, 100/min, 1000/hour
- `header_consistency`: Require Content-Type application/json

### 7. Credential Stuffing Protection
**ID:** `builtin_credential_stuffing` | **Priority:** 20

Generic protection against credential stuffing attacks.

**Defenses used:**
- `fingerprint`: Block headless browsers
- `rate_limiter`: 3/min, 20/hour (very strict)
- `behavioral`: Require keyboard input
- `header_consistency`: Require browser headers

## Pattern Matching

### Regex Syntax

Attack signatures use Lua pattern matching. Key differences from standard regex:

| Pattern | Meaning |
|---------|---------|
| `.` | Any character |
| `%a` | Any letter |
| `%d` | Any digit |
| `%s` | Any whitespace |
| `%w` | Any alphanumeric |
| `%-` | Literal hyphen (escaped) |
| `%.` | Literal dot (escaped) |
| `%+` | Literal plus (escaped) |
| `*` | 0 or more (greedy) |
| `+` | 1 or more (greedy) |
| `?` | 0 or 1 |
| `[...]` | Character class |
| `[^...]` | Negated class |

### Examples

```lua
-- Match python-requests user agent
"python%-requests"

-- Match any .ru domain
"https?://[^%s]+%.ru/"

-- Match URL shorteners
"https?://bit%.ly/"

-- Match BBCode links
"\\[url="

-- Match money amounts
"\\$%d+"

-- Match PHP injection
"<%?php"
```

## Merging Strategy

When multiple signatures are attached to a defense line, their sections are merged:

### List Fields (Additive)

Lists are concatenated:

```lua
-- Signature 1
blocked_keywords = {"word1", "word2"}

-- Signature 2
blocked_keywords = {"word3", "word4"}

-- Merged result
blocked_keywords = {"word1", "word2", "word3", "word4"}
```

### Numeric Fields (Most Restrictive)

Numbers use the most restrictive value:

```lua
-- Signature 1
requests_per_minute = 100

-- Signature 2
requests_per_minute = 50

-- Merged result (lower = more restrictive)
requests_per_minute = 50
```

### Boolean Fields (OR)

Booleans use OR (true if any is true):

```lua
-- Signature 1
require_mouse_movement = false

-- Signature 2
require_mouse_movement = true

-- Merged result
require_mouse_movement = true
```

## Stats Tracking

Attack signatures track match statistics for monitoring:

```
waf:signature_stats:{signature_id}:total      -- Total matches
waf:signature_stats:{signature_id}:blocked    -- Blocked matches
waf:signature_stats:{signature_id}:flagged    -- Flagged matches
waf:signature_stats:{signature_id}:last_match -- Last match timestamp
```

Query stats via API:

```
GET /api/attack-signatures/{id}/stats
```

Response:
```json
{
  "total_matches": 1234,
  "blocked": 456,
  "flagged": 778,
  "last_match": "2024-01-15T10:30:00Z"
}
```

## API Reference

### List Signatures

```
GET /api/attack-signatures
```

Response:
```json
{
  "signatures": [
    {
      "id": "builtin_wordpress_login",
      "name": "WordPress Login Protection",
      "builtin": true,
      "enabled": true,
      "priority": 50,
      "tags": ["wordpress", "login", "brute-force"]
    }
  ]
}
```

### Get Signature

```
GET /api/attack-signatures/{id}
```

### Create Signature

```
POST /api/attack-signatures
Content-Type: application/json

{
  "id": "custom_signature",
  "name": "Custom Signature",
  "signatures": { ... },
  "tags": ["custom"]
}
```

### Update Signature

```
PUT /api/attack-signatures/{id}
```

### Delete Signature

```
DELETE /api/attack-signatures/{id}
```

Note: Built-in signatures cannot be deleted.

### Toggle Signature

```
POST /api/attack-signatures/{id}/enable
POST /api/attack-signatures/{id}/disable
```

## Redis Storage

```redis
# Signature index
ZADD waf:attack_signatures:index 50 "builtin_wordpress_login" 70 "builtin_contact_form_spam"

# Signature configuration
SET waf:attack_signatures:config:builtin_wordpress_login '{"id":"builtin_wordpress_login",...}'

# Builtin version tracking
SET waf:attack_signatures:builtin_version "1"

# Stats (in shared memory, periodically synced)
SET waf:signature_stats:builtin_wordpress_login:total "1234"
SET waf:signature_stats:builtin_wordpress_login:last_match "1705312200"
```

## Creating Custom Signatures

### Step 1: Identify the threat

Determine which attack vector you want to protect against:
- What patterns appear in malicious requests?
- Which fields are targeted?
- What user agents are used?

### Step 2: Choose defense sections

Select appropriate defense mechanisms:
- Use `fingerprint` for user agent patterns
- Use `keyword_filter` for content patterns
- Use `rate_limiter` for velocity controls
- Use `behavioral` for bot detection

### Step 3: Define patterns

Create specific patterns:

```json
{
  "id": "custom_scanner_protection",
  "name": "Custom Scanner Protection",
  "enabled": true,
  "priority": 45,

  "signatures": {
    "fingerprint": {
      "blocked_user_agents": [
        "CustomScanner/1.0",
        "BadBot"
      ],
      "flagged_user_agents": [
        {"pattern": "scanner", "score": 30}
      ]
    },
    "keyword_filter": {
      "blocked_keywords": ["dangerous-payload"],
      "blocked_patterns": ["<script>.*alert"]
    },
    "rate_limiter": {
      "requests_per_minute": 5
    }
  },

  "tags": ["custom", "scanner", "xss"]
}
```

### Step 4: Test in monitoring mode

1. Create the signature
2. Attach to endpoint via defense line
3. Set endpoint to monitoring mode
4. Monitor signature match stats
5. Adjust patterns based on results

### Step 5: Enable blocking

Once confident in the patterns:
1. Switch endpoint to blocking mode
2. Monitor for false positives
3. Adjust as needed

## Best Practices

### Pattern Design

1. **Be specific**: Avoid overly broad patterns that cause false positives
2. **Escape properly**: Use `%` for Lua pattern escapes
3. **Test patterns**: Verify against known good and bad inputs
4. **Document purpose**: Add descriptions explaining what each pattern catches

### Performance

1. **Limit signature count**: Each signature adds processing overhead
2. **Use blocked over flagged**: Blocked patterns short-circuit faster
3. **Order by priority**: Put most specific/strict signatures first
4. **Monitor execution time**: Check logs for slow patterns

### Maintenance

1. **Review stats regularly**: Identify unused or ineffective signatures
2. **Update patterns**: Attack patterns evolve - update accordingly
3. **Tag consistently**: Use tags for organization and filtering
4. **Version control**: Store signatures in version control for history
