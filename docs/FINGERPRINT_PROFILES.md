# Fingerprint Profiles

Fingerprint profiles provide advanced client identification and behavioral control based on browser characteristics, request headers, and form submission patterns.

> **Note:** This document covers **Fingerprint Profiles** - a system for classifying clients (browsers, bots, mobile apps) based on headers. This is separate from the **Fingerprint Defense Node** in [Defense Profiles](DEFENSE_PROFILES.md), which uses fingerprint data as one check within a defense DAG. Fingerprint Profiles run early to classify the client; the fingerprint defense node runs later within a profile's execution flow.

---

## Table of Contents

1. [Overview](#overview)
2. [How Fingerprinting Works](#how-fingerprinting-works)
3. [Built-in Profiles](#built-in-profiles)
4. [Creating Custom Profiles](#creating-custom-profiles)
5. [Profile Matching](#profile-matching)
6. [Fingerprint Generation](#fingerprint-generation)
7. [Rate Limiting by Fingerprint](#rate-limiting-by-fingerprint)
8. [API Reference](#api-reference)
9. [Configuration Examples](#configuration-examples)

---

## Overview

Fingerprint profiles allow you to:

- **Identify client types** based on headers (browsers, bots, mobile apps)
- **Apply different actions** per client type (allow, block, flag, ignore)
- **Generate unique fingerprints** for rate limiting across IP changes
- **Customize scoring** based on client behavior patterns

### Use Cases

| Scenario | Solution |
|----------|----------|
| Block known bot signatures | Create profile matching bot User-Agent patterns |
| Allow trusted mobile apps | Create profile for app-specific headers |
| Rate limit by browser fingerprint | Enable fingerprint-based rate limiting |
| Ignore internal monitoring | Create profile for health check user agents |

---

## How Fingerprinting Works

```
Request arrives
      ↓
┌─────────────────────────────────────┐
│ 1. Extract headers for matching     │
│    (User-Agent, Accept-Language,    │
│     custom headers, etc.)           │
└─────────────────────────────────────┘
      ↓
┌─────────────────────────────────────┐
│ 2. Match against profiles           │
│    (sorted by priority, highest     │
│     priority = lowest number)       │
└─────────────────────────────────────┘
      ↓
┌─────────────────────────────────────┐
│ 3. Apply profile action             │
│    - allow: proceed normally        │
│    - block: reject request          │
│    - flag: add score, continue      │
│    - ignore: skip WAF checks        │
└─────────────────────────────────────┘
      ↓
┌─────────────────────────────────────┐
│ 4. Generate fingerprint             │
│    (hash of configured headers +    │
│     form field values)              │
└─────────────────────────────────────┘
      ↓
┌─────────────────────────────────────┐
│ 5. Apply fingerprint rate limiting  │
│    (if enabled for the profile)     │
└─────────────────────────────────────┘
```

---

## Built-in Profiles

The WAF includes several built-in profiles that cover common scenarios:

### modern-browser

Matches modern desktop and mobile browsers.

```json
{
  "id": "modern-browser",
  "name": "Modern Browser",
  "priority": 100,
  "action": "allow",
  "matching": {
    "match_mode": "all",
    "conditions": [
      {"header": "User-Agent", "condition": "present"},
      {"header": "Accept-Language", "condition": "present"},
      {"header": "Accept-Encoding", "condition": "matches", "pattern": "gzip"}
    ]
  }
}
```

### legacy-browser

Matches older browsers with relaxed requirements.

```json
{
  "id": "legacy-browser",
  "name": "Legacy Browser",
  "priority": 200,
  "action": "allow",
  "score": 5,
  "matching": {
    "match_mode": "all",
    "conditions": [
      {"header": "User-Agent", "condition": "present"}
    ]
  }
}
```

### known-bot

Matches known search engine and service bots. These are ignored by the WAF.

```json
{
  "id": "known-bot",
  "name": "Known Bot",
  "priority": 50,
  "action": "ignore",
  "matching": {
    "match_mode": "any",
    "conditions": [
      {"header": "User-Agent", "condition": "matches", "pattern": "(?i)(googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|facebookexternalhit|twitterbot|linkedinbot|applebot)"}
    ]
  }
}
```

### headless-browser

Matches headless browser automation tools.

```json
{
  "id": "headless-browser",
  "name": "Headless Browser",
  "priority": 120,
  "action": "flag",
  "score": 25,
  "matching": {
    "match_mode": "any",
    "conditions": [
      {"header": "User-Agent", "condition": "matches", "pattern": "(?i)(headlesschrome|phantomjs|puppeteer|playwright|selenium|webdriver)"}
    ]
  }
}
```

### suspicious-bot

Matches command-line tools and scripting libraries.

```json
{
  "id": "suspicious-bot",
  "name": "Suspicious Bot",
  "priority": 150,
  "action": "flag",
  "score": 30,
  "matching": {
    "match_mode": "any",
    "conditions": [
      {"header": "User-Agent", "condition": "matches", "pattern": "(?i)(curl|wget|python-requests|python-urllib|java|httpclient|okhttp|axios|node-fetch|go-http-client|ruby|perl|libwww)"}
    ]
  }
}
```

### no-user-agent

Matches requests with no User-Agent header (highly suspicious).

```json
{
  "id": "no-user-agent",
  "name": "No User-Agent",
  "priority": 300,
  "action": "flag",
  "score": 40,
  "matching": {
    "match_mode": "all",
    "conditions": [
      {"header": "User-Agent", "condition": "absent"}
    ]
  }
}
```

---

## Creating Custom Profiles

### Profile Structure

```json
{
  "id": "my-custom-profile",
  "name": "My Custom Profile",
  "description": "Matches requests from our mobile app",
  "enabled": true,
  "priority": 75,
  "action": "allow",
  "score": 0,
  "matching": {
    "match_mode": "all",
    "conditions": [
      {
        "header": "X-App-Version",
        "condition": "present"
      },
      {
        "header": "User-Agent",
        "condition": "matches",
        "pattern": "MyApp/[0-9]+"
      }
    ]
  },
  "fingerprint_headers": {
    "headers": ["User-Agent", "X-App-Version", "X-Device-ID"],
    "normalize": true,
    "max_length": 100,
    "include_field_names": true
  },
  "rate_limiting": {
    "enabled": true,
    "fingerprint_rate_limit": 30
  }
}
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier (alphanumeric, hyphens, underscores) |
| `name` | string | Yes | Display name |
| `description` | string | No | Optional description |
| `enabled` | boolean | No | Enable/disable profile (default: true) |
| `priority` | number | No | Matching priority, lower = higher priority (default: 500) |
| `action` | string | No | Action on match: allow, block, flag, ignore (default: allow) |
| `score` | number | No | Spam score to add when matched (default: 0) |
| `matching` | object | No | Matching conditions |
| `fingerprint_headers` | object | No | Headers to include in fingerprint |
| `rate_limiting` | object | No | Per-fingerprint rate limiting |

### Matching Conditions

Each condition specifies a header and how to match it:

| Condition | Description | Pattern Required |
|-----------|-------------|------------------|
| `present` | Header must exist | No |
| `absent` | Header must not exist | No |
| `matches` | Header value matches regex pattern | Yes |
| `not_matches` | Header value does not match pattern | Yes |

### Match Modes

- `all` - All conditions must match (AND logic)
- `any` - At least one condition must match (OR logic)

---

## Profile Matching

### Priority Order

Profiles are evaluated in priority order (lowest number first):

```
Priority 50:  known-bot        → matches Googlebot, ignores WAF
Priority 75:  my-mobile-app    → matches app header, allows
Priority 100: modern-browser   → matches normal browsers
Priority 120: headless-browser → matches automation
Priority 150: suspicious-bot   → matches curl/wget
Priority 200: legacy-browser   → fallback for old browsers
```

### First Match Wins

The first profile that matches determines the action. If no profile matches, the endpoint's `no_match_action` setting applies:

- `use_default` - Apply default scoring (adds `no_match_score` points)
- `allow` - Allow the request
- `block` - Block the request
- `flag` - Flag for review

---

## Fingerprint Generation

Fingerprints are SHA-256 hashes combining:

1. **Header values** - Configured headers from the request
2. **Form field values** - Configured form fields (optional)

### Header Selection

Configure which headers contribute to the fingerprint:

```json
{
  "fingerprint_headers": {
    "headers": [
      "User-Agent",
      "Accept-Language",
      "Accept-Encoding"
    ],
    "normalize": true,
    "max_length": 100,
    "include_field_names": true
  }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `headers` | UA, Accept-Language, Accept-Encoding | Headers to hash |
| `normalize` | true | Lowercase and trim values |
| `max_length` | 100 | Truncate long values |
| `include_field_names` | true | Include header names in hash |

### Example Fingerprint

For a request with:
- User-Agent: `Mozilla/5.0 Chrome/120`
- Accept-Language: `en-US,en`
- Accept-Encoding: `gzip, deflate, br`

Fingerprint input (with `include_field_names: true`):
```
User-Agent:mozilla/5.0 chrome/120|Accept-Language:en-us,en|Accept-Encoding:gzip, deflate, br
```

Resulting fingerprint: `a7f3b2c1d4e5...` (SHA-256 hash)

---

## Rate Limiting by Fingerprint

Fingerprint-based rate limiting tracks requests per unique fingerprint, independent of IP address:

```json
{
  "rate_limiting": {
    "enabled": true,
    "fingerprint_rate_limit": 20
  }
}
```

### Why Use Fingerprint Rate Limiting?

| Scenario | IP Rate Limiting | Fingerprint Rate Limiting |
|----------|-----------------|---------------------------|
| User behind NAT/proxy | Blocks all users sharing IP | Limits each user individually |
| Bot rotating IPs | Ineffective | Tracks bot across IP changes |
| Mobile users changing networks | May block legitimate users | Consistent tracking |

### How It Works

1. Generate fingerprint from request headers
2. Increment counter in HAProxy stick-table: `fp_rate:<fingerprint>`
3. If count exceeds `fingerprint_rate_limit`, block request
4. Counter resets every minute

---

## API Reference

### List Profiles

```
GET /api/fingerprint-profiles
```

Response:
```json
{
  "profiles": [
    {"id": "modern-browser", "name": "Modern Browser", "builtin": true, ...},
    {"id": "my-custom", "name": "My Custom", "builtin": false, ...}
  ]
}
```

### Get Profile

```
GET /api/fingerprint-profiles/:id
```

### Create Profile

```
POST /api/fingerprint-profiles
Content-Type: application/json

{
  "id": "my-new-profile",
  "name": "My New Profile",
  "priority": 150,
  "action": "flag",
  "score": 20,
  "matching": {...}
}
```

### Update Profile

```
PUT /api/fingerprint-profiles/:id
Content-Type: application/json

{
  "name": "Updated Name",
  "priority": 100
}
```

### Delete Profile

```
DELETE /api/fingerprint-profiles/:id
```

Note: Built-in profiles cannot be deleted.

### Reset Built-in Profiles

```
POST /api/fingerprint-profiles/reset-builtin
```

Restores all built-in profiles to their default configuration.

### Test Profile Matching

```
POST /api/fingerprint-profiles/test
Content-Type: application/json

{
  "headers": {
    "User-Agent": "Mozilla/5.0...",
    "Accept-Language": "en-US"
  },
  "profiles": ["modern-browser", "suspicious-bot"],
  "form_fields": {"email": "test@example.com"}
}
```

Response:
```json
{
  "matched_profiles": [
    {"id": "modern-browser", "priority": 100, "action": "allow"}
  ],
  "result": {
    "blocked": false,
    "total_score": 0,
    "fingerprint": "a7f3b2c1..."
  }
}
```

---

## Configuration Examples

### Example 1: Block Aggressive Scrapers

```json
{
  "id": "aggressive-scraper",
  "name": "Aggressive Scraper",
  "priority": 80,
  "action": "block",
  "matching": {
    "match_mode": "any",
    "conditions": [
      {"header": "User-Agent", "condition": "matches", "pattern": "scrapy|mechanize|aiohttp"},
      {"header": "Accept", "condition": "absent"}
    ]
  }
}
```

### Example 2: Allow Trusted Partner API

```json
{
  "id": "partner-api",
  "name": "Partner API",
  "priority": 25,
  "action": "ignore",
  "matching": {
    "match_mode": "all",
    "conditions": [
      {"header": "X-Partner-Key", "condition": "present"},
      {"header": "X-Partner-Key", "condition": "matches", "pattern": "^pk_[a-zA-Z0-9]{32}$"}
    ]
  }
}
```

### Example 3: Flag Missing Referer

```json
{
  "id": "no-referer",
  "name": "Missing Referer",
  "priority": 180,
  "action": "flag",
  "score": 15,
  "matching": {
    "match_mode": "all",
    "conditions": [
      {"header": "Referer", "condition": "absent"},
      {"header": "User-Agent", "condition": "present"}
    ]
  }
}
```

### Example 4: Endpoint-Specific Profiles

Apply specific profiles to an endpoint:

```json
{
  "id": "contact-form",
  "name": "Contact Form",
  "fingerprint_profiles": {
    "enabled": true,
    "profiles": ["modern-browser", "legacy-browser"],
    "no_match_action": "flag",
    "no_match_score": 20
  }
}
```

---

## Admin UI

The Fingerprint Profiles page in the Admin UI provides:

- **Profile List** - View all profiles with status, priority, and actions
- **Create/Edit** - Visual editor for profile configuration
- **Test Tool** - Test headers against profiles to see matching results
- **Reset Built-ins** - Restore default built-in profiles

Access via: **Security → Fingerprint Profiles** in the sidebar.
