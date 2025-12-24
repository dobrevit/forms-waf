# Defense Profiles System

## Overview

Defense Profiles provide a flexible, DAG-based (Directed Acyclic Graph) system for orchestrating WAF defense mechanisms. Instead of a fixed pipeline, you can configure custom execution flows with branching logic, score aggregation, and multiple response actions.

Key features:
- **DAG-based execution**: Define defense flows as graphs with nodes and edges
- **Multiple profile support**: Attach multiple profiles to endpoints with priority ordering
- **Parallel execution**: Profiles execute concurrently for better performance
- **Built-in profiles**: Pre-configured profiles for common use cases
- **Attack signature integration**: Combine profiles with attack signatures via Defense Lines

## Architecture

### Execution Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Request Processing                                 │
│                                                                             │
│  ┌──────────┐    ┌─────────────────────────┐    ┌──────────────────────┐   │
│  │ Incoming │───▶│   Endpoint Resolution   │───▶│  Profile Selection   │   │
│  │ Request  │    │ (vhost_resolver.lua)    │    │                      │   │
│  └──────────┘    └─────────────────────────┘    └──────────────────────┘   │
│                                                            │                │
│                                                            ▼                │
│                  ┌─────────────────────────────────────────────────┐       │
│                  │          Multi-Profile Executor                  │       │
│                  │      (defense_profile_multi_executor.lua)        │       │
│                  │                                                  │       │
│                  │  ┌──────────┐  ┌──────────┐  ┌──────────┐       │       │
│                  │  │Profile 1 │  │Profile 2 │  │Profile 3 │       │       │
│                  │  │(priority │  │(priority │  │(priority │       │       │
│                  │  │  100)    │  │  200)    │  │  300)    │       │       │
│                  │  └────┬─────┘  └────┬─────┘  └────┬─────┘       │       │
│                  │       │             │             │              │       │
│                  │       └─────────────┼─────────────┘              │       │
│                  │                     ▼                            │       │
│                  │           ┌─────────────────┐                    │       │
│                  │           │   Aggregation   │                    │       │
│                  │           │ (OR/AND/MAJORITY│                    │       │
│                  │           └─────────────────┘                    │       │
│                  └─────────────────────────────────────────────────┘       │
│                                        │                                    │
│                                        ▼                                    │
│                  ┌─────────────────────────────────────────────────┐       │
│                  │            Defense Lines (Optional)              │       │
│                  │      Profiles + Attack Signatures merged         │       │
│                  └─────────────────────────────────────────────────┘       │
│                                        │                                    │
│                                        ▼                                    │
│                  ┌─────────────────────────────────────────────────┐       │
│                  │              Final Action                        │       │
│                  │    (allow / block / captcha / tarpit)           │       │
│                  └─────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Single Profile Execution (DAG)

Each profile is executed as a directed acyclic graph:

```
┌───────┐     ┌────────────┐     ┌────────────┐     ┌─────────────┐
│ Start │────▶│ IP Allow   │────▶│   GeoIP    │────▶│ IP Reputa-  │
└───────┘     │   list     │     │            │     │   tion      │
              └────────────┘     └────────────┘     └─────────────┘
                  │ allowed           │ blocked            │ blocked
                  ▼                   ▼                    ▼
              ┌───────┐         ┌──────────┐         ┌──────────┐
              │ ALLOW │         │  BLOCK   │         │  BLOCK   │
              └───────┘         └──────────┘         └──────────┘
                                                           │ continue
                                                           ▼
              ┌──────────────────────────────────────────────────┐
              │                Content Checks                     │
              │  Honeypot → Keywords → Hash → Fields → Patterns  │
              └──────────────────────────────────────────────────┘
                                     │
                                     ▼
              ┌──────────────────────────────────────────────────┐
              │              Sum Operator                         │
              │         (aggregate all scores)                    │
              └──────────────────────────────────────────────────┘
                                     │
                                     ▼
              ┌──────────────────────────────────────────────────┐
              │           Threshold Branch                        │
              │   score < 50: allow                              │
              │   score 50-80: captcha                           │
              │   score >= 80: block                             │
              └──────────────────────────────────────────────────┘
```

## Node Types

### 1. Start Node

Entry point for graph execution. Every profile must have exactly one start node.

```json
{
  "id": "start",
  "type": "start",
  "position": {"x": 50, "y": 300},
  "outputs": {"next": "ip_allowlist"}
}
```

### 2. Defense Nodes

Execute a registered defense mechanism against the request.

```json
{
  "id": "honeypot",
  "type": "defense",
  "defense": "honeypot",
  "position": {"x": 650, "y": 300},
  "config": {
    "action": "block",
    "score": 50
  },
  "outputs": {
    "blocked": "action_block",
    "continue": "keyword_filter"
  }
}
```

**Available defenses:**

| Defense | Description | Outputs |
|---------|-------------|---------|
| `ip_allowlist` | Check if IP is in allowlist | `allowed`, `continue` |
| `geoip` | Geographic and ASN filtering | `blocked`, `continue` |
| `ip_reputation` | IP reputation databases | `blocked`, `continue` |
| `timing_token` | Form fill timing validation | `continue` |
| `behavioral` | User behavior analysis | `continue` |
| `honeypot` | Hidden field detection | `blocked`, `continue` |
| `keyword_filter` | Keyword scanning | `blocked`, `continue` |
| `content_hash` | Duplicate content detection | `blocked`, `continue` |
| `expected_fields` | Field validation | `blocked`, `continue` |
| `pattern_scan` | Regex pattern matching | `continue` |
| `disposable_email` | Temporary email detection | `blocked`, `continue` |
| `field_anomalies` | Bot-like patterns | `continue` |
| `fingerprint` | Client fingerprinting (uses [Fingerprint Profiles](FINGERPRINT_PROFILES.md) data) | `blocked`, `continue` |
| `header_consistency` | Browser header validation | `continue` |
| `rate_limiter` | Rate limiting | `blocked`, `continue` |

### 3. Operator Nodes

Aggregate or transform results from defense nodes.

**Sum Operator**
```json
{
  "id": "sum_all",
  "type": "operator",
  "operator": "sum",
  "position": {"x": 1050, "y": 300},
  "inputs": ["timing_token", "behavioral", "honeypot", "keyword_filter"],
  "outputs": {"next": "threshold_check"}
}
```

**Threshold Branch Operator**
```json
{
  "id": "threshold_check",
  "type": "operator",
  "operator": "threshold_branch",
  "position": {"x": 1150, "y": 300},
  "config": {
    "ranges": [
      {"min": 0, "max": 50, "output": "low"},
      {"min": 50, "max": 80, "output": "medium"},
      {"min": 80, "max": null, "output": "high"}
    ]
  },
  "outputs": {
    "low": "action_allow",
    "medium": "action_captcha",
    "high": "action_block"
  }
}
```

**Available operators:**

| Operator | Description |
|----------|-------------|
| `sum` | Add scores from all inputs |
| `max` | Take highest score |
| `min` | Take lowest score |
| `threshold_branch` | Route based on score ranges |
| `and` | All inputs must be true |
| `or` | Any input can be true |

### 4. Observation Nodes

Record data without affecting scoring or blocking decisions.

```json
{
  "id": "field_learner",
  "type": "observation",
  "observation": "field_learner",
  "position": {"x": 1300, "y": 400},
  "outputs": {"continue": "fingerprint"}
}
```

**Available observations:**

| Observation | Description |
|-------------|-------------|
| `field_learner` | Records field names for automatic discovery |

### 5. Action Nodes

Terminal nodes that determine the final response.

```json
{
  "id": "action_block",
  "type": "action",
  "action": "block",
  "position": {"x": 1500, "y": 500},
  "config": {"reason": "spam_detected"}
}
```

**Available actions:**

| Action | Description | Config |
|--------|-------------|--------|
| `allow` | Pass request to backend | - |
| `block` | Return HTTP 403 | `reason` |
| `tarpit` | Delay then block | `delay_seconds`, `then_action` |
| `captcha` | Serve CAPTCHA challenge | `provider` |
| `flag` | Mark for review, continue | `reason`, `score` |
| `monitor` | Log but don't block | - |

## Built-in Profiles

### 1. Legacy (Backward Compatible)
**ID:** `legacy` | **Priority:** 1000

Mirrors the original waf_handler.lua execution order. Use for migration compatibility.

Execution: IP Allowlist → GeoIP → IP Reputation → Timing → Behavioral → Honeypot → Keywords → Hash → Expected Fields → Patterns → Disposable Email → Field Anomalies → Field Learner → Fingerprint → Sum → Threshold (80)

### 2. Balanced Web Protection
**ID:** `balanced-web` | **Priority:** 100

Balanced protection for web forms with CAPTCHA for medium scores.

Features:
- Early exit on high IP risk scores
- CAPTCHA for scores 50-80
- Block for scores >= 80

### 3. Strict API Protection
**ID:** `strict-api` | **Priority:** 50

High-security profile for API endpoints using tarpit for suspicious requests.

Features:
- IP reputation first (most effective for API abuse)
- 10-second tarpit for bad IP reputation
- Strict thresholds (40/70/100)
- 50ms max execution time

### 4. Permissive (Low Security)
**ID:** `permissive` | **Priority:** 200

Minimal protection for high-traffic, low-risk pages.

Features:
- Only critical checks (IP reputation, honeypot, keywords, hash)
- High threshold (120)
- 30ms max execution time

### 5. High-Value Transaction Protection
**ID:** `high-value` | **Priority:** 25

Maximum protection for payment and signup forms.

Features:
- All defense mechanisms enabled
- Multi-stage thresholds (30/50/80/120)
- 10-second tarpit for high scores
- 150ms max execution time

### 6. Monitor Only (No Blocking)
**ID:** `monitor-only` | **Priority:** 900

Runs all checks but never blocks. For testing and observation.

Features:
- All blocked outputs route to sum instead of block
- Final action is always "monitor"
- Full scoring for metrics

## Multi-Profile Execution

### Attaching Multiple Profiles

Endpoints can have multiple profiles attached with priorities:

```json
{
  "id": "contact-form",
  "defense_profiles": {
    "enabled": true,
    "profiles": [
      {"id": "balanced-web", "priority": 100, "weight": 1.0},
      {"id": "strict-api", "priority": 50, "weight": 0.8}
    ],
    "aggregation": "OR",
    "score_aggregation": "SUM",
    "short_circuit": true
  }
}
```

### Aggregation Strategies

**Decision Aggregation** (`aggregation`):

| Strategy | Behavior |
|----------|----------|
| `OR` | Block if ANY profile blocks (default - safety first) |
| `AND` | Block only if ALL profiles block |
| `MAJORITY` | Block if >50% of profiles block |

**Score Aggregation** (`score_aggregation`):

| Strategy | Behavior |
|----------|----------|
| `SUM` | Add all profile scores together |
| `MAX` | Take the highest score |
| `WEIGHTED_AVG` | Weighted average based on profile weights |

### Short-Circuit Optimization

When `short_circuit: true`, if a profile blocks the request, remaining profiles are skipped:

```
Profile 1 (priority 50): block  ← Execution stops here
Profile 2 (priority 100): (not executed)
Profile 3 (priority 200): (not executed)
```

## Profile Configuration Schema

```json
{
  "id": "custom-profile",
  "name": "Custom Profile Name",
  "description": "Description for UI display",
  "enabled": true,
  "priority": 100,

  "graph": {
    "nodes": [
      {
        "id": "start",
        "type": "start",
        "position": {"x": 50, "y": 300},
        "outputs": {"next": "first_defense"}
      },
      {
        "id": "first_defense",
        "type": "defense",
        "defense": "ip_allowlist",
        "position": {"x": 150, "y": 300},
        "outputs": {
          "allowed": "action_allow",
          "continue": "next_defense"
        }
      }
      // ... more nodes
    ]
  },

  "settings": {
    "default_action": "allow",
    "max_execution_time_ms": 100
  }
}
```

### Node Position

Position is used by the visual editor UI for layout:
- `x`: Horizontal position in pixels
- `y`: Vertical position in pixels

### Profile Settings

| Setting | Default | Description |
|---------|---------|-------------|
| `default_action` | `allow` | Action when no terminal node reached |
| `max_execution_time_ms` | `100` | Max execution time before warning |

## Defense Lines

Defense Lines combine a base profile with attack signatures for specialized protection:

```json
{
  "id": "contact-form",
  "defense_lines": [
    {
      "enabled": true,
      "profile_id": "balanced-web",
      "signature_ids": ["builtin_contact_form_spam", "builtin_credential_stuffing"]
    }
  ]
}
```

Defense Lines are executed AFTER base profiles pass. If any line blocks, the request is blocked.

See [ATTACK_SIGNATURES.md](ATTACK_SIGNATURES.md) for details on signature configuration.

## API Reference

### List Profiles

```
GET /api/defense-profiles
```

Response:
```json
{
  "profiles": [
    {
      "id": "balanced-web",
      "name": "Balanced Web Protection",
      "builtin": true,
      "enabled": true,
      "priority": 100
    }
  ]
}
```

### Get Profile

```
GET /api/defense-profiles/{id}
```

### Create Profile

```
POST /api/defense-profiles
Content-Type: application/json

{
  "id": "custom-profile",
  "name": "Custom Profile",
  "graph": { ... },
  "settings": { ... }
}
```

### Update Profile

```
PUT /api/defense-profiles/{id}
```

### Delete Profile

```
DELETE /api/defense-profiles/{id}
```

Note: Built-in profiles cannot be deleted.

### Validate Profile

```
POST /api/defense-profiles/validate
Content-Type: application/json

{
  "graph": { ... }
}
```

Response:
```json
{
  "valid": true,
  "errors": []
}
```

Or:
```json
{
  "valid": false,
  "errors": [
    "Graph contains a cycle: start -> node1 -> node2 -> start",
    "Node 'xyz' output 'blocked' references non-existent node 'missing'"
  ]
}
```

## Redis Storage

```redis
# Profile index
ZADD waf:defense_profiles:index 100 "balanced-web" 50 "strict-api"

# Profile configuration
SET waf:defense_profiles:config:balanced-web '{"id":"balanced-web",...}'

# Builtin version tracking
SET waf:defense_profiles:builtin_version "3"
```

## Monitoring Mode Behavior

In monitoring mode (`mode: monitoring`), profiles execute fully but don't block:

1. All defense mechanisms run
2. Scores are calculated
3. `would_block_reasons` is populated
4. Final action is "allow" (or "monitor")
5. Headers include what would have been blocked

This allows testing profiles in production without affecting traffic.

## Creating Custom Profiles

### Step 1: Start with a base

Copy an existing built-in profile as a starting point:

```json
{
  "id": "my-custom",
  "name": "My Custom Profile",
  "extends": "balanced-web",
  "graph": {
    "nodes": [
      // Override or add nodes
    ]
  }
}
```

### Step 2: Customize nodes

Add, remove, or modify defense nodes:

```json
{
  "id": "extra_honeypot",
  "type": "defense",
  "defense": "honeypot",
  "config": {
    "field_names": ["custom_hp_field"],
    "action": "block"
  },
  "outputs": {
    "blocked": "action_block",
    "continue": "next_node"
  },
  "insert_after": "ip_allowlist"
}
```

### Step 3: Adjust thresholds

Modify threshold ranges for your use case:

```json
{
  "id": "threshold_check",
  "config": {
    "ranges": [
      {"min": 0, "max": 30, "output": "low"},      // More permissive
      {"min": 30, "max": 60, "output": "medium"},
      {"min": 60, "max": null, "output": "high"}   // Lower block threshold
    ]
  }
}
```

### Step 4: Validate and test

1. Use the validate API endpoint
2. Test in monitoring mode first
3. Review logs and metrics
4. Enable blocking mode when confident

## Performance Considerations

- **Parallel execution**: Multiple profiles run concurrently using ngx.thread
- **Short-circuit**: Enable to skip remaining profiles after a block
- **Max execution time**: Profiles exceeding limits are flagged but complete
- **Caching**: Defense results are cached within a request context

Typical execution times:
- Simple profile (5 nodes): 5-10ms
- Complex profile (15+ nodes): 20-50ms
- Multi-profile (3 profiles): 30-100ms
