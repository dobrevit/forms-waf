# Global Metrics Aggregation

This guide explains the distributed metrics aggregation system for multi-instance WAF deployments.

## Overview

The metrics system provides:
- **Local metrics** - Per-instance counters stored in shared dictionaries
- **Cluster metrics** - Aggregated metrics from all instances via Redis
- **Prometheus export** - Standard format for monitoring systems
- **Real-time dashboard** - Local and global metrics displayed side-by-side

## Architecture

```
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────┐
│   Instance 0    │   │   Instance 1    │   │   Instance 2    │
│  (LEADER)       │   │                 │   │                 │
│                 │   │                 │   │                 │
│  waf_metrics    │   │  waf_metrics    │   │  waf_metrics    │
│  (shared dict)  │   │  (shared dict)  │   │  (shared dict)  │
└────────┬────────┘   └────────┬────────┘   └────────┬────────┘
         │ push (30s)          │ push (30s)          │ push (30s)
         ▼                     ▼                     ▼
┌─────────────────────────────────────────────────────────────┐
│                         Redis                                │
│                                                              │
│  waf:metrics:instance:inst-0     waf:metrics:instance:inst-1 │
│  waf:metrics:instance:inst-2     waf:metrics:global          │
│                                                              │
└─────────────────────────────┬───────────────────────────────┘
                              │ aggregate (10s)
                              ▼
                     ┌─────────────────┐
                     │     Leader      │
                     │  aggregates all │
                     │  into :global   │
                     └─────────────────┘
```

---

## Local Metrics

### Shared Dictionary Storage

Local metrics are stored in the `waf_metrics` nginx shared dictionary:

```nginx
lua_shared_dict waf_metrics 10m;
```

### Metric Keys

Key format: `{prefix}:{vhost_id}:{endpoint_id}`

| Prefix | Metric | Description |
|--------|--------|-------------|
| `req_total:` | Total requests | All requests processed |
| `req_blocked:` | Blocked | Requests blocked by WAF |
| `req_monitored:` | Monitored | Would-block in monitor mode |
| `req_allowed:` | Allowed | Requests allowed through |
| `req_skipped:` | Skipped | WAF bypassed |
| `spam_score:` | Spam score sum | For average calculation (computed by [defense profiles](DEFENSE_PROFILES.md)) |
| `form_sub:` | Form submissions | POST form submissions |
| `val_err:` | Validation errors | Field validation failures |

### Recording Metrics

```lua
local metrics = require "metrics"

-- Record a request outcome
metrics.record_request(vhost_id, endpoint_id, "blocked", spam_score)

-- Increment specific counters
metrics.incr("form_submissions", vhost_id, endpoint_id)
metrics.incr("validation_errors", vhost_id, endpoint_id)
```

---

## Cluster Metrics

### Push Mechanism

Each instance pushes its local metrics to Redis every 30 seconds:

```lua
-- Called by instance_coordinator heartbeat timer
metrics.push_to_redis(instance_id, redis_connection)
```

The push uses a Redis transaction (MULTI/EXEC) for atomicity:

```
MULTI
HMSET waf:metrics:instance:{id} total_requests 1500 blocked_requests 45 ...
EXPIRE waf:metrics:instance:{id} 300
SETEX waf:metrics:instance:{id}:updated 300 {timestamp}
EXEC
```

### Aggregation (Leader Only)

The leader aggregates metrics every 10 seconds:

1. **SCAN** Redis for all `waf:metrics:instance:*` keys
2. **Pipeline** HMGET commands for efficiency
3. **Sum** all metric fields
4. **Write** to `waf:metrics:global`

```lua
-- Called by instance_coordinator leader maintenance timer
metrics.aggregate_global_metrics(redis_connection, active_instances)
```

### Metrics Fields Synced

```lua
local SYNC_FIELDS = {
    "total_requests",
    "blocked_requests",
    "monitored_requests",
    "allowed_requests",
    "skipped_requests",
    "form_submissions",
    "validation_errors"
}
```

---

## Redis Keys

### Instance Metrics

**Key:** `waf:metrics:instance:{instance_id}`

**Type:** Hash with TTL (300s)

```
total_requests: 1500
blocked_requests: 45
monitored_requests: 12
allowed_requests: 1443
skipped_requests: 0
form_submissions: 320
validation_errors: 5
```

### Instance Updated Timestamp

**Key:** `waf:metrics:instance:{instance_id}:updated`

**Type:** String with TTL (300s)

**Value:** Unix timestamp

### Global Aggregated Metrics

**Key:** `waf:metrics:global`

**Type:** Hash (no TTL)

```
total_requests: 4500
blocked_requests: 135
monitored_requests: 36
allowed_requests: 4329
skipped_requests: 0
form_submissions: 960
validation_errors: 15
instance_count: 3
```

### Global Updated Timestamp

**Key:** `waf:metrics:global:updated`

**Type:** String (no TTL)

**Value:** Unix timestamp

---

## API Access

### GET /api/metrics

Returns both local and global metrics:

```json
{
  "total_requests": 1500,
  "blocked_requests": 45,
  "monitored_requests": 12,
  "allowed_requests": 1443,
  "skipped_requests": 0,
  "form_submissions": 320,
  "validation_errors": 5,
  "by_vhost": {
    "my-vhost": {
      "total": 1200,
      "blocked": 40,
      "monitored": 10,
      "allowed": 1150
    }
  },
  "by_endpoint": {},
  "global": {
    "total_requests": 4500,
    "blocked_requests": 135,
    "monitored_requests": 36,
    "allowed_requests": 4329,
    "skipped_requests": 0,
    "form_submissions": 960,
    "validation_errors": 15,
    "instance_count": 3,
    "last_updated": "2024-12-19T10:30:15Z"
  }
}
```

### GET /metrics (Prometheus)

Standard Prometheus format:

```
# HELP waf_requests_total Total number of requests processed
# TYPE waf_requests_total counter
waf_requests_total{vhost="my-vhost",endpoint="_global"} 1500
waf_requests_total{vhost="_default",endpoint="_global"} 300

# HELP waf_requests_blocked_total Total number of blocked requests
# TYPE waf_requests_blocked_total counter
waf_requests_blocked_total{vhost="my-vhost",endpoint="_global"} 45

# HELP waf_shared_dict_bytes Shared dictionary memory usage
# TYPE waf_shared_dict_bytes gauge
waf_shared_dict_bytes{dict="waf_metrics"} 102400

# HELP waf_worker_count Total worker count
# TYPE waf_worker_count gauge
waf_worker_count 4
```

---

## Timing Configuration

| Setting | Value | Purpose |
|---------|-------|---------|
| Push interval | 30s | How often instances push to Redis |
| Aggregation interval | 10s | How often leader aggregates |
| Metrics TTL | 300s | When orphaned metrics expire |
| Leader cache TTL | 5s | Local cache of leader status |

---

## Dashboard Display

The Admin UI Dashboard shows local and global metrics side-by-side:

```
Total Requests
  150  |  4,500
 local   global

Blocked Requests
   5   |   135
 local   global

Cluster: 3 instances
Last updated: 10:30:15
```

When global metrics are unavailable (single instance or no leader):
- Only local metrics are shown
- No "global" column displayed
- Works seamlessly for single-instance deployments

---

## Handling Edge Cases

### Instance Restart

When an instance restarts:
1. Local metrics reset to 0
2. Old metrics in Redis persist until TTL expires
3. Aggregation includes metrics from old key until expiry
4. New metrics accumulate in new instance

This ensures metrics aren't lost during rolling updates.

### Leader Failover

When leader fails:
1. Global metrics become stale (show `last_updated` time)
2. New leader elected within ~30 seconds
3. New leader resumes aggregation
4. Dashboard shows fresh `last_updated` once resumed

### Network Partition

In a split-brain scenario:
- Each partition's leader aggregates its visible instances
- Metrics may be temporarily inconsistent
- Resolves automatically when partition heals

---

## Integration with Instance Coordinator

The metrics system integrates with `instance_coordinator.lua`:

### Heartbeat Timer (every 15s)

```lua
-- In heartbeat_timer_handler
if now - last_metrics_push >= METRICS_PUSH_INTERVAL then
    metrics.push_to_redis(INSTANCE_ID, red)
    last_metrics_push = now
end
```

### Leader Maintenance Timer (every 10s)

```lua
-- In leader_maintenance_handler
if is_leader then
    metrics.aggregate_global_metrics(red, active_instances)
end
```

---

## TypeScript Interface

```typescript
interface MetricsSummary {
  // Local metrics
  total_requests: number
  blocked_requests: number
  monitored_requests: number
  allowed_requests: number
  skipped_requests: number
  form_submissions: number
  validation_errors: number
  by_vhost: Record<string, VhostMetrics>
  by_endpoint: Record<string, EndpointMetrics>

  // Global metrics (optional - present in cluster deployments)
  global?: GlobalMetrics
}

interface GlobalMetrics {
  total_requests: number
  blocked_requests: number
  monitored_requests: number
  allowed_requests: number
  skipped_requests: number
  form_submissions: number
  validation_errors: number
  instance_count: number
  last_updated?: string  // ISO 8601 format
}
```

---

## Performance Considerations

### Redis Pipelining

Aggregation uses pipelining to minimize round trips:

```lua
red:init_pipeline()
for _, key in ipairs(metrics_keys) do
    red:hmget(key, unpack(SYNC_FIELDS))
end
local results = red:commit_pipeline()
```

### SCAN vs KEYS

Uses SCAN instead of KEYS to avoid blocking Redis:

```lua
local cursor = "0"
repeat
    local res = red:scan(cursor, "MATCH", pattern, "COUNT", 100)
    cursor = res[1]
    -- process res[2] (keys)
until cursor == "0"
```

### Atomic Transactions

Push uses MULTI/EXEC to prevent orphaned keys:

```lua
red:multi()
red:hmset(key, ...)
red:expire(key, TTL)
red:setex(updated_key, TTL, timestamp)
red:exec()
```

---

## Troubleshooting

### Global Metrics Missing

**Symptoms:** Dashboard shows only local metrics

**Causes:**
- No leader elected
- Redis connection issues
- Single instance deployment

**Solution:**
- Check `/api/cluster/status` for leader
- Verify Redis connectivity
- Global metrics are optional for single instance

### Stale Global Metrics

**Symptoms:** `last_updated` is old (> 30 seconds)

**Causes:**
- Leader not aggregating (crashed, network issues)
- Leader election in progress

**Solution:**
- Check leader health
- Wait for new leader election
- Manually verify with Redis CLI

### Metrics Drift Between Instances

**Symptoms:** Sum of local metrics != global metrics

**Causes:**
- Recent instance restart
- TTL hasn't expired on old metrics
- Aggregation timing

**Solution:**
- This is expected behavior during transitions
- Wait for TTL expiry (5 minutes)
- Metrics will converge

### Redis Memory

**Symptoms:** Redis memory growing

**Causes:**
- Many instances with long TTLs
- Keys not expiring

**Solution:**
- Check key count: `KEYS waf:metrics:instance:*`
- Verify TTLs: `TTL waf:metrics:instance:pod-0`
- Consider shorter TTL if needed
