# Cluster Coordination and Leader Election

This guide explains the distributed coordination system for multi-pod WAF deployments.

## Overview

The cluster coordination system provides:
- **Instance registration** - Track all running WAF instances
- **Heartbeat monitoring** - Detect failed or drifted instances
- **Leader election** - Single leader for cluster-wide tasks
- **Stale cleanup** - Automatic removal of dead instances
- **Task scheduling** - Run singleton tasks on the leader only

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Redis                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │ waf:cluster │  │ waf:cluster │  │ waf:cluster:leader  │ │
│  │ :instances  │  │ :instance:* │  │                     │ │
│  │ (HASH)      │  │ :heartbeat  │  │ (STRING + TTL)      │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└────────────────────────────────────┬────────────────────────┘
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         │                           │                           │
         ▼                           ▼                           ▼
   ┌───────────┐              ┌───────────┐              ┌───────────┐
   │ Instance  │              │ Instance  │              │ Instance  │
   │   pod-0   │              │   pod-1   │              │   pod-2   │
   │  (LEADER) │              │ (follower)│              │ (follower)│
   └───────────┘              └───────────┘              └───────────┘
```

## Instance Identification

Each instance is identified by:

1. **HOSTNAME environment variable** (preferred) - Set by Kubernetes StatefulSet
2. **Fallback:** `unknown-{worker_pid}` - Used in local development

```bash
# Kubernetes StatefulSet sets HOSTNAME automatically
HOSTNAME=forms-waf-openresty-0

# Or set manually in docker-compose
environment:
  - HOSTNAME=waf-instance-1
```

---

## Timing Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `HEARTBEAT_INTERVAL` | 15s | How often instances send heartbeats |
| `HEARTBEAT_TTL` | 90s | Redis key expiration (6x interval for tolerance) |
| `LEADER_TTL` | 30s | Leader key TTL |
| `LEADER_RENEW_INTERVAL` | 10s | How often leader renews TTL |
| `DRIFT_THRESHOLD` | 60s | Mark as "drifted" after 1 minute |
| `STALE_THRESHOLD` | 300s | Remove after 5 minutes |
| `METRICS_PUSH_INTERVAL` | 30s | Metrics sync to Redis |

---

## Instance States

| State | Condition | Action |
|-------|-----------|--------|
| `active` | Heartbeat within 60 seconds | Normal operation |
| `drifted` | Heartbeat 60-300 seconds ago | Warning logged, status updated |
| `down` | Heartbeat > 300 seconds ago | Removed from registry |

---

## Leader Election

### Algorithm

Leader election uses Redis atomic operations:

```
SET waf:cluster:leader {instance_id} NX PX 30000
```

- **NX** = Only set if key doesn't exist
- **PX 30000** = Expire in 30 seconds (auto-release on failure)

### Election Flow

1. Instance starts → registers in `waf:cluster:instances`
2. Instance checks if leader key exists
3. If no leader → attempt `SET NX PX`
4. If successful → instance becomes leader
5. Leader renews TTL every 10 seconds

### Failover

When a leader fails:
1. Leader key expires (30 seconds TTL)
2. Next instance heartbeat tries `SET NX`
3. First successful instance becomes new leader
4. Maximum failover time: ~30 seconds

---

## Redis Keys

### Instance Registry

**Key:** `waf:cluster:instances`

**Type:** Hash

```
{instance_id} → {
  "instance_id": "forms-waf-0",
  "started_at": 1734567890,
  "last_heartbeat": 1734567950,
  "status": "active",
  "worker_count": 4
}
```

### Instance Heartbeat

**Key:** `waf:cluster:instance:{instance_id}:heartbeat`

**Type:** String with TTL (90s)

**Value:** Unix timestamp of last heartbeat

### Leader Key

**Key:** `waf:cluster:leader`

**Type:** String with TTL (30s)

**Value:** Instance ID of current leader

### Leader Since

**Key:** `waf:cluster:leader:since`

**Type:** String (no TTL)

**Value:** Unix timestamp when leadership was acquired

---

## Leader-Only Tasks

The leader performs these cluster-wide tasks:

1. **Health Monitoring** - Check all instance heartbeats
2. **Stale Cleanup** - Remove instances down > 5 minutes
3. **Global Metrics Aggregation** - Combine metrics from all instances
4. **Registered Tasks** - Custom tasks scheduled via API

### Registering Leader Tasks

```lua
local coordinator = require "instance_coordinator"

-- Register a task to run on leader only
coordinator.register_for_leader_task(
    "my_cleanup_task",  -- Task name
    function()          -- Callback
        -- This runs only on the leader
        perform_cleanup()
    end,
    3600,              -- Interval in seconds (1 hour)
    60                 -- Initial delay (optional)
)
```

---

## Timers

### Heartbeat Timer (all instances, every 15s)

1. Update `waf:cluster:instance:{id}:heartbeat` with SETEX (90s TTL)
2. Update `last_heartbeat` in instance metadata
3. Push local metrics to Redis (every 30s)

### Leader Maintenance Timer (leader only, every 10s)

1. Check if still leader
2. Renew leader key TTL
3. Check instance health:
   - Mark drifted instances
   - Remove stale instances
4. Aggregate global metrics
5. Run registered leader tasks

---

## API Reference

### GET /api/cluster/status

Get overall cluster health.

**Response:**
```json
{
  "cluster_healthy": true,
  "instance_count": 3,
  "active_instances": 3,
  "drifted_instances": 0,
  "leader": {
    "instance_id": "forms-waf-0",
    "since": 1734567890
  },
  "this_instance": {
    "id": "forms-waf-1",
    "is_leader": false
  }
}
```

### GET /api/cluster/instances

List all registered instances.

**Response:**
```json
{
  "total": 3,
  "current_leader": "forms-waf-0",
  "instances": [
    {
      "instance_id": "forms-waf-0",
      "status": "active",
      "is_leader": true,
      "started_at": 1734567000,
      "last_heartbeat": 1734567950,
      "worker_count": 4
    },
    {
      "instance_id": "forms-waf-1",
      "status": "active",
      "is_leader": false,
      "started_at": 1734567100,
      "last_heartbeat": 1734567945,
      "worker_count": 4
    }
  ]
}
```

### GET /api/cluster/leader

Get current leader info.

**Response:**
```json
{
  "leader": "forms-waf-0",
  "this_instance": {
    "id": "forms-waf-1",
    "is_leader": false
  }
}
```

### GET /api/cluster/config

Get coordinator configuration.

**Response:**
```json
{
  "instance_id": "forms-waf-1",
  "heartbeat_interval": 15,
  "heartbeat_ttl": 90,
  "leader_ttl": 30,
  "leader_renew_interval": 10,
  "drift_threshold": 60,
  "stale_threshold": 300,
  "redis_host": "redis",
  "redis_port": 6379
}
```

### GET /api/cluster/this

Get info about the current instance.

**Response:**
```json
{
  "instance_id": "forms-waf-1",
  "is_leader": false,
  "worker_id": 0,
  "worker_count": 4,
  "config": {
    "heartbeat_interval": 15,
    "leader_ttl": 30,
    "drift_threshold": 60,
    "stale_threshold": 300
  }
}
```

---

## Initialization

The coordinator is started in `init_worker_by_lua`:

```lua
-- Only worker 0 participates in coordination
if ngx.worker.id() == 0 then
    local coordinator = require "instance_coordinator"
    coordinator.start_coordinator_timer()
end
```

The initialization sequence:
1. Register instance in Redis
2. Attempt leader election
3. Start heartbeat timer (15s interval)
4. Start leader maintenance timer (10s interval)

---

## Graceful Shutdown

On shutdown, instances should deregister:

```lua
local coordinator = require "instance_coordinator"

-- Called during nginx shutdown
coordinator.deregister_instance()
```

This:
1. Removes instance from registry
2. Deletes heartbeat key
3. Releases leadership (if leader) for faster failover

---

## Kubernetes Configuration

### StatefulSet Requirements

```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: forms-waf-openresty
spec:
  replicas: 3
  serviceName: forms-waf-openresty-headless
  podManagementPolicy: Parallel  # All pods start together
  template:
    spec:
      containers:
      - name: openresty
        env:
        - name: HOSTNAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
```

### Headless Service

Required for stable pod DNS names:

```yaml
apiVersion: v1
kind: Service
metadata:
  name: forms-waf-openresty-headless
spec:
  clusterIP: None
  selector:
    app: forms-waf-openresty
```

---

## Usage Patterns

### Check Leader Status

```lua
local coordinator = require "instance_coordinator"

if coordinator.is_leader() then
    -- Run cluster-wide task
end
```

### Get Cluster Info

```lua
local coordinator = require "instance_coordinator"

local status = coordinator.get_cluster_status()
print("Active instances:", status.active_instances)
print("Current leader:", status.leader.instance_id)
```

### Run Task Only on Leader

```lua
local coordinator = require "instance_coordinator"

coordinator.register_for_leader_task("daily_report", function()
    generate_daily_report()
end, 86400)  -- Once per day
```

---

## Troubleshooting

### No Leader Elected

**Symptoms:** All instances show `is_leader: false`

**Causes:**
- Redis connection issues
- All instances started simultaneously and failed atomic SET

**Solution:**
- Check Redis connectivity
- Wait for next election cycle (10s)
- Restart one instance if needed

### Split Brain

**Symptoms:** Multiple instances claim leadership

**This should not happen** due to Redis atomic operations. If it does:
- Check Redis replication configuration
- Ensure single Redis instance or proper clustering
- Review network partitioning

### Instances Not Cleaning Up

**Symptoms:** Dead instances remain in registry

**Causes:**
- No leader elected (cleanup is leader task)
- Leader not running maintenance timer

**Solution:**
- Ensure leader is healthy
- Check leader maintenance timer logs

### Heartbeat Failures

**Symptoms:** Instances marked as drifted/down

**Causes:**
- Redis connection issues
- High load causing timer delays
- Network partitioning

**Solution:**
- Check Redis connectivity from pods
- Review nginx error logs for timeout errors
- Consider increasing HEARTBEAT_TTL

---

## Monitoring

### Key Metrics to Watch

1. **Cluster health:** `cluster_healthy` should be `true`
2. **Drifted instances:** Should be 0 in normal operation
3. **Leader stability:** Leader should not change frequently
4. **Heartbeat age:** Should stay under 15-30 seconds

### Log Messages

```
# Normal operation
instance_coordinator: registered instance 'forms-waf-0'
instance_coordinator: instance 'forms-waf-0' acquired leadership

# Warning conditions
instance_coordinator: cluster status - 2 active, 1 drifted instances
instance_coordinator: heartbeat failed: connection refused

# Error conditions
instance_coordinator: removing stale instance 'forms-waf-2'
instance_coordinator: failed to renew leadership: not leader
```

---

## Security Considerations

1. **Redis Authentication** - Use `REDIS_PASSWORD` in production

2. **Network Isolation** - Redis should only be accessible from WAF pods

3. **Leader Privileges** - Leader performs cluster-wide operations; ensure Redis ACLs if needed

4. **API Access** - Cluster endpoints should require authentication (RBAC: metrics:read)
