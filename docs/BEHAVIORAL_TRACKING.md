# Behavioral Tracking and Anomaly Detection

This guide explains the ML-based behavioral tracking system for form submission pattern analysis in the Forms WAF.

## Overview

Behavioral tracking provides:
- **Flow-based monitoring** - Track submission patterns across multi-page forms
- **Time-series data** - Historical statistics with configurable retention
- **Duration histograms** - Analyze how long users take to fill forms
- **Unique IP tracking** - Count distinct users via HyperLogLog
- **Anomaly detection** - Z-score based deviation from learned baselines

## Key Concepts

### Flows

A **flow** represents a user journey through one or more pages before submitting a form. For example:
- A contact form is a simple single-page flow
- A checkout process spanning cart → shipping → payment is a multi-step flow

Flows are identified by:
- **Start paths** - Pages where users begin the flow
- **End paths** - Pages where form submission occurs
- **Path matching** - Exact, prefix, or regex patterns

### Time Buckets

Data is aggregated across 5 time bucket types with different retention periods:

| Bucket Type | Format | TTL |
|-------------|--------|-----|
| hour | 2024121910 | 90 days |
| day | 20241219 | 1 year |
| week | 2024W51 | 2 years |
| month | 202412 | 5 years |
| year | 2024 | 10 years |

### Duration Histogram

Tracks how long users take to complete forms:

| Bucket | Range |
|--------|-------|
| 0-2 | 0 to 2 seconds |
| 2-5 | 2 to 5 seconds |
| 5-10 | 5 to 10 seconds |
| 10-30 | 10 to 30 seconds |
| 30-60 | 30 to 60 seconds |
| 60-120 | 1 to 2 minutes |
| 120-300 | 2 to 5 minutes |
| 300+ | Over 5 minutes |

---

## Configuration

### Vhost Configuration

Enable behavioral tracking in the vhost configuration:

```json
{
  "id": "my-vhost",
  "name": "My Website",
  "behavioral": {
    "enabled": true,
    "flows": [
      {
        "name": "checkout",
        "start_paths": ["/cart", "/products/*"],
        "end_paths": ["/checkout/complete"],
        "start_methods": ["GET"],
        "end_methods": ["POST"],
        "path_match_mode": "prefix"
      },
      {
        "name": "contact",
        "start_paths": ["/contact"],
        "end_paths": ["/contact"],
        "path_match_mode": "exact"
      }
    ],
    "tracking": {
      "submission_counts": true,
      "fill_duration": true,
      "unique_ips": true,
      "avg_spam_score": true
    },
    "anomaly_detection": {
      "enabled": true,
      "std_dev_threshold": 2.0,
      "action": "score",
      "score_addition": 15
    },
    "baselines": {
      "learning_period_days": 14,
      "min_samples": 100
    }
  }
}
```

### Flow Configuration Options

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Unique identifier for the flow |
| `start_paths` | array | Paths where users enter the flow |
| `end_paths` | array | Paths where form submission occurs |
| `start_methods` | array | HTTP methods for start (default: any) |
| `end_methods` | array | HTTP methods for end (default: any) |
| `path_match_mode` | string | `exact`, `prefix`, or `regex` |

### Tracking Options

| Field | Default | Description |
|-------|---------|-------------|
| `submission_counts` | true | Track total submissions and outcomes |
| `fill_duration` | true | Record form fill time histogram |
| `unique_ips` | true | Count distinct IPs via HyperLogLog |
| `avg_spam_score` | true | Track average spam scores |

### Anomaly Detection Options

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | false | Enable anomaly detection |
| `std_dev_threshold` | 2.0 | Z-score threshold for anomaly flagging |
| `action` | "score" | Action: `score`, `flag`, `block` |
| `score_addition` | 15 | Points added when anomaly detected |

### Baseline Options

| Field | Default | Description |
|-------|---------|-------------|
| `learning_period_days` | 14 | Days of data to analyze |
| `min_samples` | 100 | Minimum hourly samples required |

---

## Redis Data Schema

### Submission Counts

**Key:** `waf:behavioral:{vhost_id}:{flow_name}:counts:{bucket_type}:{bucket_id}`

**Type:** Hash

```
submissions: 1500
allowed: 1420
blocked: 45
monitored: 35
spam_score_sum: 12500
spam_score_count: 1500
```

### Duration Histogram

**Key:** `waf:behavioral:{vhost_id}:{flow_name}:duration:{bucket_type}:{bucket_id}`

**Type:** Sorted Set (ZSET)

```
0-2:     15      # 15 submissions in 0-2 seconds
2-5:     45      # 45 submissions in 2-5 seconds
5-10:    320     # etc.
10-30:   890
30-60:   180
60-120:  35
120-300: 12
300+:    3
```

### Unique IPs

**Key:** `waf:behavioral:{vhost_id}:{flow_name}:ips:{bucket_type}:{bucket_id}`

**Type:** HyperLogLog (PFADD/PFCOUNT)

### Baseline Data

**Key:** `waf:behavioral:{vhost_id}:{flow_name}:baseline`

**Type:** Hash

```
learning_complete: 1
hourly_avg_submissions: 62.50
hourly_std_dev_submissions: 15.30
hourly_p50_submissions: 58
hourly_p90_submissions: 85
hourly_p99_submissions: 112
samples_used: 336
learning_period_days: 14
last_updated: 1734567890
```

### Index Keys

**Vhost index:** `waf:behavioral:index:vhosts` (Set)

**Flow index:** `waf:behavioral:index:{vhost_id}:flows` (Set)

---

## Anomaly Detection

### How It Works

1. **Learning Phase**: System collects hourly submission counts for the configured learning period (default 14 days)

2. **Baseline Calculation**: Once minimum samples are collected:
   - Calculate mean (average hourly submissions)
   - Calculate standard deviation
   - Calculate percentiles (p50, p90, p99)

3. **Detection**: For each incoming submission:
   - Get current hour's submission count
   - Calculate Z-score: `(current - mean) / std_dev`
   - If Z-score exceeds threshold, flag as anomaly

### Z-Score Thresholds

| Threshold | Meaning |
|-----------|---------|
| 1.0 | ~32% of normal hours exceed this |
| 2.0 | ~5% of normal hours exceed this |
| 3.0 | ~0.3% of normal hours exceed this |

### Anomaly Actions

- **score**: Add points to spam score (default: +15)
- **flag**: Add `behavioral:high_rate` flag
- **block**: Immediately block the request

---

## API Reference

### GET /api/behavioral/summary

Get summary of all behavioral tracking.

**Query Parameters:**
- `vhost_id` (optional) - Filter by vhost

**Response:**
```json
{
  "total_tracked_vhosts": 3,
  "vhosts": [
    {
      "vhost_id": "my-vhost",
      "flows": [
        {
          "name": "checkout",
          "baseline_status": "ready",
          "samples_collected": 336,
          "last_hour": {
            "submissions": 45,
            "blocked": 2,
            "allowed": 43,
            "unique_ips": 38,
            "avg_spam_score": 8.5
          }
        }
      ]
    }
  ]
}
```

### GET /api/behavioral/stats

Get historical statistics for a flow.

**Query Parameters:**
- `vhost_id` (required) - Virtual host ID
- `flow_name` (required) - Flow name
- `bucket_type` (optional) - `hour`, `day`, `week`, `month`, `year` (default: hour)
- `count` (optional) - Number of buckets to retrieve (default: 24)

**Response:**
```json
{
  "vhost_id": "my-vhost",
  "flow_name": "checkout",
  "bucket_type": "hour",
  "count": 24,
  "stats": [
    {
      "bucket_id": "2024121910",
      "timestamp": 1734606000,
      "submissions": 45,
      "allowed": 43,
      "blocked": 2,
      "monitored": 0,
      "avg_spam_score": 8.5,
      "duration_histogram": {
        "0-2": 1,
        "2-5": 3,
        "5-10": 15,
        "10-30": 20,
        "30-60": 5,
        "60-120": 1
      },
      "unique_ips": 38
    }
  ]
}
```

### GET /api/behavioral/baseline

Get baseline data for a flow.

**Query Parameters:**
- `vhost_id` (required) - Virtual host ID
- `flow_name` (required) - Flow name

**Response:**
```json
{
  "vhost_id": "my-vhost",
  "flow_name": "checkout",
  "status": "ready",
  "baseline": {
    "learning_complete": true,
    "hourly_avg_submissions": 62.5,
    "hourly_std_dev_submissions": 15.3,
    "hourly_p50_submissions": 58,
    "hourly_p90_submissions": 85,
    "hourly_p99_submissions": 112,
    "samples_used": 336,
    "learning_period_days": 14,
    "last_updated": "1734567890"
  }
}
```

### POST /api/behavioral/recalculate

Force baseline recalculation.

**Query Parameters:**
- `vhost_id` (required) - Virtual host ID
- `flow_name` (optional) - Specific flow, or all flows if omitted

**Response:**
```json
{
  "vhost_id": "my-vhost",
  "flow_name": "all",
  "results": {
    "checkout": {"success": true},
    "contact": {"success": false, "error": "insufficient samples"}
  }
}
```

### GET /api/behavioral/flows

List all flows for a vhost.

**Query Parameters:**
- `vhost_id` (required) - Virtual host ID

**Response:**
```json
{
  "vhost_id": "my-vhost",
  "flows": ["checkout", "contact"],
  "configs": {
    "checkout": {
      "name": "checkout",
      "start_paths": ["/cart", "/products/*"],
      "end_paths": ["/checkout/complete"],
      "path_match_mode": "prefix"
    }
  }
}
```

### GET /api/behavioral/vhosts

List all vhosts with behavioral tracking enabled.

**Response:**
```json
{
  "total": 3,
  "vhosts": [
    {
      "vhost_id": "my-vhost",
      "name": "My Website",
      "hostnames": ["example.com"],
      "flows": ["checkout", "contact"],
      "tracking": {
        "submission_counts": true,
        "fill_duration": true,
        "unique_ips": true
      },
      "anomaly_detection": {
        "enabled": true,
        "std_dev_threshold": 2.0
      }
    }
  ]
}
```

---

## Admin UI

The Admin UI provides a **Behavioral Analytics** page with:

1. **Overview Dashboard**
   - List of vhosts with behavioral tracking
   - Flow status and baseline readiness
   - Quick stats for the last hour

2. **Flow Details**
   - Historical charts (submissions, blocks, spam scores)
   - Duration histogram visualization
   - Unique IP trends

3. **Baseline Management**
   - View calculated baselines
   - Trigger recalculation
   - Monitor learning progress

4. **Anomaly Detection Status**
   - Current detection threshold
   - Recent anomaly flags
   - False positive tuning

---

## Use Cases

### Bot Detection

Bots typically submit forms instantly (0-2 seconds). The duration histogram reveals:
- Normal users: Peak in 30-60 second range
- Bots: Spike in 0-2 second range

### Traffic Spike Detection

Anomaly detection catches unusual submission rates:
- Marketing campaign success → gradual increase (normal)
- Spam attack → sudden 10x spike (anomaly flagged)

### Multi-Step Form Tracking

Track user journeys across pages:
```json
{
  "name": "registration",
  "start_paths": ["/register/step1"],
  "end_paths": ["/register/complete"],
  "path_match_mode": "exact"
}
```

---

## Troubleshooting

### Baseline Not Ready

**Problem:** Baseline shows "learning" status

**Causes:**
- Insufficient traffic (need min_samples hourly data points)
- Flow not properly configured (paths don't match)

**Solution:**
- Wait for more data collection
- Check flow path configuration
- Lower min_samples if appropriate

### High False Positives

**Problem:** Legitimate traffic flagged as anomaly

**Causes:**
- Threshold too low
- Normal traffic patterns vary widely

**Solution:**
- Increase std_dev_threshold (try 2.5 or 3.0)
- Review baseline data for accuracy
- Consider seasonal adjustments

### No Data Recorded

**Problem:** Stats show zero submissions

**Causes:**
- Behavioral tracking not enabled
- Flow paths don't match request paths
- Redis connection issues

**Solution:**
- Verify `behavioral.enabled: true` in vhost config
- Check path_match_mode and patterns
- Check Redis connectivity

---

## Security Considerations

1. **Data Retention** - Historical data is retained per bucket TTL; adjust for compliance

2. **IP Privacy** - HyperLogLog provides approximate unique counts without storing actual IPs

3. **Rate Limiting** - The API endpoints should be protected by RBAC (security:read permission)

4. **Baseline Manipulation** - Admin-only access to recalculate endpoints prevents baseline poisoning
