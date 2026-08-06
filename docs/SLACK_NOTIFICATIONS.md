# Slack Notifications

This guide covers the Slack webhook notification system for real-time security alerting with intelligent deduplication and attack lifecycle tracking.

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Configuration](#configuration)
4. [Message Format](#message-format)
5. [Attack Lifecycle](#attack-lifecycle)
6. [Deduplication Logic](#deduplication-logic)
7. [API Reference](#api-reference)
8. [Admin UI](#admin-ui)
9. [Troubleshooting](#troubleshooting)

---

## Overview

The Slack notification system sends formatted alerts to Slack channels when security events occur. Unlike standard webhooks that send every event, Slack notifications use intelligent deduplication to prevent alert fatigue:

- **Attack Started**: Notification when a new attack is first detected
- **Attack Ongoing**: Periodic updates while an attack continues (configurable interval)
- **Attack Resolved**: Notification when an attack ends (no new events for threshold period)

This approach ensures your security team is informed without being overwhelmed by thousands of individual event notifications.

---

## Features

### Prettified Messages

Messages use Slack's attachment format with:
- **Color-coded sidebars**: Red (new attack), Yellow (ongoing), Green (resolved)
- **Structured fields**: Attack type, target, duration, event count displayed in columns
- **Timestamps**: Slack-native date formatting with timezone support
- **Footer**: Attack ID for correlation and tracking

### Attack Stream Tracking

Different attack types are tracked independently:
- Keyword filter blocks
- High spam scores
- Rate limit triggers
- Honeypot detections
- CAPTCHA triggers
- Fingerprint floods

### Intelligent Deduplication

- Configurable update interval (1-30 minutes)
- Configurable resolution threshold (2-60 minutes)
- Events grouped by source IP prefix + attack type + target

---

## Configuration

### Basic Setup

1. **Create a Slack Incoming Webhook**:
   - Go to your Slack workspace settings
   - Navigate to Apps > Incoming Webhooks
   - Click "Add New Webhook to Workspace"
   - Select the target channel
   - Copy the webhook URL

2. **Configure in Admin UI**:
   - Navigate to Operations > Slack Notifications
   - Enable Slack notifications
   - Paste your webhook URL
   - Configure event types and intervals
   - Click Save

### Configuration Options

| Setting | Description | Default | Range |
|---------|-------------|---------|-------|
| `enabled` | Enable/disable Slack notifications | `false` | - |
| `webhook_url` | Slack incoming webhook URL (**must be `https://`**) | - | Required |
| `channel` | Channel override (legacy webhooks only) | - | Optional |
| `update_interval` | Seconds between ongoing attack updates | `300` | 60-1800 |
| `resolution_threshold` | Seconds without events before attack is resolved | `600` | 120-3600 |
| `events` | Event types to notify on | All | See below |
| `mention_users` | Slack user IDs to @mention | `[]` | Array |
| `mention_on_high_severity` | Only @mention for high severity | `false` | - |

### Event Types

| Event Type | Description | Status |
|------------|-------------|--------|
| `request_blocked` | Request blocked by WAF rules | Emitted |
| `captcha_triggered` | CAPTCHA challenge issued | Emitted |
| `honeypot_triggered` | Honeypot field filled | Emitted |
| `disposable_email` | Disposable email detected | Emitted |
| `rate_limit_triggered` | IP or hash rate limit exceeded | **Not emitted yet** |
| `high_spam_score` | Spam score above threshold | **Not emitted yet** |
| `fingerprint_flood` | Fingerprint-based rate limit | **Not emitted yet** |

The three marked **Not emitted yet** are accepted by the API for forward
compatibility, but nothing in the WAF currently raises them — subscribing to them
alone produces no alerts. `GET /api/slack/config` reports the authoritative lists
as `emitted_events` and `unavailable_events`, and the default configuration
enables only the emitted ones.

### Channel Override

**Note**: Modern Slack incoming webhooks have the channel fixed at creation time. The channel override only works with:
- Legacy incoming webhooks
- Custom Slack Apps with `chat:write` scope

If you need to send to multiple channels, create multiple webhook URLs.

### Example Configuration

```json
{
  "enabled": true,
  "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
  "channel": "#security-alerts",
  "update_interval": 300,
  "resolution_threshold": 600,
  "events": [
    "request_blocked",
    "rate_limit_triggered",
    "high_spam_score"
  ],
  "mention_users": ["U12345ABC"],
  "mention_on_high_severity": true,
  "severity_thresholds": {
    "high_event_count": 100,
    "high_event_rate": 10
  }
}
```

---

## Message Format

### Attack Started (Red)

Sent when a new attack is first detected.

```
:rotating_light: Attack Detected

Attack Type     Target
Keyword Block   example.com/contact

Source IP       Started
192.168.1.x/24  Jan 15, 2025 2:30 PM

Detection Details
Matched Keywords: viagra, casino
Spam Score: 95

─────────────────────────────────
Attack ID: abc123 | WAF Appliance
```

### Attack Ongoing (Yellow)

Sent at configured intervals while attack continues.

```
:warning: Ongoing Attack Update

Attack Type     Target
Keyword Block   example.com/contact

Duration        Total Events
15 minutes      247

Attack Rate     Unique IPs
~16 events/min  3

─────────────────────────────────
Attack ID: abc123 | Started: Jan 15, 2025 2:30 PM
```

### Attack Resolved (Green)

Sent when no new events occur within the resolution threshold.

```
:white_check_mark: Attack Resolved

Attack Type     Target
Keyword Block   example.com/contact

Duration        Total Events
23 minutes      412

─────────────────────────────────
Attack ID: abc123 | No new events for 10 minutes
```

---

## Attack Lifecycle

```
                    ┌─────────────────────────────────────────┐
                    │           Attack Detected               │
                    │  (First matching event received)        │
                    └─────────────────┬───────────────────────┘
                                      │
                                      ▼
                    ┌─────────────────────────────────────────┐
                    │      Send "Attack Started" Message      │
                    │           (Red sidebar)                 │
                    └─────────────────┬───────────────────────┘
                                      │
                    ┌─────────────────┴───────────────────────┐
                    │                                         │
                    ▼                                         ▼
        ┌───────────────────────┐             ┌───────────────────────┐
        │   More Events         │             │   No Events for       │
        │   (Attack ongoing)    │             │   resolution_threshold│
        └───────────┬───────────┘             └───────────┬───────────┘
                    │                                     │
                    ▼                                     │
        ┌───────────────────────┐                         │
        │   update_interval     │                         │
        │   elapsed?            │                         │
        └─────┬─────────┬───────┘                         │
              │ Yes     │ No                              │
              ▼         │                                 │
┌─────────────────────┐ │                                 │
│ Send "Ongoing"      │ │                                 │
│ Message (Yellow)    │ │                                 │
└──────────┬──────────┘ │                                 │
           │            │                                 │
           └────────────┴─────────────────────────────────┤
                                                          │
                                                          ▼
                                      ┌─────────────────────────────────────────┐
                                      │     Send "Attack Resolved" Message      │
                                      │            (Green sidebar)              │
                                      └─────────────────────────────────────────┘
```

---

## Deduplication Logic

### Attack Uniqueness

An attack is uniquely identified by combining:

| Component | Description | Example |
|-----------|-------------|---------|
| IP Prefix | /24 for IPv4, /48 for IPv6 | `192.168.1.0/24` |
| Attack Type | Event type + details | `blocked:keyword` |
| Target | vhost + endpoint | `example.com:/contact` |

This ensures:
- Same attacker hitting different endpoints = separate attacks
- Different attackers hitting same endpoint = separate attacks
- Same attack type from same source = single attack stream

### State Management

Attack state is stored in Redis with automatic expiration:

```
waf:slack:config                    # Slack configuration
waf:slack:attack:{attack_key}       # Per-attack state (TTL: 2x resolution_threshold)
waf:slack:active_attacks            # SET of active attack keys
waf:slack:stats                     # Notification statistics
```

### Resolution Detection

A background timer runs every 60 seconds to check for resolved attacks:

1. Iterate through all active attack keys
2. Check time since last event (`last_seen`)
3. If `now - last_seen >= resolution_threshold`:
   - Send "Attack Resolved" notification
   - Remove from active attacks set
   - Mark attack state as resolved

---

## API Reference

### Get Configuration

```bash
GET /api/slack/config
```

Response:
```json
{
  "enabled": true,
  "webhook_url": "https://hooks.slack.com/services/...",
  "channel": "#security-alerts",
  "update_interval": 300,
  "resolution_threshold": 600,
  "events": ["request_blocked", "high_spam_score"],
  "mention_users": [],
  "mention_on_high_severity": false,
  "severity_thresholds": {
    "high_event_count": 100,
    "high_event_rate": 10
  }
}
```

### Update Configuration

```bash
PUT /api/slack/config
Content-Type: application/json

{
  "enabled": true,
  "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
  "update_interval": 300,
  "resolution_threshold": 600,
  "events": ["request_blocked"]
}
```

### Send Test Notification

```bash
POST /api/slack/test
```

Sends a test message to verify webhook configuration.

Response:
```json
{
  "success": true,
  "message": "Test notification sent"
}
```

### List Active Attacks

```bash
GET /api/slack/attacks
```

Response:
```json
{
  "attacks": [
    {
      "attack_key": "abc123",
      "attack_type": "blocked:keyword",
      "source_ip_prefix": "192.168.1.0/24",
      "target_vhost": "example.com",
      "target_endpoint": "/contact",
      "first_seen": 1705330200,
      "last_seen": 1705331400,
      "event_count": 47,
      "notification_count": 3,
      "status": "active"
    }
  ],
  "total": 1
}
```

### Get Statistics

```bash
GET /api/slack/stats
```

Response:
```json
{
  "total_notifications": 156,
  "attack_started": 42,
  "attack_ongoing": 98,
  "attack_resolved": 16,
  "failed_notifications": 3,
  "last_notification": 1705331580,
  "uptime_hours": 168
}
```

### Reset Statistics

```bash
POST /api/slack/stats/reset
```

---

## Admin UI

### Accessing Slack Settings

Navigate to **Operations > Slack Notifications** in the Admin UI.

### Configuration Panel

The settings page provides:

1. **Enable Toggle**: Turn Slack notifications on/off
2. **Webhook URL**: Input field with validation
3. **Channel Override**: Optional channel (with help text about legacy webhooks)
4. **Update Interval**: Slider from 1-30 minutes
5. **Resolution Threshold**: Slider from 2-60 minutes
6. **Event Types**: Checkboxes for each event type
7. **@Mention Settings**: User IDs to mention, severity option
8. **Test Button**: Send test notification to verify setup

### Active Attacks Panel

Displays currently tracked attack streams:

| Column | Description |
|--------|-------------|
| Attack Type | Type of attack detected |
| Source | IP prefix of attacker |
| Target | vhost/endpoint being attacked |
| Events | Total event count |
| Duration | Time since first event |
| Status | active/resolved |

### Statistics Panel

Shows notification metrics:
- Total notifications sent
- Breakdown by type (started/ongoing/resolved)
- Failed notifications
- Reset statistics button

---

## Troubleshooting

### Notifications Not Sending

1. **Check webhook URL**:
   ```bash
   curl -X POST https://hooks.slack.com/services/YOUR/WEBHOOK/URL \
     -H 'Content-Type: application/json' \
     -d '{"text": "Test message"}'
   ```

2. **Verify enabled**:
   ```bash
   curl http://localhost:8082/api/slack/config | jq .enabled
   ```

3. **Check event types**: Ensure the event types you expect are enabled

4. **Check logs**:
   ```bash
   docker logs forms-waf-openresty 2>&1 | grep -i slack
   ```

### Too Many Notifications

- Increase `update_interval` (longer time between updates)
- Increase `resolution_threshold` (attacks stay grouped longer)
- Filter `events` to only critical types

### Missing Attack Resolution Messages

- Resolution checker runs every 60 seconds
- Attacks are resolved after `resolution_threshold` seconds of inactivity
- Check that the WAF instance is running continuously

### Channel Override Not Working

Modern Slack incoming webhooks cannot override the channel. Options:
1. Create separate webhook URLs per channel
2. Use a Slack App with `chat:write` scope
3. Use legacy incoming webhooks (if available in your workspace)

### Test Message Works But Real Alerts Don't

1. Verify attack is triggering the correct event type
2. Check if the event type is enabled in configuration
3. Confirm the attack passes the minimum threshold for notification
4. Review Redis for attack state: `redis-cli KEYS "waf:slack:*"`

### High Latency in Notifications

- Slack notifications use `ngx.timer.at(0, ...)` for async processing
- Check nginx error logs for timer errors
- Verify Redis connectivity for state operations

---

## Best Practices

### Channel Organization

- Use dedicated channels for WAF alerts (e.g., `#waf-alerts`)
- Consider severity-based channels (`#waf-critical`, `#waf-info`)
- Don't send to general channels - alerts get lost

### Interval Tuning

| Environment | Update Interval | Resolution Threshold |
|-------------|-----------------|---------------------|
| High-traffic production | 10-15 minutes | 15-30 minutes |
| Medium-traffic | 5-10 minutes | 10-15 minutes |
| Low-traffic / testing | 2-5 minutes | 5-10 minutes |

### @Mention Strategy

- Only use `mention_on_high_severity: true` for on-call alerting
- Configure appropriate `high_event_count` and `high_event_rate` thresholds
- Avoid @mentioning for every alert to prevent alert fatigue

### Security and Operational Notes

- **The webhook URL is a credential.** Anyone holding it can post into your
  security channel, so `GET /api/slack/config` returns it masked as `***` with a
  separate `webhook_url_set` boolean. Submit the mask unchanged to keep the
  stored value, or a new `https://` URL to replace it. Plain `http://` is
  rejected — it would leak the token and every attack detail in cleartext.
- **Message content is escaped.** Host headers, request paths and field names are
  attacker-controlled, so `<`, `>`, `&` and backticks are neutralised before a
  payload is built. Without this a crafted request path could ping `@channel` or
  render a spoofed link inside an alert.
- **Notifications are rate limited** to 20/minute globally, independent of
  deduplication, and at most 500 concurrent attacks are tracked. A circuit
  breaker pauses sending for 5 minutes after 5 consecutive failures, and at most
  32 notifications may be in flight at once.
- **Resolution checking and the daily stats reset are cluster singletons**, run
  via `instance_coordinator` leader election. In a multi-replica deployment only
  the leader sends resolution messages.

### Combining with Webhooks

Slack notifications complement (don't replace) standard webhooks:
- **Slack**: Human-readable alerts for security team
- **Webhooks**: Machine-readable events for SIEM/SOAR integration

Both can be enabled simultaneously, and they are fully independent: Slack is
dispatched before any webhook-specific check, so enabling Slack while leaving
webhooks disabled works, and a full webhook queue does not suppress Slack alerts.

---

## Related Documentation

- [Webhooks Configuration](API_HANDLERS.md#webhooksslua) - Standard webhook setup
- [User Guide](guide/USER_GUIDE.md) - General WAF configuration
- [Attack Playbook](guide/ATTACK_PLAYBOOK.md) - Responding to attacks
