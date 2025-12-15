# Forms WAF - Advanced Spam Protection System

A comprehensive, multi-layer spam protection system for web forms using OpenResty (Lua) for intelligent form analysis and HAProxy for global rate limiting. Features a modern React-based Admin UI for real-time configuration management.

## Features at a Glance

| Category | Features |
|----------|----------|
| **Content Analysis** | Keyword filtering, content hashing, honeypot detection, disposable email blocking, link analysis |
| **Behavioral Detection** | Form timing tokens, field anomaly detection, submission fingerprinting |
| **Threat Intelligence** | IP reputation (AbuseIPDB), GeoIP restrictions, datacenter/VPN detection |
| **Bot Protection** | CAPTCHA integration (reCAPTCHA, hCaptcha, Turnstile), rate limiting |
| **Operations** | Webhook notifications, audit logging, bulk import/export, Prometheus metrics |
| **Multi-tenancy** | Virtual hosts, per-endpoint configuration, field learning |

## Architecture Overview

```
Client → Ingress → OpenResty → HAProxy → Backend
                      ↓            ↓
                    Redis    (Stick-table sync)
                      ↑
                  Admin UI (port 3000)
                  Admin API (port 8082)
```

### Components

1. **OpenResty** (Port 8080/8081/8082) - Intelligent form analysis engine
   - Multi-format parsing (multipart, urlencoded, JSON)
   - Content-based spam scoring with 20+ detection rules
   - Redis-backed dynamic configuration
   - Per-vhost and per-endpoint customization

2. **HAProxy** - Global rate limiting with stick-table sync
   - StatefulSet with automatic peer discovery
   - Per-hash, per-IP, and per-fingerprint rate limiting
   - Prometheus metrics export

3. **Redis** - Dynamic configuration store
   - Keywords, hashes, IP lists
   - Virtual host and endpoint configurations
   - Session management for Admin UI

4. **Admin UI** - React-based management dashboard
   - Real-time configuration updates
   - Visual management of all WAF features
   - Role-based authentication

---

## Quick Start

### Local Development (Docker Compose)

```bash
# Start all services
docker-compose up -d

# Initialize Redis with default data
docker-compose exec redis sh /init-data.sh

# Access Admin UI at http://localhost:3000
# Default credentials: admin / changeme

# Test the WAF
./scripts/test-waf.sh http://localhost:8080
```

### Kubernetes Deployment (Helm)

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

cd helm/forms-waf
helm dependency build
helm install forms-waf . -n forms-waf --create-namespace
```

---

## Feature Details

### 1. Content Analysis

#### Keyword Filtering
- **Blocked Keywords**: Instant rejection (e.g., "viagra", "casino")
- **Flagged Keywords**: Score-based with configurable weights
- Case-insensitive matching with word boundary detection

#### Content Hashing
- SHA256 hashing of normalized form content
- Duplicate submission detection across all users
- Configurable thresholds for blocking repeated content

#### Honeypot Field Detection
Automatically detects and scores submissions that fill hidden honeypot fields.

```json
{
  "honeypot_fields": ["website", "url", "phone2"],
  "honeypot_action": "flag",
  "honeypot_score": 50
}
```

#### Disposable Email Detection
Blocks or flags submissions using temporary email services:
- 250+ built-in disposable domains
- Custom domain blocklist via Redis
- Configurable action (block/flag/monitor)

#### Enhanced Link Analysis
- **URL Shortener Detection**: Flags bit.ly, tinyurl.com, etc. (25+ services)
- **Suspicious TLD Detection**: Flags .xyz, .top, .click, etc.
- **Excessive Link Detection**: Scores based on link count

### 2. Behavioral Detection

#### Form Timing Tokens
Detects bot submissions by measuring time between form load and submission:

| Timing | Score | Reason |
|--------|-------|--------|
| No cookie | +30 | Direct POST without loading form |
| < 2 seconds | +40 | Too fast for human |
| < 5 seconds | +20 | Suspiciously fast |
| > 5 seconds | +0 | Normal behavior |

Enable via Admin UI: **Security → Form Timing**

#### Field Anomaly Detection
Detects suspicious patterns in form submissions:
- Identical field lengths (bot-generated)
- Sequential/incremental values
- ALL CAPS submissions
- Test data patterns ("test", "asdf", "123")
- Unusually long field values

#### Submission Fingerprinting
Creates client fingerprints based on:
- User-Agent string
- Accept-Language header
- Field names submitted
- Request characteristics

Used for cross-request correlation and flood detection.

### 3. Threat Intelligence

#### IP Reputation
Checks IP addresses against multiple sources:

| Provider | Description |
|----------|-------------|
| **Local Blocklist** | Redis-based manual blocklist |
| **AbuseIPDB** | External API (requires API key) |
| **Custom Webhook** | Your internal reputation service |

Enable via Admin UI: **Security → IP Reputation**

Configuration example:
```json
{
  "enabled": true,
  "abuseipdb": {
    "enabled": true,
    "api_key": "your-api-key",
    "min_confidence": 25
  },
  "block_score": 80,
  "flag_score": 50
}
```

#### GeoIP Restrictions
Country and ASN-based access control using MaxMind GeoLite2 databases:

- **Country Blocking**: Block specific countries
- **Country Allowlist**: Only allow specific countries
- **ASN Blocking**: Block specific networks
- **Datacenter Detection**: Flag/block cloud provider IPs

Enable via Admin UI: **Security → GeoIP**

**Setup Requirements:**
1. Download [GeoLite2 databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free registration required)
2. Mount to `/usr/share/GeoIP/`:
   - `GeoLite2-Country.mmdb`
   - `GeoLite2-ASN.mmdb`

```yaml
# docker-compose.yml
volumes:
  - ./geoip:/usr/share/GeoIP:ro
```

### 4. Bot Protection

#### CAPTCHA Integration
Supports multiple CAPTCHA providers with automatic fallback:

| Provider | Features |
|----------|----------|
| **reCAPTCHA v2** | Checkbox challenge |
| **reCAPTCHA v3** | Invisible scoring |
| **hCaptcha** | Privacy-focused alternative |
| **Cloudflare Turnstile** | Frictionless verification |

Configure via Admin UI: **CAPTCHA → Providers** and **CAPTCHA → Settings**

Features:
- Per-endpoint CAPTCHA requirements
- Trust tokens for verified users
- Configurable score thresholds
- Fallback chain if primary fails

#### Rate Limiting
Multi-layer rate limiting:

| Layer | Scope | Default |
|-------|-------|---------|
| OpenResty | Per-endpoint | Configurable |
| HAProxy | Per-IP | 30/min |
| HAProxy | Per-hash | 10/min |
| HAProxy | Per-fingerprint | 50/min |

### 5. Operational Features

#### Webhook Notifications
Send real-time notifications for WAF events:

```json
{
  "enabled": true,
  "urls": ["https://your-webhook.example.com/waf-events"],
  "events": ["blocked", "flagged", "captcha_required"],
  "batch_size": 10,
  "batch_interval_ms": 5000
}
```

Configure via Admin UI: **Operations → Webhooks**

#### Audit Logging
JSON-formatted structured logs for security events:

```json
{
  "@timestamp": "2024-01-15T10:30:00Z",
  "event_type": "request_blocked",
  "client_ip": "192.168.1.100",
  "spam_score": 85,
  "flags": ["keyword:blocked:viagra", "timing:too_fast"],
  "vhost_id": "example-com",
  "endpoint_id": "contact-form"
}
```

#### Bulk Import/Export
Import and export configurations via Admin UI: **Operations → Bulk**

Supported data types:
- Blocked/flagged keywords
- IP allowlist
- Blocked hashes

Formats: JSON, CSV (keywords only)

#### Prometheus Metrics
Available at `/metrics` endpoint:

| Metric | Description |
|--------|-------------|
| `waf_requests_total` | Total requests by vhost, endpoint, result |
| `waf_spam_score_histogram` | Distribution of spam scores |
| `waf_blocked_total` | Blocked requests by reason |
| `waf_captcha_challenges_total` | CAPTCHA challenges issued |

### 6. Multi-tenancy

#### Virtual Hosts
Configure per-domain WAF rules:

- Exact hostname matching (`example.com`)
- Wildcard support (`*.example.com`)
- Per-vhost thresholds and routing
- WAF modes: blocking, monitoring, passthrough

Configure via Admin UI: **Virtual Hosts**

#### Endpoint Configuration
Per-endpoint customization:

| Setting | Description |
|---------|-------------|
| **WAF Mode** | blocking, monitoring, passthrough, strict |
| **Thresholds** | Override global spam score limits |
| **Rate Limits** | Per-endpoint request limits |
| **Field Validation** | Required fields, max lengths |
| **Expected Fields** | Block unexpected field names |
| **Honeypot Fields** | Hidden fields to detect bots |

Configure via Admin UI: **Endpoints**

#### Field Learning
Automatic field discovery from submissions:

1. Enable learning mode on endpoint
2. WAF records field names and infers types
3. Review learned fields in Admin UI
4. Mark fields as expected or honeypot
5. Enable validation to block unexpected fields

---

## Configuration Reference

### Redis Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:keywords:blocked` | SET | Keywords that trigger immediate block |
| `waf:keywords:flagged` | SET | Keywords with scores (`keyword:score`) |
| `waf:hashes:blocked` | SET | Content hashes to block |
| `waf:config:thresholds` | HASH | Global thresholds |
| `waf:whitelist:ips` | SET | IPs to bypass filtering |
| `waf:vhosts:config:{id}` | STRING | Virtual host config (JSON) |
| `waf:endpoints:config:{id}` | STRING | Endpoint config (JSON) |
| `waf:config:timing_token` | STRING | Timing token config (JSON) |
| `waf:config:geoip` | STRING | GeoIP config (JSON) |
| `waf:config:ip_reputation` | STRING | IP reputation config (JSON) |
| `waf:config:captcha` | STRING | CAPTCHA config (JSON) |
| `waf:config:webhooks` | STRING | Webhook config (JSON) |
| `waf:reputation:blocked_ips` | SET | Local IP blocklist |
| `waf:disposable_domains` | SET | Custom disposable email domains |

### Global Thresholds

| Threshold | Default | Description |
|-----------|---------|-------------|
| `spam_score_block` | 80 | Score to block immediately |
| `spam_score_flag` | 50 | Score to flag for monitoring |
| `hash_count_block` | 10 | Block after N identical submissions |
| `ip_rate_limit` | 30 | Max submissions/minute per IP |
| `ip_daily_limit` | 500 | Max submissions/day per IP |

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_HOST` | redis | Redis hostname |
| `REDIS_PORT` | 6379 | Redis port |
| `REDIS_PASSWORD` | - | Redis password (optional) |
| `WAF_ADMIN_AUTH` | true | Require authentication for Admin API |
| `WAF_EXPOSE_HEADERS` | false | Expose debug headers in responses |

---

## API Reference

### Authentication (Port 8082)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Login with credentials |
| `/api/auth/logout` | POST | End session |
| `/api/auth/verify` | GET | Verify session |
| `/api/auth/change-password` | POST | Change password |

### WAF Admin API (Port 8082)

All endpoints require authentication.

#### Core
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | WAF status |
| `/api/metrics` | GET | Metrics summary |
| `/api/sync` | POST | Force Redis sync |

#### Keywords
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/keywords/blocked` | GET/POST/DELETE | Blocked keywords |
| `/api/keywords/flagged` | GET/POST/PUT/DELETE | Flagged keywords |

#### Virtual Hosts
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/vhosts` | GET/POST | List/create vhosts |
| `/api/vhosts/{id}` | GET/PUT/DELETE | Manage vhost |
| `/api/vhosts/{id}/enable` | POST | Enable vhost |
| `/api/vhosts/{id}/disable` | POST | Disable vhost |

#### Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/endpoints` | GET/POST | List/create endpoints |
| `/api/endpoints/{id}` | GET/PUT/DELETE | Manage endpoint |
| `/api/endpoints/{id}/fields` | GET | Get learned fields |

#### Security Features
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/timing/config` | GET/PUT | Timing token config |
| `/api/geoip/config` | GET/PUT | GeoIP config |
| `/api/geoip/lookup` | GET | Lookup IP location |
| `/api/reputation/config` | GET/PUT | IP reputation config |
| `/api/reputation/check` | GET | Check IP reputation |
| `/api/reputation/blocklist` | GET/POST/DELETE | Local blocklist |

#### CAPTCHA
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/captcha/providers` | GET/POST | List/create providers |
| `/api/captcha/providers/{id}` | GET/PUT/DELETE | Manage provider |
| `/api/captcha/config` | GET/PUT | Global CAPTCHA settings |

#### Operations
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/webhooks/config` | GET/PUT | Webhook config |
| `/api/webhooks/test` | POST | Test webhook |
| `/api/bulk/export/{type}` | GET | Export data |
| `/api/bulk/import/{type}` | POST | Import data |

---

## Response Headers

### Debug Headers (when `WAF_EXPOSE_HEADERS=true`)

| Header | Description |
|--------|-------------|
| `X-Spam-Score` | Calculated spam score |
| `X-Spam-Flags` | Triggered detection flags |
| `X-Form-Hash` | Content hash |
| `X-Blocked` | Whether request was blocked |
| `X-Block-Reason` | Reason for blocking |
| `X-GeoIP-Country` | Detected country code |
| `X-WAF-Mode` | Current WAF mode |

---

## Project Structure

```
forms-waf/
├── admin-ui/                 # React Admin Dashboard
│   └── src/
│       ├── pages/
│       │   ├── security/     # Timing, GeoIP, Reputation
│       │   ├── captcha/      # CAPTCHA providers/settings
│       │   ├── webhooks/     # Webhook configuration
│       │   └── bulk/         # Import/export
├── openresty/
│   ├── Dockerfile
│   └── lua/
│       ├── waf_handler.lua       # Main WAF logic
│       ├── timing_token.lua      # Form timing detection
│       ├── geoip.lua             # GeoIP restrictions
│       ├── ip_reputation.lua     # IP reputation checks
│       ├── captcha_handler.lua   # CAPTCHA integration
│       ├── webhooks.lua          # Webhook notifications
│       ├── honeypot.lua          # Honeypot detection
│       ├── disposable_domains.lua # Disposable email detection
│       ├── field_learner.lua     # Field learning system
│       └── metrics.lua           # Prometheus metrics
├── haproxy/
│   ├── Dockerfile
│   └── haproxy.cfg
├── helm/forms-waf/           # Helm chart
└── scripts/
    ├── test-waf.sh
    └── load-test.sh
```

---

## Production Considerations

1. **Redis HA**: Use Redis Sentinel or Cluster
2. **TLS**: Enable TLS for all external communication
3. **Admin Security**:
   - Change default password immediately
   - Restrict Admin API access via network policies
4. **GeoIP Databases**: Set up automatic updates for MaxMind databases
5. **Monitoring**: Configure Prometheus alerts for:
   - High block rates
   - Unusual traffic patterns
   - API errors
6. **Logging**: Ship audit logs to centralized logging system
7. **Rate Limits**: Tune based on expected traffic patterns

---

## Troubleshooting

### Common Issues

**GeoIP not working:**
- Verify MaxMind databases are mounted at `/usr/share/GeoIP/`
- Check logs for "geoip: mmdb library not available"

**CAPTCHA verification failing:**
- Verify provider credentials in Admin UI
- Check network connectivity to CAPTCHA provider APIs
- Review timeout settings

**High false positive rate:**
- Review spam score thresholds
- Check keyword lists for overly broad terms
- Enable monitoring mode to analyze before blocking

### Debug Mode

Enable debug headers to troubleshoot:
```bash
# docker-compose.yml
environment:
  - WAF_EXPOSE_HEADERS=true
```

Then check response headers:
```bash
curl -v -X POST http://localhost:8080/submit -d "test=data"
```

---

## License

MIT
