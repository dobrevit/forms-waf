# Forms WAF - Spam Protection System

A multi-layer spam protection system for web forms using OpenResty (Lua) for form parsing/filtering and HAProxy with stick-tables for global rate limiting.

## Architecture Overview

```
Client → Ingress → OpenResty → HAProxy → Backend
                      ↓            ↓
                    Redis    (Stick-table sync)
```

### Components

1. **OpenResty** - Form parsing, content hashing, keyword filtering
   - Parses multipart/form-data, urlencoded, and JSON forms
   - SHA256 hashing of form content for duplicate detection
   - Redis-backed dynamic keyword filtering
   - Pattern-based spam scoring (URLs, XSS, etc.)

2. **HAProxy** - Global rate limiting with stick-table synchronization
   - StatefulSet with peer discovery
   - Stick-tables synced across all replicas
   - Per-hash and per-IP rate limiting
   - Global abuse detection

3. **Redis** - Dynamic configuration store
   - Blocked/flagged keyword lists
   - Blocked content hashes
   - Configuration thresholds
   - IP whitelist

## Quick Start

### Local Development (Docker Compose)

```bash
# Start all services
docker-compose up -d

# With Redis Commander UI (for debugging)
docker-compose --profile tools up -d

# Initialize Redis with default data
docker-compose exec redis sh /init-data.sh

# Test the WAF
./scripts/test-waf.sh http://localhost:8080

# View logs
docker-compose logs -f openresty haproxy
```

### Kubernetes Deployment (Helm)

```bash
# Add Bitnami repo for Redis dependency
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo update

# Build dependencies
cd helm/forms-waf
helm dependency build

# Install
helm install forms-waf . -n forms-waf --create-namespace

# Install with custom values
helm install forms-waf . -n forms-waf --create-namespace \
  -f values-production.yaml \
  --set haproxy.replicaCount=5 \
  --set openresty.autoscaling.enabled=true
```

### Kubernetes Deployment (kd templates)

```bash
# Set environment variables
export NAMESPACE=forms-waf
export RELEASE_NAME=forms-waf
export OPENRESTY_IMAGE=your-registry/forms-waf-openresty
export HAPROXY_IMAGE=your-registry/forms-waf-haproxy

# Deploy
./kd-templates/deploy.sh

# Or with custom environment file
./kd-templates/deploy.sh ./kd-templates/env.production
```

## Configuration

### Redis Keys

| Key | Type | Description |
|-----|------|-------------|
| `waf:keywords:blocked` | SET | Keywords that trigger immediate block |
| `waf:keywords:flagged` | SET | Keywords that add to spam score (format: `keyword:score`) |
| `waf:hashes:blocked` | SET | Content hashes to block |
| `waf:config:thresholds` | HASH | Configuration thresholds |
| `waf:whitelist:ips` | SET | IPs to bypass filtering |

### Thresholds

| Threshold | Default | Description |
|-----------|---------|-------------|
| `spam_score_block` | 80 | Score at which to block immediately |
| `spam_score_flag` | 50 | Score at which to flag for HAProxy |
| `hash_count_block` | 10 | Block if same hash seen N times |
| `ip_rate_limit` | 30 | Max submissions per minute per IP |

### Managing Keywords

```bash
# Using the management script
./scripts/manage-keywords.sh list-blocked
./scripts/manage-keywords.sh add-blocked "spam-word"
./scripts/manage-keywords.sh add-flagged "suspicious" 15

# Using the Admin API
curl http://localhost:8080/waf-admin/keywords/blocked
curl -X POST http://localhost:8080/waf-admin/keywords/blocked \
  -H "Content-Type: application/json" \
  -d '{"keyword":"newspam"}'

# Direct Redis
redis-cli SADD waf:keywords:blocked "spam-keyword"
redis-cli SADD waf:keywords:flagged "suspicious:15"
```

## API Endpoints

### WAF Admin API

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/waf-admin/status` | GET | WAF status and configuration |
| `/waf-admin/keywords/blocked` | GET/POST/DELETE | Manage blocked keywords |
| `/waf-admin/keywords/flagged` | GET/POST | Manage flagged keywords |
| `/waf-admin/hashes/blocked` | GET/POST | Manage blocked hashes |
| `/waf-admin/whitelist/ips` | GET/POST | Manage IP whitelist |
| `/waf-admin/config/thresholds` | GET/POST | Manage thresholds |
| `/waf-admin/sync` | POST | Force Redis sync |

### HAProxy Stats

- Stats UI: `http://localhost:8404/stats`
- Prometheus metrics: `http://localhost:8404/metrics`

## Testing

```bash
# Run test suite
./scripts/test-waf.sh http://localhost:8080

# Load testing
./scripts/load-test.sh http://localhost:8080 30s 100

# Manual tests
# Legitimate request
curl -X POST http://localhost:8080/submit \
  -d "name=John&email=john@example.com&message=Hello"

# Should be blocked (contains blocked keyword)
curl -X POST http://localhost:8080/submit \
  -d "name=Spammer&message=Buy viagra now!"

# Should be blocked (high spam score)
curl -X POST http://localhost:8080/submit \
  -d "message=FREE winner! Click here! Limited time! Act now!"
```

## Headers

### Request Headers (OpenResty → HAProxy)

| Header | Description |
|--------|-------------|
| `X-Form-Hash` | SHA256 hash of normalized form content |
| `X-Spam-Score` | Calculated spam score (0-100+) |
| `X-Spam-Flags` | Comma-separated list of triggered flags |
| `X-Client-IP` | Original client IP |
| `X-Blocked` | Set to "true" if blocked by OpenResty |

### Response Headers (HAProxy → Client)

| Header | Description |
|--------|-------------|
| `X-WAF-Hash-Count` | How many times this hash has been seen |
| `X-WAF-IP-Rate` | Current request rate for this IP |

## Project Structure

```
forms-waf/
├── docker-compose.yml        # Local development
├── openresty/
│   ├── Dockerfile
│   ├── conf/nginx.conf
│   └── lua/
│       ├── waf_handler.lua      # Main WAF logic
│       ├── form_parser.lua      # Form parsing
│       ├── content_hasher.lua   # Content hashing
│       ├── keyword_filter.lua   # Keyword filtering
│       ├── redis_sync.lua       # Redis synchronization
│       ├── waf_config.lua       # Configuration
│       ├── admin_api.lua        # Admin API
│       └── metrics.lua          # Prometheus metrics
├── haproxy/
│   ├── Dockerfile
│   ├── haproxy.cfg
│   └── docker-entrypoint.sh
├── redis/
│   ├── redis.conf
│   └── init-data.sh
├── helm/forms-waf/           # Helm chart
│   ├── Chart.yaml
│   ├── values.yaml
│   └── templates/
├── kd-templates/             # kd deployment templates
│   ├── deploy.sh
│   ├── env.default
│   └── *.yaml
├── scripts/
│   ├── test-waf.sh
│   ├── load-test.sh
│   └── manage-keywords.sh
└── docs/
    └── ARCHITECTURE.md
```

## Production Considerations

1. **Redis HA**: Use Redis Sentinel or Cluster for high availability
2. **TLS**: Enable TLS for HAProxy peer communication
3. **Authentication**: Protect admin API with authentication
4. **Monitoring**: Enable Prometheus metrics and alerts
5. **Logging**: Configure structured logging for analysis
6. **Tuning**: Adjust stick-table sizes based on traffic

## License

MIT
