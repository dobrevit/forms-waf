# Forms WAF - Spam Protection System

A multi-layer spam protection system for web forms using OpenResty (Lua) for form parsing/filtering and HAProxy with stick-tables for global rate limiting. Includes a modern React-based Admin UI for configuration management.

## Architecture Overview

```
Client → Ingress → OpenResty → HAProxy → Backend
                      ↓            ↓
                    Redis    (Stick-table sync)
                      ↑
                  Admin UI
```

### Components

1. **OpenResty** - Form parsing, content hashing, keyword filtering
   - Parses multipart/form-data, urlencoded, and JSON forms
   - SHA256 hashing of form content for duplicate detection
   - Redis-backed dynamic keyword filtering
   - Pattern-based spam scoring (URLs, XSS, etc.)
   - **Virtual host (vhost) support** - Multi-tenant with per-host configuration
   - **Dynamic endpoint configuration** - Per-endpoint WAF rules and thresholds

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
   - **Virtual host configurations**
   - **Endpoint configurations**

4. **Admin UI** - React-based management dashboard
   - Session-based authentication with password management
   - Virtual host management (multi-tenant)
   - Endpoint configuration with per-endpoint thresholds
   - Keyword management (blocked/flagged with scores)
   - Real-time configuration updates

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
| `waf:config:thresholds` | HASH | Global configuration thresholds |
| `waf:config:routing` | HASH | Global routing configuration (HAProxy upstream) |
| `waf:whitelist:ips` | SET | IPs to bypass filtering |
| `waf:vhosts:index` | ZSET | Virtual host IDs by priority |
| `waf:vhosts:config:{id}` | STRING | Virtual host configuration (JSON) |
| `waf:vhosts:hosts:exact` | HASH | Exact hostname to vhost mapping |
| `waf:vhosts:hosts:wildcard` | ZSET | Wildcard hostname patterns |
| `waf:endpoints:index` | ZSET | Endpoint IDs by priority |
| `waf:endpoints:config:{id}` | STRING | Endpoint configuration (JSON) |
| `waf:endpoints:paths:exact` | HASH | Exact path to endpoint mapping |

### Thresholds

| Threshold | Default | Description |
|-----------|---------|-------------|
| `spam_score_block` | 80 | Score at which to block immediately |
| `spam_score_flag` | 50 | Score at which to flag for HAProxy |
| `hash_count_block` | 10 | Block if same hash seen N times |
| `ip_rate_limit` | 30 | Max submissions per minute per IP |
| `ip_daily_limit` | 500 | Max submissions per day per IP |
| `hash_unique_ips_block` | 5 | Block hash if seen from N unique IPs |

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

### Authentication (Port 8082)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Login with username/password |
| `/api/auth/logout` | POST | End session |
| `/api/auth/verify` | GET | Verify session validity |
| `/api/auth/change-password` | POST | Change password |

### WAF Admin API (Port 8082, requires authentication)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | WAF status and configuration |
| `/api/keywords/blocked` | GET/POST/PUT/DELETE | Manage blocked keywords |
| `/api/keywords/flagged` | GET/POST/PUT/DELETE | Manage flagged keywords |
| `/api/hashes/blocked` | GET/POST/DELETE | Manage blocked hashes |
| `/api/whitelist/ips` | GET/POST/DELETE | Manage IP whitelist |
| `/api/config/thresholds` | GET/POST | Manage global thresholds |
| `/api/config/routing` | GET/PUT | Manage global routing (HAProxy upstream) |
| `/api/vhosts` | GET/POST | List/create virtual hosts |
| `/api/vhosts/{id}` | GET/PUT/DELETE | Manage virtual host |
| `/api/vhosts/{id}/enable` | POST | Enable virtual host |
| `/api/vhosts/{id}/disable` | POST | Disable virtual host |
| `/api/vhosts/match` | GET | Test hostname matching |
| `/api/vhosts/context` | GET | Get full request context |
| `/api/endpoints` | GET/POST | List/create endpoints |
| `/api/endpoints/{id}` | GET/PUT/DELETE | Manage endpoint |
| `/api/endpoints/{id}/enable` | POST | Enable endpoint |
| `/api/endpoints/{id}/disable` | POST | Disable endpoint |
| `/api/endpoints/match` | GET | Test path matching |
| `/api/sync` | POST | Force Redis sync |

### HAProxy Stats

- Stats UI: `http://localhost:8404/stats`
- Prometheus metrics: `http://localhost:8404/metrics`

### Admin UI

Access the Admin UI at `http://localhost:3000` (development) or via the configured ingress.

Default credentials: `admin` / `changeme` (must be changed on first login)

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
├── admin-ui/                 # React Admin Dashboard
│   ├── src/
│   │   ├── api/              # API client and types
│   │   ├── components/       # UI components (shadcn/ui)
│   │   ├── contexts/         # Auth context
│   │   └── pages/            # Page components
│   │       ├── vhosts/       # Virtual host management
│   │       ├── endpoints/    # Endpoint configuration
│   │       ├── keywords/     # Keyword management
│   │       └── config/       # Global configuration
│   └── package.json
├── openresty/
│   ├── Dockerfile
│   ├── conf/nginx.conf
│   └── lua/
│       ├── waf_handler.lua      # Main WAF logic
│       ├── form_parser.lua      # Form parsing
│       ├── content_hasher.lua   # Content hashing
│       ├── keyword_filter.lua   # Keyword filtering
│       ├── redis_sync.lua       # Redis synchronization
│       ├── waf_config.lua       # Global configuration
│       ├── admin_api.lua        # Admin API endpoints
│       ├── admin_auth.lua       # Session authentication
│       ├── vhost_matcher.lua    # Virtual host matching
│       ├── vhost_resolver.lua   # Request context resolution
│       ├── endpoint_matcher.lua # Endpoint matching
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
│   ├── files/lua/            # Lua modules for ConfigMap
│   └── templates/
│       ├── admin-ui-*.yaml   # Admin UI deployment
│       └── ...
├── kd-templates/             # kd deployment templates
│   ├── deploy.sh
│   ├── env.default
│   └── *.yaml
├── scripts/
│   ├── test-waf.sh
│   ├── load-test.sh
│   └── manage-keywords.sh
└── docs/
    ├── ARCHITECTURE.md
    ├── ENDPOINT_CONFIGURATION.md
    └── ADMIN_API_SEPARATION.md
```

## Production Considerations

1. **Redis HA**: Use Redis Sentinel or Cluster for high availability
2. **TLS**: Enable TLS for HAProxy peer communication
3. **Admin UI Security**:
   - Change default admin password immediately
   - Run Admin UI behind ingress with TLS
   - Consider network policies to restrict access
4. **Admin API**: Runs on dedicated port 8082 (not exposed externally)
5. **Monitoring**: Enable Prometheus metrics and alerts
6. **Logging**: Configure structured logging for analysis
7. **Tuning**: Adjust stick-table sizes based on traffic

## Key Features

### Multi-Tenant Virtual Hosts
- Configure per-host WAF rules
- Wildcard hostname support (e.g., `*.example.com`)
- Per-vhost routing to different HAProxy backends
- Override global thresholds per vhost

### Dynamic Endpoint Configuration
- Per-endpoint WAF modes (blocking, monitoring, passthrough, strict)
- Custom thresholds per endpoint
- Rate limiting per endpoint
- Field validation (required fields, max lengths, ignored fields)
- Vhost-scoped endpoints (priority over global)

### Keyword Management
- Blocked keywords: Immediate rejection
- Flagged keywords: Score-based with customizable weights
- Edit/update keywords atomically via API

## License

MIT
