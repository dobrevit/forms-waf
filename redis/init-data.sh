#!/bin/sh
# Initialize Redis with default WAF data

REDIS_HOST=${REDIS_HOST:-localhost}
REDIS_PORT=${REDIS_PORT:-6379}

echo "Initializing Redis with default WAF data..."

# Wait for Redis to be ready
until redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping 2>/dev/null | grep -q PONG; do
    echo "Waiting for Redis..."
    sleep 1
done

echo "Redis is ready. Loading initial data..."

# Blocked keywords (immediate rejection)
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SADD waf:keywords:blocked \
    "viagra" \
    "cialis" \
    "casino" \
    "poker" \
    "lottery" \
    "crypto-investment" \
    "bitcoin-profit" \
    "forex-trading" \
    "earn-money-fast" \
    "work-from-home-opportunity" \
    "nigerian-prince" \
    "inheritance-fund" \
    "weight-loss-miracle" \
    "male-enhancement" \
    "adult-content" \
    "xxx" \
    "porn" \
    "webcam-girls"

echo "Loaded blocked keywords"

# Flagged keywords (add to spam score) - format: keyword:score
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SADD waf:keywords:flagged \
    "free:10" \
    "winner:15" \
    "click here:10" \
    "urgent:10" \
    "act now:10" \
    "limited time:10" \
    "exclusive offer:10" \
    "discount:5" \
    "cheap:5" \
    "buy now:10" \
    "subscribe:5" \
    "unsubscribe:5" \
    "guarantee:5" \
    "no obligation:10" \
    "risk free:10" \
    "100% free:15" \
    "double your:15" \
    "earn extra:10" \
    "extra income:10" \
    "make money:10" \
    "million dollars:15" \
    "cash bonus:10" \
    "credit card:5" \
    "investment:5" \
    "opportunity:5" \
    "incredible:5" \
    "amazing:5" \
    "congratulations:10" \
    "dear friend:10" \
    "dear sir:5"

echo "Loaded flagged keywords"

# Default thresholds
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET waf:config:thresholds \
    spam_score_block 80 \
    spam_score_flag 50 \
    hash_count_block 10 \
    hash_unique_ips_block 5 \
    ip_rate_limit 30 \
    ip_daily_limit 500

echo "Loaded default thresholds"

# Whitelist internal IPs (example)
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SADD waf:whitelist:ips \
    "127.0.0.1" \
    "10.0.0.0/8" \
    "172.16.0.0/12" \
    "192.168.0.0/16"

echo "Loaded IP whitelist"

# ============================================================================
# Admin User Configuration
# ============================================================================

echo "Loading admin user configuration..."

# Default admin user
# Password: changeme (SHA-256 hashed with salt)
# IMPORTANT: Change this password on first login!
# The hash is: SHA256(salt + "changeme" + salt) where salt = "waf_admin_salt_v1"
# Pre-computed: echo -n "waf_admin_salt_v1changemewaf_admin_salt_v1" | sha256sum
ADMIN_USER='{
  "username": "admin",
  "password_hash": "6e5f4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e",
  "salt": "waf_admin_salt_v1",
  "role": "admin",
  "must_change_password": true,
  "created_at": "2024-01-01T00:00:00Z"
}'

# We need to compute the actual hash - using shell
ADMIN_SALT="waf_admin_salt_v1"
ADMIN_PASSWORD="changeme"
# Note: In production, use a proper password hashing library like bcrypt
# This SHA-256 approach is simplified for the init script
ADMIN_HASH=$(echo -n "${ADMIN_SALT}${ADMIN_PASSWORD}${ADMIN_SALT}" | sha256sum | cut -d' ' -f1)

ADMIN_USER_JSON=$(cat <<EOF
{
  "username": "admin",
  "password_hash": "${ADMIN_HASH}",
  "salt": "${ADMIN_SALT}",
  "role": "admin",
  "must_change_password": true,
  "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF
)

redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:admin:users:admin" "$ADMIN_USER_JSON"

echo "Loaded default admin user (username: admin, password: changeme)"
echo "WARNING: Change the default password on first login!"

# ============================================================================
# Example Endpoint Configurations
# ============================================================================

echo "Loading example endpoint configurations..."

# Example 1: Passthrough endpoint for health checks and webhooks
HEALTH_ENDPOINT='{
  "id": "health-endpoints",
  "name": "Health Check Endpoints",
  "description": "Skip WAF for health check and monitoring endpoints",
  "enabled": true,
  "mode": "passthrough",
  "matching": {
    "paths": ["/health", "/ready", "/live", "/metrics"],
    "path_prefix": "/healthz/",
    "methods": ["GET", "HEAD"]
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:endpoints:config:health-endpoints" "$HEALTH_ENDPOINT"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:endpoints:index" 10 "health-endpoints"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:endpoints:paths:exact" "/health:GET" "health-endpoints"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:endpoints:paths:exact" "/ready:GET" "health-endpoints"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:endpoints:paths:exact" "/live:GET" "health-endpoints"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:endpoints:paths:exact" "/metrics:GET" "health-endpoints"

# Example 2: Strict contact form protection
CONTACT_ENDPOINT='{
  "id": "contact-form",
  "name": "Contact Form",
  "description": "Public contact form with strict spam protection",
  "enabled": true,
  "mode": "blocking",
  "matching": {
    "paths": ["/api/contact", "/contact/submit", "/contact"],
    "methods": ["POST"],
    "content_types": ["application/json", "application/x-www-form-urlencoded"]
  },
  "thresholds": {
    "spam_score_block": 60,
    "spam_score_flag": 30,
    "ip_rate_limit": 5
  },
  "keywords": {
    "inherit_global": true,
    "additional_blocked": [],
    "additional_flagged": ["website:5", "seo:10", "backlink:15"]
  },
  "fields": {
    "required": ["email", "message"],
    "max_length": {"message": 5000, "name": 100}
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:endpoints:config:contact-form" "$CONTACT_ENDPOINT"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:endpoints:index" 50 "contact-form"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:endpoints:paths:exact" "/api/contact:POST" "contact-form"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:endpoints:paths:exact" "/contact/submit:POST" "contact-form"

# Example 3: Monitoring mode for new API endpoints
MONITORING_ENDPOINT='{
  "id": "api-monitoring",
  "name": "API Monitoring",
  "description": "Monitor API endpoints without blocking (for testing)",
  "enabled": true,
  "mode": "monitoring",
  "matching": {
    "path_prefix": "/api/v2/"
  },
  "thresholds": {
    "spam_score_block": 80
  },
  "keywords": {
    "inherit_global": true
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:endpoints:config:api-monitoring" "$MONITORING_ENDPOINT"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:endpoints:index" 80 "api-monitoring"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:endpoints:paths:prefix" 80 "/api/v2/|*|api-monitoring"

# Example 4: Webhook passthrough
WEBHOOK_ENDPOINT='{
  "id": "webhooks",
  "name": "Webhook Endpoints",
  "description": "Allow external webhooks without WAF filtering",
  "enabled": true,
  "mode": "passthrough",
  "matching": {
    "path_prefix": "/webhooks/"
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:endpoints:config:webhooks" "$WEBHOOK_ENDPOINT"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:endpoints:index" 20 "webhooks"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:endpoints:paths:prefix" 20 "/webhooks/|*|webhooks"

echo "Loaded example endpoint configurations"

# ============================================================================
# Example Virtual Host Configurations
# ============================================================================

echo "Loading example virtual host configurations..."

# Default vhost - catch-all for unmatched hosts
DEFAULT_VHOST='{
  "id": "_default",
  "name": "Default Virtual Host",
  "description": "Catch-all configuration for unmatched hosts",
  "enabled": true,
  "hostnames": [],
  "waf": {
    "enabled": true,
    "mode": "monitoring"
  },
  "routing": {
    "use_haproxy": true
  },
  "thresholds": {
    "spam_score_block": 80,
    "spam_score_flag": 50
  },
  "keywords": {
    "inherit_global": true,
    "additional_blocked": [],
    "additional_flagged": [],
    "exclusions": []
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:vhosts:config:_default" "$DEFAULT_VHOST"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:index" 0 "_default"

echo "Loaded default vhost"

# Example 1: Main website with HAProxy routing
MAIN_WEBSITE_VHOST='{
  "id": "main-website",
  "name": "Main Website",
  "description": "Primary website with strict WAF protection",
  "enabled": true,
  "hostnames": ["example.com", "www.example.com"],
  "waf": {
    "enabled": true,
    "mode": "blocking"
  },
  "routing": {
    "use_haproxy": true,
    "haproxy_backend": "website_backend"
  },
  "thresholds": {
    "spam_score_block": 60,
    "spam_score_flag": 30,
    "ip_rate_limit": 10
  },
  "keywords": {
    "inherit_global": true,
    "additional_blocked": ["competitor-spam"],
    "additional_flagged": ["promo:5", "deal:5"],
    "exclusions": []
  },
  "endpoints": {
    "inherit_global": true,
    "overrides": {}
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:vhosts:config:main-website" "$MAIN_WEBSITE_VHOST"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:index" 100 "main-website"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:vhosts:hosts:exact" "example.com" "main-website"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:vhosts:hosts:exact" "www.example.com" "main-website"

echo "Loaded main-website vhost"

# Example 2: API subdomain with direct upstream (bypassing HAProxy)
API_VHOST='{
  "id": "api-subdomain",
  "name": "API Subdomain",
  "description": "API with direct upstream routing",
  "enabled": true,
  "hostnames": ["api.example.com"],
  "waf": {
    "enabled": true,
    "mode": "blocking"
  },
  "routing": {
    "use_haproxy": false,
    "upstream": {
      "servers": ["10.0.1.10:8080", "10.0.1.11:8080"],
      "health_check": "/health",
      "timeout": 30
    }
  },
  "thresholds": {
    "spam_score_block": 100,
    "ip_rate_limit": 100
  },
  "keywords": {
    "inherit_global": true
  },
  "endpoints": {
    "inherit_global": true
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:vhosts:config:api-subdomain" "$API_VHOST"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:index" 100 "api-subdomain"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:vhosts:hosts:exact" "api.example.com" "api-subdomain"

echo "Loaded api-subdomain vhost"

# Example 3: Wildcard subdomain for customer sites
CUSTOMER_WILDCARD_VHOST='{
  "id": "customer-sites",
  "name": "Customer Sites Wildcard",
  "description": "Wildcard match for customer subdomains",
  "enabled": true,
  "hostnames": ["*.customers.example.com"],
  "waf": {
    "enabled": true,
    "mode": "monitoring"
  },
  "routing": {
    "use_haproxy": true,
    "haproxy_backend": "customer_backend"
  },
  "thresholds": {
    "spam_score_block": 70
  },
  "keywords": {
    "inherit_global": true,
    "exclusions": ["free"]
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:vhosts:config:customer-sites" "$CUSTOMER_WILDCARD_VHOST"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:index" 100 "customer-sites"
# Wildcard patterns use a sorted set with priority
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:hosts:wildcard" 100 "*.customers.example.com|customer-sites"

echo "Loaded customer-sites wildcard vhost"

# Example 4: Staging environment (passthrough mode for testing)
STAGING_VHOST='{
  "id": "staging-env",
  "name": "Staging Environment",
  "description": "Staging servers with WAF in passthrough mode",
  "enabled": true,
  "hostnames": ["staging.example.com", "*.staging.example.com"],
  "waf": {
    "enabled": true,
    "mode": "passthrough"
  },
  "routing": {
    "use_haproxy": false,
    "upstream": {
      "servers": ["staging-backend:8080"]
    }
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:vhosts:config:staging-env" "$STAGING_VHOST"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:index" 100 "staging-env"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:vhosts:hosts:exact" "staging.example.com" "staging-env"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:hosts:wildcard" 90 "*.staging.example.com|staging-env"

echo "Loaded staging-env vhost"

# Example 5: Partner portal with custom keywords
PARTNER_VHOST='{
  "id": "partner-portal",
  "name": "Partner Portal",
  "description": "Partner-facing portal with relaxed keyword filtering",
  "enabled": true,
  "hostnames": ["partners.example.com"],
  "waf": {
    "enabled": true,
    "mode": "blocking"
  },
  "routing": {
    "use_haproxy": true,
    "haproxy_backend": "partner_backend"
  },
  "thresholds": {
    "spam_score_block": 90,
    "spam_score_flag": 60
  },
  "keywords": {
    "inherit_global": true,
    "exclusions": ["investment", "opportunity", "subscribe"],
    "additional_flagged": ["unauthorized:20", "reseller:10"]
  },
  "endpoints": {
    "inherit_global": false,
    "custom": []
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:vhosts:config:partner-portal" "$PARTNER_VHOST"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:index" 100 "partner-portal"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:vhosts:hosts:exact" "partners.example.com" "partner-portal"

echo "Loaded partner-portal vhost"

# Example 6: Disabled vhost (for maintenance)
MAINTENANCE_VHOST='{
  "id": "maintenance-site",
  "name": "Maintenance Site",
  "description": "Site under maintenance - disabled",
  "enabled": false,
  "hostnames": ["maintenance.example.com"],
  "waf": {
    "enabled": false
  },
  "routing": {
    "use_haproxy": true
  }
}'
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SET "waf:vhosts:config:maintenance-site" "$MAINTENANCE_VHOST"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZADD "waf:vhosts:index" 100 "maintenance-site"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HSET "waf:vhosts:hosts:exact" "maintenance.example.com" "maintenance-site"

echo "Loaded maintenance-site vhost (disabled)"

echo "Loaded example virtual host configurations"

echo "Redis initialization complete!"

# Show loaded data
echo ""
echo "=== Loaded Data Summary ==="
echo "Blocked keywords: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:keywords:blocked)"
echo "Flagged keywords: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:keywords:flagged)"
echo "Whitelisted IPs: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:whitelist:ips)"
echo "Endpoint configs: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZCARD waf:endpoints:index)"
echo "Virtual hosts: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZCARD waf:vhosts:index)"
echo "Exact host mappings: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HLEN waf:vhosts:hosts:exact)"
echo "Wildcard host patterns: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZCARD waf:vhosts:hosts:wildcard)"
echo "Admin users configured: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" KEYS 'waf:admin:users:*' | wc -l)"
echo ""
echo "Thresholds:"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HGETALL waf:config:thresholds
echo ""
echo "Endpoints:"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZRANGE waf:endpoints:index 0 -1 WITHSCORES
echo ""
echo "Virtual Hosts:"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZRANGE waf:vhosts:index 0 -1 WITHSCORES
echo ""
echo "Host Mappings (exact):"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HGETALL waf:vhosts:hosts:exact
echo ""
echo "Host Mappings (wildcard):"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZRANGE waf:vhosts:hosts:wildcard 0 -1 WITHSCORES
echo ""
echo "=== Admin UI Access ==="
echo "URL: http://localhost:8082"
echo "Default credentials: admin / changeme"
echo "WARNING: Change password on first login!"
