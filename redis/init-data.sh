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
    "paths": ["/api/contact", "/contact/submit"],
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

echo "Redis initialization complete!"

# Show loaded data
echo ""
echo "=== Loaded Data Summary ==="
echo "Blocked keywords: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:keywords:blocked)"
echo "Flagged keywords: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:keywords:flagged)"
echo "Whitelisted IPs: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:whitelist:ips)"
echo "Endpoint configs: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZCARD waf:endpoints:index)"
echo "Thresholds:"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HGETALL waf:config:thresholds
echo ""
echo "Endpoints:"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ZRANGE waf:endpoints:index 0 -1 WITHSCORES
