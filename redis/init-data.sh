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

echo "Redis initialization complete!"

# Show loaded data
echo ""
echo "=== Loaded Data Summary ==="
echo "Blocked keywords: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:keywords:blocked)"
echo "Flagged keywords: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:keywords:flagged)"
echo "Whitelisted IPs: $(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" SCARD waf:whitelist:ips)"
echo "Thresholds:"
redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" HGETALL waf:config:thresholds
