#!/bin/bash
# Keyword management script for Forms WAF
# Usage: ./manage-keywords.sh <command> [args]

set -e

REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"
WAF_URL="${WAF_URL:-http://localhost:8080}"

usage() {
    cat << EOF
Forms WAF Keyword Management

Usage: $0 <command> [args]

Commands:
  list-blocked              List all blocked keywords
  list-flagged              List all flagged keywords
  list-hashes               List all blocked hashes
  list-whitelist            List whitelisted IPs

  add-blocked <keyword>     Add a blocked keyword
  add-flagged <keyword> [score]  Add a flagged keyword with optional score (default: 10)
  add-hash <hash>           Add a blocked hash
  add-whitelist <ip>        Add IP to whitelist

  remove-blocked <keyword>  Remove a blocked keyword
  remove-flagged <keyword>  Remove a flagged keyword
  remove-hash <hash>        Remove a blocked hash
  remove-whitelist <ip>     Remove IP from whitelist

  import-blocked <file>     Import blocked keywords from file (one per line)
  import-flagged <file>     Import flagged keywords from file (format: keyword:score)

  stats                     Show WAF statistics
  sync                      Force Redis sync

Options:
  --redis-host HOST    Redis host (default: localhost)
  --redis-port PORT    Redis port (default: 6379)
  --waf-url URL        WAF admin URL (default: http://localhost:8080)

Examples:
  $0 add-blocked "spam-keyword"
  $0 add-flagged "suspicious" 15
  $0 import-blocked keywords.txt
  $0 stats
EOF
}

# Parse global options
while [[ $# -gt 0 ]]; do
    case $1 in
        --redis-host)
            REDIS_HOST="$2"
            shift 2
            ;;
        --redis-port)
            REDIS_PORT="$2"
            shift 2
            ;;
        --waf-url)
            WAF_URL="$2"
            shift 2
            ;;
        *)
            break
            ;;
    esac
done

COMMAND="${1:-}"
shift || true

redis_cmd() {
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" "$@"
}

waf_api() {
    local method="$1"
    local endpoint="$2"
    local data="$3"

    if [ -n "$data" ]; then
        curl -s -X "$method" "$WAF_URL/waf-admin$endpoint" \
            -H "Content-Type: application/json" \
            -d "$data"
    else
        curl -s -X "$method" "$WAF_URL/waf-admin$endpoint"
    fi
}

case "$COMMAND" in
    list-blocked)
        echo "Blocked Keywords:"
        redis_cmd SMEMBERS waf:keywords:blocked | sort
        ;;

    list-flagged)
        echo "Flagged Keywords (keyword:score):"
        redis_cmd SMEMBERS waf:keywords:flagged | sort
        ;;

    list-hashes)
        echo "Blocked Hashes:"
        redis_cmd SMEMBERS waf:hashes:blocked
        ;;

    list-whitelist)
        echo "Whitelisted IPs:"
        redis_cmd SMEMBERS waf:whitelist:ips
        ;;

    add-blocked)
        keyword="$1"
        if [ -z "$keyword" ]; then
            echo "Error: keyword required"
            exit 1
        fi
        redis_cmd SADD waf:keywords:blocked "$keyword"
        echo "Added blocked keyword: $keyword"
        ;;

    add-flagged)
        keyword="$1"
        score="${2:-10}"
        if [ -z "$keyword" ]; then
            echo "Error: keyword required"
            exit 1
        fi
        redis_cmd SADD waf:keywords:flagged "${keyword}:${score}"
        echo "Added flagged keyword: $keyword (score: $score)"
        ;;

    add-hash)
        hash="$1"
        if [ -z "$hash" ]; then
            echo "Error: hash required"
            exit 1
        fi
        redis_cmd SADD waf:hashes:blocked "$hash"
        echo "Added blocked hash: $hash"
        ;;

    add-whitelist)
        ip="$1"
        if [ -z "$ip" ]; then
            echo "Error: IP required"
            exit 1
        fi
        redis_cmd SADD waf:whitelist:ips "$ip"
        echo "Added whitelisted IP: $ip"
        ;;

    remove-blocked)
        keyword="$1"
        if [ -z "$keyword" ]; then
            echo "Error: keyword required"
            exit 1
        fi
        redis_cmd SREM waf:keywords:blocked "$keyword"
        echo "Removed blocked keyword: $keyword"
        ;;

    remove-flagged)
        keyword="$1"
        if [ -z "$keyword" ]; then
            echo "Error: keyword required"
            exit 1
        fi
        # Remove all entries matching the keyword (any score)
        for entry in $(redis_cmd SMEMBERS waf:keywords:flagged | grep "^${keyword}:"); do
            redis_cmd SREM waf:keywords:flagged "$entry"
        done
        echo "Removed flagged keyword: $keyword"
        ;;

    remove-hash)
        hash="$1"
        if [ -z "$hash" ]; then
            echo "Error: hash required"
            exit 1
        fi
        redis_cmd SREM waf:hashes:blocked "$hash"
        echo "Removed blocked hash: $hash"
        ;;

    remove-whitelist)
        ip="$1"
        if [ -z "$ip" ]; then
            echo "Error: IP required"
            exit 1
        fi
        redis_cmd SREM waf:whitelist:ips "$ip"
        echo "Removed whitelisted IP: $ip"
        ;;

    import-blocked)
        file="$1"
        if [ -z "$file" ] || [ ! -f "$file" ]; then
            echo "Error: valid file required"
            exit 1
        fi
        count=0
        while IFS= read -r keyword; do
            [ -z "$keyword" ] && continue
            [[ "$keyword" =~ ^# ]] && continue
            redis_cmd SADD waf:keywords:blocked "$keyword"
            ((count++))
        done < "$file"
        echo "Imported $count blocked keywords"
        ;;

    import-flagged)
        file="$1"
        if [ -z "$file" ] || [ ! -f "$file" ]; then
            echo "Error: valid file required"
            exit 1
        fi
        count=0
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            [[ "$line" =~ ^# ]] && continue
            redis_cmd SADD waf:keywords:flagged "$line"
            ((count++))
        done < "$file"
        echo "Imported $count flagged keywords"
        ;;

    stats)
        echo "=== WAF Statistics ==="
        echo ""
        echo "Keywords:"
        echo "  Blocked: $(redis_cmd SCARD waf:keywords:blocked)"
        echo "  Flagged: $(redis_cmd SCARD waf:keywords:flagged)"
        echo ""
        echo "Blocklists:"
        echo "  Blocked hashes: $(redis_cmd SCARD waf:hashes:blocked)"
        echo "  Whitelisted IPs: $(redis_cmd SCARD waf:whitelist:ips)"
        echo ""
        echo "Thresholds:"
        redis_cmd HGETALL waf:config:thresholds | paste - - | while read key value; do
            echo "  $key: $value"
        done
        ;;

    sync)
        echo "Forcing WAF sync..."
        waf_api POST /sync
        echo "Sync triggered"
        ;;

    *)
        usage
        exit 1
        ;;
esac
