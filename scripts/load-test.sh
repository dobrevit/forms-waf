#!/bin/bash
# Load testing script for Forms WAF
# Requires: wrk or ab (Apache Benchmark)
# Usage: ./load-test.sh [base_url] [duration] [connections]

BASE_URL="${1:-http://localhost:8080}"
DURATION="${2:-30s}"
CONNECTIONS="${3:-100}"
THREADS="${4:-4}"

echo "========================================"
echo "Forms WAF Load Test"
echo "========================================"
echo "URL: $BASE_URL"
echo "Duration: $DURATION"
echo "Connections: $CONNECTIONS"
echo "Threads: $THREADS"
echo ""

# Check for wrk
if command -v wrk &> /dev/null; then
    echo "Using wrk for load testing..."

    # Create Lua script for POST requests
    cat > /tmp/waf-loadtest.lua << 'EOF'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"

counter = 0

request = function()
    counter = counter + 1
    local body = "name=User" .. counter .. "&email=test" .. counter .. "@example.com&message=Load test message " .. counter
    return wrk.format(nil, "/submit", nil, body)
end

response = function(status, headers, body)
    if status ~= 200 then
        -- Track non-200 responses
    end
end
EOF

    echo ""
    echo "--- Legitimate Traffic Test ---"
    wrk -t$THREADS -c$CONNECTIONS -d$DURATION -s /tmp/waf-loadtest.lua "$BASE_URL"

    echo ""
    echo "--- Spam Traffic Test ---"
    cat > /tmp/waf-spam.lua << 'EOF'
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/x-www-form-urlencoded"

counter = 0

request = function()
    counter = counter + 1
    -- Mix of spam and legitimate traffic
    local body
    if counter % 10 == 0 then
        body = "name=Spammer&message=Buy viagra free winner click here now"
    else
        body = "name=User" .. counter .. "&message=Normal message " .. counter
    end
    return wrk.format(nil, "/submit", nil, body)
end
EOF

    wrk -t$THREADS -c$CONNECTIONS -d$DURATION -s /tmp/waf-spam.lua "$BASE_URL"

    # Cleanup
    rm -f /tmp/waf-loadtest.lua /tmp/waf-spam.lua

elif command -v ab &> /dev/null; then
    echo "Using Apache Benchmark (ab)..."

    # Convert duration to number of requests (rough estimate)
    REQUESTS=$((${DURATION%s} * 100))

    echo ""
    echo "--- Legitimate Traffic Test ---"
    ab -n $REQUESTS -c $CONNECTIONS -p /dev/stdin -T 'application/x-www-form-urlencoded' \
        "$BASE_URL/submit" <<< "name=TestUser&email=test@example.com&message=Load test message"

else
    echo "Neither 'wrk' nor 'ab' found. Installing options:"
    echo ""
    echo "Ubuntu/Debian:"
    echo "  sudo apt-get install wrk apache2-utils"
    echo ""
    echo "macOS:"
    echo "  brew install wrk"
    echo ""
    echo "Manual test with curl:"
    echo "  for i in {1..100}; do curl -s -o /dev/null -w '%{http_code}\n' -X POST $BASE_URL/submit -d 'name=test&message=test' & done; wait"
    exit 1
fi

echo ""
echo "========================================"
echo "Load Test Complete"
echo "========================================"
