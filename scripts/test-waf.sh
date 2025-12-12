#!/bin/bash
# Test script for Forms WAF
# Usage: ./test-waf.sh [base_url]

set -e
#set -x

BASE_URL="${1:-http://localhost:8080}"
PASS=0
FAIL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    PASS=$((PASS+1))
    return 0
}

log_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    FAIL=$((FAIL+1))
    return 0
}

log_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

test_request() {
    local name="$1"
    local expected_status="$2"
    local method="$3"
    local endpoint="$4"
    shift 4
    local data="$@"

    local response
    local status

    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$BASE_URL$endpoint" "$data")
    fi

    status=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$status" = "$expected_status" ]; then
        log_pass "$name (status: $status)"
    else
        log_fail "$name (expected: $expected_status, got: $status)"
        echo "  Response: $body"
    fi
}

echo "========================================"
echo "Forms WAF Test Suite"
echo "Base URL: $BASE_URL"
echo "========================================"
echo ""

# Wait for service to be ready
log_info "Checking service health..."
for i in {1..30}; do
    if curl -s "$BASE_URL/health" > /dev/null 2>&1; then
        log_pass "Service is healthy"
        break
    fi
    if [ $i -eq 30 ]; then
        log_fail "Service not responding after 30 seconds"
        exit 1
    fi
    sleep 1
done
echo ""

# Test 1: Legitimate form submission
log_info "Testing legitimate form submissions..."
test_request "Simple contact form" "200" "POST" "/submit" \
    -d "name=John Doe" -d "email=john@example.com" -d "message=Hello, this is a test message"

test_request "Form with special characters" "200" "POST" "/submit" \
    -d "name=Jane O'Brien" -d "message=Testing special chars: <>&\""

test_request "JSON form submission" "200" "POST" "/submit" \
    -H "Content-Type: application/json" \
    -d '{"name":"Test User","email":"test@example.com","message":"JSON submission test"}'

echo ""

# Test 2: Blocked keywords (should return 403)
log_info "Testing blocked keywords..."
test_request "Blocked keyword: viagra" "403" "POST" "/submit" \
    -d "name=Spammer" -d "message=Buy viagra now!"

test_request "Blocked keyword: casino" "403" "POST" "/submit" \
    -d "name=Spammer" -d "message=Best casino online"

test_request "Blocked keyword: crypto-investment" "403" "POST" "/submit" \
    -d "name=Scammer" -d "message=Amazing crypto-investment opportunity"

echo ""

# Test 3: Flagged keywords (adds to spam score)
log_info "Testing flagged keywords (score accumulation)..."
test_request "Single flagged keyword" "200" "POST" "/submit" \
    -d "name=User" -d message='This offer is free'

test_request "Multiple flagged keywords (high score)" "403" "POST" "/submit" \
    -d "name=User" -d message='FREE winner! Click here now! Limited time exclusive offer! Act now! Urgent! Risk free guarantee!'

echo ""

# Test 4: Pattern detection
log_info "Testing pattern detection..."
test_request "Multiple URLs (should flag)" "200" "POST" "/submit" \
    -d "message=Check out http://example.com and http://test.com"

test_request "Excessive URLs (should block)" "403" "POST" "/submit" \
    -d "message=Visit http://a.com http://b.com http://c.com http://d.com http://e.com for more"

test_request "XSS attempt (should block)" "403" "POST" "/submit" \
    -d "message=<script>alert('xss')</script>"

echo ""

# Test 5: Content hashing (duplicate detection)
log_info "Testing duplicate detection..."
UNIQUE_MSG="Test message $(date +%s)"
test_request "First submission of unique content" "200" "POST" "/submit" \
    -d "name=User" -d "message='$UNIQUE_MSG'"

# Same content should still work (under rate limit)
test_request "Second submission of same content" "200" "POST" "/submit" \
    -d "name=User" -d "message='$UNIQUE_MSG'"

echo ""

# Test 6: Health and metrics endpoints
log_info "Testing health and metrics endpoints..."
test_request "Health endpoint" "200" "GET" "/health"

echo ""

# Test 7: Admin API (if accessible)
log_info "Testing Admin API..."
test_request "Admin status endpoint" "200" "GET" "/waf-admin/status"
test_request "List blocked keywords" "200" "GET" "/waf-admin/keywords/blocked"
test_request "List flagged keywords" "200" "GET" "/waf-admin/keywords/flagged"

echo ""

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Failed: ${RED}$FAIL${NC}"
echo ""

if [ $FAIL -gt 0 ]; then
    exit 1
fi
