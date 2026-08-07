#!/bin/bash
# Test script for Forms WAF
# Usage: ./test-waf.sh [base_url] [admin_url]

set -e
#set -x

BASE_URL="${1:-http://localhost:8080}"
ADMIN_URL="${2:-http://localhost:8082}"
PASS=0
FAIL=0

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# A real Chrome request is more than a User-Agent string. The WAF's
# fake-modern-browser check flags a request that claims to be Chrome 120 while
# omitting the client hints and Sec-Fetch headers Chrome always sends -- which is
# correct bot detection, and exactly what a -A flag alone looks like. Tests that
# describe themselves as "legitimate browser" must therefore send a browser's
# headers, or they assert the opposite of what they claim.
BROWSER_UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
BROWSER_HEADERS=(
    -H "Accept-Language: en-GB,en;q=0.9"
    -H "Accept-Encoding: gzip, deflate, br"
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
    -H 'sec-ch-ua: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"'
    -H 'sec-ch-ua-mobile: ?0'
    -H 'sec-ch-ua-platform: "Windows"'
    -H 'Sec-Fetch-Site: same-origin'
    -H 'Sec-Fetch-Mode: navigate'
    -H 'Sec-Fetch-User: ?1'
    -H 'Sec-Fetch-Dest: document'
    -H 'Upgrade-Insecure-Requests: 1'
)

# Create temp cookie jars for timing cookies and admin session
COOKIE_JAR=$(mktemp)
ADMIN_COOKIE_JAR=$(mktemp)
SETUP_COOKIE_JAR=$(mktemp)
ORIGINAL_IP_RATE_LIMIT=""
ORIGINAL_FP_RATE_LIMIT=""
ORIGINAL_WP_RPM=""

cleanup() {
    # Restore anything the harness changed before removing the jars.
    if [ -n "$ORIGINAL_IP_RATE_LIMIT" ]; then
        curl -s -b "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/config/thresholds" \
            -H 'Content-Type: application/json' \
            -d "{\"name\":\"ip_rate_limit\",\"value\":$ORIGINAL_IP_RATE_LIMIT}" >/dev/null 2>&1 || true
        curl -s -b "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/sync" >/dev/null 2>&1 || true
    fi
    if [ -n "$ORIGINAL_FP_RATE_LIMIT" ]; then
        curl -s -b "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/config/thresholds" \
            -H 'Content-Type: application/json' \
            -d "{\"name\":\"fingerprint_rate_limit\",\"value\":$ORIGINAL_FP_RATE_LIMIT}" >/dev/null 2>&1 || true
        curl -s -b "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/sync" >/dev/null 2>&1 || true
    fi
    if [ -n "$ORIGINAL_WP_RPM" ] && command -v python3 >/dev/null 2>&1; then
        WP_CFG=$(curl -s -b "$SETUP_COOKIE_JAR" "$ADMIN_URL/api/endpoints/wp-login" 2>/dev/null)
        WP_TMP=$(mktemp)
        printf '%s' "$WP_CFG" | ORIGINAL_WP_RPM="$ORIGINAL_WP_RPM" python3 -c "
import sys, os, json
cfg = json.load(sys.stdin)['endpoint']
rl = cfg.setdefault('rate_limiting', {})
rl['enabled'] = True
rl['requests_per_minute'] = int(os.environ['ORIGINAL_WP_RPM'])
rl['requests_per_day'] = 100
sys.stdout.write(json.dumps(cfg))
" > "$WP_TMP" 2>/dev/null
        curl -s -b "$SETUP_COOKIE_JAR" -X PUT "$ADMIN_URL/api/endpoints/wp-login" \
            -H 'Content-Type: application/json' --data-binary @"$WP_TMP" >/dev/null 2>&1 || true
        curl -s -b "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/sync" >/dev/null 2>&1 || true
        rm -f "$WP_TMP"
    fi
    rm -f "$COOKIE_JAR" "$ADMIN_COOKIE_JAR" "$SETUP_COOKIE_JAR"
}
trap cleanup EXIT

# This suite issues far more requests per minute from one address than the default
# ip_rate_limit (30) permits, so later tests would return 429 and be reported as
# detection failures. When admin credentials are available, raise the limit for the
# duration of the run and restore it on exit.
if [ -n "$WAF_ADMIN_USER" ] && [ -n "$WAF_ADMIN_PASS" ]; then
    login_code=$(curl -s -c "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/auth/login" \
        -H 'Content-Type: application/json' \
        -d "{\"username\":\"$WAF_ADMIN_USER\",\"password\":\"$WAF_ADMIN_PASS\"}" \
        -o /dev/null -w '%{http_code}' 2>/dev/null || echo "000")
    if [ "$login_code" = "200" ]; then
        ORIGINAL_IP_RATE_LIMIT=$(curl -s -b "$SETUP_COOKIE_JAR" "$ADMIN_URL/api/config/thresholds" 2>/dev/null \
            | sed -n 's/.*"ip_rate_limit"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
        curl -s -b "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/config/thresholds" \
            -H 'Content-Type: application/json' \
            -d '{"name":"ip_rate_limit","value":100000}' >/dev/null 2>&1
        # The suite also presents a single client fingerprint for its whole run,
        # and fingerprint_rate_limit (default 20) is enforced independently of the
        # IP limit. Leaving it in place made results alternate between clean and
        # several spurious failures depending on run timing.
        ORIGINAL_FP_RATE_LIMIT=$(curl -s -b "$SETUP_COOKIE_JAR" "$ADMIN_URL/api/config/thresholds" 2>/dev/null \
            | sed -n 's/.*"fingerprint_rate_limit"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
        curl -s -b "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/config/thresholds" \
            -H 'Content-Type: application/json' \
            -d '{"name":"fingerprint_rate_limit","value":100000}' >/dev/null 2>&1
        # The wp-login endpoint has its own rate_limiting.requests_per_minute of
        # 10 -- a deliberate brute-force control -- and its defense-line section
        # issues more requests than that in a minute. PUT validates the whole
        # object, so the config must be round-tripped: GET returns both the raw
        # stored config under "endpoint" and the merged view under "resolved";
        # only "endpoint" is safe to send back.
        if command -v python3 >/dev/null 2>&1; then
            WP_CFG=$(curl -s -b "$SETUP_COOKIE_JAR" "$ADMIN_URL/api/endpoints/wp-login" 2>/dev/null)
            if printf '%s' "$WP_CFG" | grep -q '"endpoint"'; then
                ORIGINAL_WP_RPM=$(printf '%s' "$WP_CFG" | python3 -c "
import sys, json
cfg = json.load(sys.stdin).get('endpoint', {})
print(cfg.get('rate_limiting', {}).get('requests_per_minute', ''))
" 2>/dev/null)
                WP_TMP=$(mktemp)
                printf '%s' "$WP_CFG" | python3 -c "
import sys, json
cfg = json.load(sys.stdin)['endpoint']
rl = cfg.setdefault('rate_limiting', {})
rl['enabled'] = True
rl['requests_per_minute'] = 100000
rl['requests_per_day'] = 1000000
sys.stdout.write(json.dumps(cfg))
" > "$WP_TMP" 2>/dev/null
                curl -s -b "$SETUP_COOKIE_JAR" -X PUT "$ADMIN_URL/api/endpoints/wp-login" \
                    -H 'Content-Type: application/json' --data-binary @"$WP_TMP" >/dev/null 2>&1
                rm -f "$WP_TMP"
            fi
        fi
        curl -s -b "$SETUP_COOKIE_JAR" -X POST "$ADMIN_URL/api/sync" >/dev/null 2>&1
        sleep 2
    fi
fi

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

# A gap we have deliberately chosen not to assert on yet. Counted separately so it
# is visible in the summary without turning the suite red or hiding regressions.
KNOWN_GAPS=0
log_known_gap() {
    echo -e "${YELLOW}[KNOWN GAP]${NC} $1"
    KNOWN_GAPS=$((KNOWN_GAPS+1))
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

    local response
    local status

    if [ "$method" = "GET" ]; then
        response=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -w "\n%{http_code}" "$BASE_URL$endpoint")
    else
        # Pass remaining arguments properly to curl, use cookie jar for timing cookies
        response=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -w "\n%{http_code}" -X "$method" "$BASE_URL$endpoint" "$@")
    fi

    status=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$status" = "$expected_status" ]; then
        log_pass "$name (status: $status)"
    elif [ "$status" = "429" ]; then
        # The suite fires many requests from a single source address. If the WAF's
        # own IP rate limit trips, the result says nothing about detection quality,
        # so report it distinctly rather than as a detection failure.
        log_fail "$name (RATE-LIMITED: got 429, expected $expected_status)"
        echo "  Exceeded ip_rate_limit. Export WAF_ADMIN_USER/WAF_ADMIN_PASS so the"
        echo "  harness can raise it for the run, or raise it manually."
    else
        log_fail "$name (expected: $expected_status, got: $status)"
        echo "  Response: $body"
    fi
}

# Test a form submission with proper timing flow (GET to set cookie, then POST)
test_form_request() {
    local name="$1"
    local expected_status="$2"
    local endpoint="$3"
    shift 3

    # First, do a GET request to set the timing cookie
    curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" "$BASE_URL$endpoint" > /dev/null 2>&1

    # Brief pause to avoid timing:too_fast (human would take at least a few seconds)
    sleep 0.5

    # Now do the POST with timing cookie
    local response
    response=$(curl -s -c "$COOKIE_JAR" -b "$COOKIE_JAR" -w "\n%{http_code}" -X POST "$BASE_URL$endpoint" "$@")

    local status
    status=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$status" = "$expected_status" ]; then
        log_pass "$name (status: $status)"
    elif [ "$status" = "429" ]; then
        # The suite fires many requests from a single source address. If the WAF's
        # own IP rate limit trips, the result says nothing about detection quality,
        # so report it distinctly rather than as a detection failure.
        log_fail "$name (RATE-LIMITED: got 429, expected $expected_status)"
        echo "  Exceeded ip_rate_limit. Export WAF_ADMIN_USER/WAF_ADMIN_PASS so the"
        echo "  harness can raise it for the run, or raise it manually."
    else
        log_fail "$name (expected: $expected_status, got: $status)"
        echo "  Response: $body"
    fi
}

echo "========================================"
echo "Forms WAF Test Suite"
echo "Base URL: $BASE_URL"
echo "Admin URL: $ADMIN_URL"
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
# These two assert "flagged but NOT blocked", which only holds for a client that
# is not already carrying the +30 bot-fingerprint penalty. Bare curl claims to be
# nothing in particular and is scored accordingly, so without browser headers the
# assertion tests the fingerprint check rather than the pattern scoring it names.
test_request "Multiple URLs (should flag)" "200" "POST" "/submit" \
    -A "$BROWSER_UA" "${BROWSER_HEADERS[@]}" \
    -d "message=Check out http://example.com and http://test.com"

test_request "Excessive URLs (should block)" "403" "POST" "/submit" \
    -d "message=Visit http://a.com http://b.com http://c.com http://d.com http://e.com for more"

# Single XSS pattern scores 30, below block threshold of 80 - should flag but allow
test_request "XSS attempt (flagged, not blocked)" "200" "POST" "/submit" \
    -A "$BROWSER_UA" "${BROWSER_HEADERS[@]}" \
    -d "message=<script>alert('xss')</script>"

# Multiple XSS patterns should accumulate score and block
test_request "Multiple XSS attempts (should block)" "403" "POST" "/submit" \
    -d "message=<script>alert(1)</script><script>alert(2)</script><script>alert(3)</script><iframe src=evil></iframe>"

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

# Test 7: Admin API (on dedicated port 8082)
log_info "Testing Admin API on dedicated port ($ADMIN_URL)..."

# Helper function for admin requests
test_admin_request() {
    local name="$1"
    local expected_status="$2"
    local method="$3"
    local endpoint="$4"
    shift 4

    local response
    local status

    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "$ADMIN_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "$ADMIN_URL$endpoint" "$@")
    fi

    status=$(echo "$response" | tail -1)
    body=$(echo "$response" | sed '$d')

    if [ "$status" = "$expected_status" ]; then
        log_pass "$name (status: $status)"
    elif [ "$status" = "429" ]; then
        # The suite fires many requests from a single source address. If the WAF's
        # own IP rate limit trips, the result says nothing about detection quality,
        # so report it distinctly rather than as a detection failure.
        log_fail "$name (RATE-LIMITED: got 429, expected $expected_status)"
        echo "  Exceeded ip_rate_limit. Export WAF_ADMIN_USER/WAF_ADMIN_PASS so the"
        echo "  harness can raise it for the run, or raise it manually."
    else
        log_fail "$name (expected: $expected_status, got: $status)"
        echo "  Response: $body"
    fi
}

# Check admin port is accessible
test_admin_request "Admin health endpoint" "200" "GET" "/health"

# Admin API requires authentication - these should return 401 without auth
test_admin_request "Admin status (no auth)" "401" "GET" "/api/status"
test_admin_request "List blocked keywords (no auth)" "401" "GET" "/api/keywords/blocked"

# Authenticated admin API tests (if credentials provided via WAF_ADMIN_USER and WAF_ADMIN_PASS)
if [ -n "$WAF_ADMIN_USER" ] && [ -n "$WAF_ADMIN_PASS" ]; then
    log_info "Testing authenticated Admin API..."

    # Login and get session cookie
    LOGIN_RESPONSE=$(curl -s -c "$ADMIN_COOKIE_JAR" -w "\n%{http_code}" \
        -X POST "$ADMIN_URL/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$WAF_ADMIN_USER\",\"password\":\"$WAF_ADMIN_PASS\"}")

    LOGIN_STATUS=$(echo "$LOGIN_RESPONSE" | tail -1)
    LOGIN_BODY=$(echo "$LOGIN_RESPONSE" | sed '$d')

    if [ "$LOGIN_STATUS" = "200" ]; then
        log_pass "Admin login successful"

        # Helper for authenticated requests
        test_auth_admin() {
            local name="$1"
            local expected_status="$2"
            local method="$3"
            local endpoint="$4"
            shift 4

            local response
            local status

            if [ "$method" = "GET" ]; then
                response=$(curl -s -b "$ADMIN_COOKIE_JAR" -w "\n%{http_code}" "$ADMIN_URL$endpoint")
            else
                response=$(curl -s -b "$ADMIN_COOKIE_JAR" -w "\n%{http_code}" -X "$method" "$ADMIN_URL$endpoint" "$@")
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

        # Test authenticated endpoints
        test_auth_admin "Admin status (auth)" "200" "GET" "/api/status"
        test_auth_admin "List blocked keywords (auth)" "200" "GET" "/api/keywords/blocked"
        test_auth_admin "List flagged keywords (auth)" "200" "GET" "/api/keywords/flagged"
        test_auth_admin "Get thresholds (auth)" "200" "GET" "/api/config/thresholds"
        test_auth_admin "List vhosts (auth)" "200" "GET" "/api/vhosts"
        test_auth_admin "List endpoints (auth)" "200" "GET" "/api/endpoints"
        test_auth_admin "Get routing config (auth)" "200" "GET" "/api/config/routing"
        test_auth_admin "Get whitelisted IPs (auth)" "200" "GET" "/api/whitelist/ips"

        # Test logout
        LOGOUT_RESPONSE=$(curl -s -b "$ADMIN_COOKIE_JAR" -c "$ADMIN_COOKIE_JAR" -w "\n%{http_code}" \
            -X POST "$ADMIN_URL/api/auth/logout")
        LOGOUT_STATUS=$(echo "$LOGOUT_RESPONSE" | tail -1)

        if [ "$LOGOUT_STATUS" = "200" ]; then
            log_pass "Admin logout successful"
        else
            log_fail "Admin logout (expected: 200, got: $LOGOUT_STATUS)"
        fi

        # Verify session is invalidated
        test_admin_request "Admin status (after logout)" "401" "GET" "/api/status"
    else
        log_fail "Admin login failed (status: $LOGIN_STATUS)"
        echo "  Response: $LOGIN_BODY"
    fi
else
    log_info "Skipping authenticated admin tests (set WAF_ADMIN_USER and WAF_ADMIN_PASS to enable)"
fi

echo ""

# Test 8: Verify admin is NOT accessible on main port (security check)
# Note: On the main port, /api/ and /waf-admin/ paths go to the backend, not the admin API
# The backend returns its own response, not the WAF admin data
log_info "Verifying admin API is NOT accessible on main port ($BASE_URL)..."
# The main port proxies to backend - we verify no WAF admin response by checking response content
response=$(curl -s "$BASE_URL/api/status")
if echo "$response" | grep -q '"waf_status"' 2>/dev/null; then
    log_fail "Admin API leaked on main port"
    echo "  Response: $response"
else
    log_pass "Admin API not accessible on main port"
fi

# Test 9: WordPress Login Protection with Defense Lines
# Tests defense lines execution with attack signature pattern matching
# The wp-login endpoint uses defense lines with builtin_wordpress_login and builtin_credential_stuffing signatures


log_info "Testing WordPress login endpoint with defense lines..."

# Check if wp-login endpoint exists
# The probe looks for the mock backend echoing the endpoint name. That only
# arrives when the request is proxied through, so once the endpoint's defense
# lines actually enforce, the probe is blocked and the section was skipped --
# the suite could not tell "not configured" from "configured and blocking me".
# A 403 is equally good evidence that the endpoint exists and is enforcing.
WP_RESPONSE=$(curl -s -w '\n%{http_code}' -X POST "$BASE_URL/wp-login.php" \
    -A "$BROWSER_UA" "${BROWSER_HEADERS[@]}" \
    -d "log=testuser&pwd=testpass")
WP_PROBE_STATUS=$(echo "$WP_RESPONSE" | tail -1)

if echo "$WP_RESPONSE" | grep -q '"endpoint":"wp-login"' || [ "$WP_PROBE_STATUS" = "403" ]; then
    log_pass "WP Login endpoint is configured"

    # Wait for rate limit reset
    sleep 3

    # Test 1: Normal request with legitimate browser should pass
    test_form_request "WP Login - Legitimate browser request" "200" "/wp-login.php" \
        -A "$BROWSER_UA" "${BROWSER_HEADERS[@]}" \
        -d "log=legituser" -d "pwd=SecureP@ss123!" -d "wp-submit=Log+In"

    sleep 1

    # Test 2: Honeypot field should trigger block
    test_form_request "WP Login - Honeypot triggered" "403" "/wp-login.php" \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36" \
        -d "log=testuser" -d "pwd=testpass" -d "website=http://spam.com"

    sleep 1

    # Test 3: Python user agent should be blocked (from builtin_wordpress_login signature)
    test_request "WP Login - Blocked UA (python-requests)" "403" "POST" "/wp-login.php" \
        -A "python-requests/2.28.0" \
        -d "log=testuser&pwd=testpass"

    sleep 1

    # Test 4: Curl user agent should be blocked
    test_request "WP Login - Blocked UA (curl)" "403" "POST" "/wp-login.php" \
        -A "curl/7.68.0" \
        -d "log=testuser&pwd=testpass"

    sleep 1

    # Test 5: Wget user agent should be blocked
    test_request "WP Login - Blocked UA (wget)" "403" "POST" "/wp-login.php" \
        -A "Wget/1.21" \
        -d "log=testuser&pwd=testpass"

    sleep 1

    # Test 6: Common username "admin" should be blocked (from builtin_credential_stuffing signature)
    test_request "WP Login - Credential stuffing (admin)" "403" "POST" "/wp-login.php" \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
        -d "log=admin&pwd=somepassword"

    sleep 1

    # Test 7: Common password should be blocked
    test_request "WP Login - Credential stuffing (password123)" "403" "POST" "/wp-login.php" \
        -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
        -d "log=someuser&pwd=password123"

else
    log_info "WP Login endpoint not configured - skipping defense line tests"
    log_info "  To enable: restart Redis to load init-data.sh, or add endpoint via Admin UI"
    log_info "  The wp-login endpoint requires defense_lines with attack signatures"
fi

echo ""

# Test 10: Attack Signatures API (authenticated)
if [ -n "$WAF_ADMIN_USER" ] && [ -n "$WAF_ADMIN_PASS" ]; then
    log_info "Testing Attack Signatures API..."

    # Re-login for this section
    curl -s -c "$ADMIN_COOKIE_JAR" \
        -X POST "$ADMIN_URL/api/auth/login" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$WAF_ADMIN_USER\",\"password\":\"$WAF_ADMIN_PASS\"}" > /dev/null

    test_auth_admin "List attack signatures" "200" "GET" "/api/attack-signatures"
    test_auth_admin "Get signature tags" "200" "GET" "/api/attack-signatures/tags"
    test_auth_admin "List builtin signatures" "200" "GET" "/api/attack-signatures/builtins"
    test_auth_admin "Get WP login signature" "200" "GET" "/api/attack-signatures/builtin_wordpress_login"
    test_auth_admin "Get credential stuffing signature" "200" "GET" "/api/attack-signatures/builtin_credential_stuffing"

    echo ""
fi

# Summary
echo "========================================"
echo "Test Summary"
echo "========================================"
echo -e "Passed: ${GREEN}$PASS${NC}"
echo -e "Known gaps: ${YELLOW}${KNOWN_GAPS}${NC} (see R-27)"
echo -e "Failed: ${RED}$FAIL${NC}"
echo ""

if [ $FAIL -gt 0 ]; then
    exit 1
fi
