# Forms WAF User Guide

This comprehensive guide covers practical usage, attack mitigation strategies, and configuration best practices for the Forms WAF system.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Understanding WAF Modes](#understanding-waf-modes)
3. [The Spam Score System](#the-spam-score-system)
4. [Defense Layers](#defense-layers)
5. [Attack Mitigation Strategies](#attack-mitigation-strategies)
6. [Configuration Recipes](#configuration-recipes)
7. [Tuning and Optimization](#tuning-and-optimization)
8. [Feature Deep Dives](#feature-deep-dives)
9. [Operational Guidance](#operational-guidance)
10. [Testing with Demo Forms](#testing-with-demo-forms)
11. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Quick Start Checklist

1. **Deploy the WAF stack** (OpenResty + HAProxy + Redis)
2. **Configure your first vhost** with monitoring mode enabled
3. **Set up timing tokens** for form pages
4. **Add honeypot fields** to your forms
5. **Monitor metrics** for false positives
6. **Tune thresholds** based on traffic patterns
7. **Enable blocking mode** when confident

### Minimal Configuration

```yaml
# Example vhost configuration (via Helm or Redis)
vhosts:
  - id: "my-site"
    hostnames:
      - "example.com"
      - "www.example.com"
    config:
      name: "My Website"
      enabled: true
      waf:
        enabled: true
        mode: "monitoring"  # Start with monitoring!
      thresholds:
        spam_score_block: 80
        spam_score_flag: 50
      security:
        honeypot_fields:
          - "website"  # Hidden field to catch bots
          - "phone_ext"
        check_disposable_email: true
```

### First-Time Deployment Tips

- **Always start in monitoring mode** - This logs would-be blocks without affecting users
- **Run for at least 1-2 weeks** - Gather baseline data before enabling blocking
- **Watch the metrics endpoint** - Monitor `/metrics` for spam scores and detection patterns
- **Check audit logs** - Review `AUDIT:` log entries for detailed blocking decisions

---

## Understanding WAF Modes

The WAF supports four operational modes that control how detected threats are handled:

| Mode | Behavior | Use Case |
|------|----------|----------|
| **monitoring** | Log detections, allow all traffic | Initial deployment, tuning |
| **blocking** | Block requests exceeding thresholds | Production protection |
| **passthrough** | Disable all checks, pass through | Maintenance, debugging |
| **strict** | Block on any detection (lower thresholds) | High-security environments |

### Mode Selection by Environment

```
Development:    passthrough or monitoring
Staging:        monitoring (mirror production rules)
Production:     blocking (after tuning period)
High-Security:  strict (e.g., payment forms)
```

### Transitioning Between Modes

1. Start with `monitoring` mode
2. Analyze logs for false positives/negatives
3. Adjust thresholds and exclusions
4. Test in `strict` mode briefly to find edge cases
5. Deploy `blocking` mode with confidence

---

## The Spam Score System

Forms WAF uses a cumulative scoring system where multiple detection signals add points. When the total score exceeds configured thresholds, action is taken.

### Score Thresholds

| Threshold | Default | Purpose |
|-----------|---------|---------|
| `spam_score_flag` | 50 | Add to HAProxy tracking tables |
| `spam_score_block` | 80 | Block the request |

### Complete Scoring Reference

#### Instant Blocks (No Score - Immediate Action)

| Detection | Trigger | Action |
|-----------|---------|--------|
| Blocked keyword | Any match in form content | Block request |
| Blocked hash | Form content hash in blocklist | Block request |
| Blocked country | IP from blocked country list | Block request |
| Blocked ASN | IP from blocked ASN | Block request |
| IP reputation blocked | Score >= 80 in reputation check | Block request |

#### Timing Token Scores

| Detection | Score | Condition |
|-----------|-------|-----------|
| No timing cookie | +30 | Direct POST without loading form page |
| Too fast submission | +40 | Form submitted in < 2 seconds |
| Suspicious fast | +20 | Form submitted in 2-5 seconds |

#### Content Pattern Scores

| Detection | Score | Notes |
|-----------|-------|-------|
| URL detected | +10 per URL | Capped at 5 matches |
| BBCode URL `[url]` | +20 per match | Forum spam indicator |
| HTML link `<a href` | +20 per match | HTML injection attempt |
| URL shortener | +15 per shortener | bit.ly, tinyurl, etc. |
| Suspicious TLD | +10 per URL | .xyz, .top, .loan, etc. |
| Email in content | +5 per email | Often spam indicator |
| Excessive caps | +5 per match | SHOUTING TEXT |
| Phone number | +3 per match | Often spam |
| Crypto wallet address | +15 per match | ETH/BTC addresses |
| Repetitive chars | +5 per match | "aaaaaaa" patterns |
| XSS attempt | +30 | `<script>`, `javascript:`, events |
| IP-based URL | +20 | `http://192.168.1.1/...` |
| Many URLs (>3) | +10 per extra URL | Excessive link spam |
| Long content (>5000 chars) | +10 | Unusually long submission |
| Short content with URL | +15 | Likely spam link drop |

#### Keyword Scores

| Detection | Score | Notes |
|-----------|-------|-------|
| Flagged keyword | +10 (configurable) | Per-keyword score customizable |
| Additional flagged | +10 (default) | Vhost-specific keywords |

#### Field Anomaly Scores

| Detection | Score | Trigger |
|-----------|-------|---------|
| All fields same length | +15 | Bot-generated fixed-length data |
| Sequential patterns | +5 per field | "aaa", "123", repeated chars |
| All caps fields | +5 per field | Multiple fields in ALL CAPS |
| Test data patterns | +8 per field | "test", "asdf", "lorem", etc. |
| No spaces in long field | +10 | >200 chars without spaces |
| Unexpected field | +5 per field | Field not in expected list |

#### Honeypot Scores

| Detection | Score | Notes |
|-----------|-------|-------|
| Honeypot field filled | +50 or Block | Configurable action |

#### GeoIP Scores

| Detection | Score | Notes |
|-----------|-------|-------|
| Flagged country | +15 | Countries in flagged list |
| Flagged ASN | +20 | ASNs in flagged list |
| Datacenter IP | +25 | Known hosting/cloud ASN |

#### IP Reputation Scores

| Detection | Score | Notes |
|-----------|-------|-------|
| Flagged reputation | +30 | AbuseIPDB score 50-80 |

#### Behavioral Tracking Scores

| Detection | Score | Notes |
|-----------|-------|-------|
| Anomaly detected | +15 | Z-score > threshold (default 2.0) |

### Score Calculation Example

```
Submission Analysis:
- No timing cookie:           +30
- Submission from datacenter: +25
- Contains 2 URLs:            +20 (10 × 2)
- One URL shortener:          +15
- Flagged keyword "winner":   +15
- Same field lengths:         +15
                             ─────
Total:                        120 → BLOCKED (exceeds 80)
```

---

## Defense Layers

Forms WAF uses a multi-layer defense approach. Understanding these layers helps you configure comprehensive protection.

```
┌──────────────────────────────────────────────────────────┐
│                    LAYER 1: Early Block                   │
│          (Before form parsing - lowest latency)           │
│                                                          │
│  ✓ IP Whitelist      → Allow immediately                │
│  ✗ IP Blocklist      → Block immediately                │
│  ✗ GeoIP Block       → Block by country/ASN             │
│  ✗ IP Reputation     → Block bad actors                 │
└──────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────┐
│                  LAYER 2: Content Analysis                │
│               (After form parsing - scoring)              │
│                                                          │
│  ✗ Blocked Keywords  → Instant block                    │
│  ✗ Blocked Hash      → Known spam content               │
│  ± Timing Token      → Add score for suspicious timing  │
│  ± Honeypot          → Score or block if filled         │
│  ± Pattern Matching  → Score for spam patterns          │
│  ± Field Anomalies   → Score for bot-like behavior      │
│  ± Disposable Email  → Score or block temporary emails  │
└──────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────┐
│                  LAYER 3: Score Evaluation                │
│                                                          │
│  spam_score >= 80    → Block request                    │
│  spam_score >= 50    → Flag for HAProxy tracking        │
│  spam_score < 50     → Allow through                    │
└──────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────┐
│               LAYER 4: HAProxy Rate Limiting              │
│            (Stick-table based enforcement)                │
│                                                          │
│  Form hash rate exceeded    → Block duplicate content   │
│  IP rate limit exceeded     → Block abusive IPs         │
│  Fingerprint rate exceeded  → Block coordinated bots    │
└──────────────────────────────────────────────────────────┘
                          ↓
┌──────────────────────────────────────────────────────────┐
│              LAYER 5: CAPTCHA Challenge (Optional)        │
│                                                          │
│  Challenge required  → Show CAPTCHA                     │
│  CAPTCHA passed      → Issue trust token, allow         │
│  CAPTCHA failed      → Block request                    │
└──────────────────────────────────────────────────────────┘
```

---

## Attack Mitigation Strategies

### Spam Bots

**Characteristics:**
- Instant form submissions (< 2 seconds)
- Fill hidden honeypot fields
- Missing or invalid timing tokens
- Predictable patterns (same field lengths)

**Mitigation Strategy:**

1. **Enable timing tokens** - Bots typically submit instantly
   ```yaml
   timing:
     enabled: true
     min_time_block: 2      # Block < 2 seconds
     min_time_flag: 5       # Flag < 5 seconds
     score_no_cookie: 30
     score_too_fast: 40
   ```

2. **Add honeypot fields** - Hidden fields that humans won't fill
   ```yaml
   security:
     honeypot_fields:
       - "website"
       - "fax_number"
       - "company_ext"
     honeypot_action: "block"  # or "flag"
   ```

3. **Enable field anomaly detection** - Catch bot patterns
   ```yaml
   security:
     check_field_anomalies: true
   ```

### Content Spam

**Characteristics:**
- Keyword stuffing (viagra, casino, crypto)
- Multiple URLs in content
- URL shorteners to hide destinations
- Repetitive submissions (same hash)

**Mitigation Strategy:**

1. **Configure blocked keywords** - Instant block
   ```bash
   # Add via API
   curl -X POST http://admin:8082/api/keywords/blocked \
     -H "Authorization: Bearer $TOKEN" \
     -d '{"keywords": ["viagra", "cialis", "casino", "poker"]}'
   ```

2. **Configure flagged keywords** - Score addition
   ```bash
   curl -X POST http://admin:8082/api/keywords/flagged \
     -d '{"keywords": [{"keyword": "free", "score": 10}, {"keyword": "winner", "score": 15}]}'
   ```

3. **Enable content hashing** - Block repeated spam
   ```yaml
   fields:
     hash:
       enabled: true
       fields:
         - "name"
         - "email"
         - "message"
   ```

4. **Configure HAProxy hash rate limiting**
   ```
   stick-table type string len 64 size 100k expire 1h store http_req_rate(10s)
   # Block if same content hash submitted > 10 times in 10 seconds
   ```

### Phishing and Scam Attempts

**Characteristics:**
- URLs to phishing sites
- URL shorteners to mask destinations
- Suspicious TLDs (.xyz, .top, .loan)
- Crypto wallet addresses for fraud

**Mitigation Strategy:**

1. **URL shorteners are auto-detected** - Adds 15 points per shortener
   - bit.ly, tinyurl.com, goo.gl, t.co, etc.

2. **Suspicious TLDs are flagged** - Adds 10 points per URL
   - .xyz, .top, .loan, .click, .link, etc.

3. **Lower thresholds for sensitive forms**
   ```yaml
   thresholds:
     spam_score_block: 60   # More aggressive
     spam_score_flag: 30
   ```

4. **Block crypto wallet addresses**
   ```yaml
   keywords:
     additional_blocked:
       - "0x[a-fA-F0-9]{40}"   # ETH addresses
   ```

### Brute Force Attacks

**Characteristics:**
- High request rate from single IP
- Same form hash repeated rapidly
- Credential stuffing patterns

**Mitigation Strategy:**

1. **HAProxy IP rate limiting**
   ```yaml
   thresholds:
     ip_rate_limit: 30   # Requests per minute per IP
   ```

2. **Enable per-fingerprint tracking**
   ```
   # HAProxy tracks submission fingerprints
   X-Submission-Fingerprint header for coordinated detection
   ```

3. **Enable CAPTCHA on repeated failures**
   ```yaml
   captcha:
     enabled: true
     provider: "turnstile"
     trigger_score: 60   # Show CAPTCHA above this score
   ```

### Distributed Attacks

**Characteristics:**
- Traffic from many IPs (botnet)
- Same patterns across IPs
- Datacenter/VPN origins
- Unusual geographic distribution

**Mitigation Strategy:**

1. **Enable behavioral tracking**
   ```yaml
   behavioral:
     enabled: true
     flows:
       - name: "contact-form"
         start_paths: ["/contact"]
         end_paths: ["/contact/submit"]
     anomaly_detection:
       enabled: true
       std_dev_threshold: 2.0
       action: "score"
       score_addition: 15
   ```

2. **Flag datacenter IPs**
   ```yaml
   geoip:
     enabled: true
     flag_datacenters: true
     datacenter_score: 25
   ```

3. **Enable fingerprint correlation**
   - Same browser fingerprint across multiple IPs = suspicious
   - Tracked via X-Submission-Fingerprint header

### Bot Farms

**Characteristics:**
- Traffic from hosting providers
- Known datacenter ASNs
- VPN/proxy exit nodes
- Unusual User-Agent patterns

**Mitigation Strategy:**

1. **Block or flag datacenter ASNs**
   ```yaml
   geoip:
     enabled: true
     block_datacenters: false   # Or true for strict
     flag_datacenters: true
     datacenter_score: 25
     # Pre-loaded with: AWS, GCP, Azure, DigitalOcean, etc.
   ```

2. **Enable IP reputation checking**
   ```yaml
   ip_reputation:
     enabled: true
     abuseipdb:
       enabled: true
       api_key: "your-api-key"
       min_confidence: 25
     block_score: 80
     flag_score: 50
   ```

3. **Block specific ASNs**
   ```yaml
   geoip:
     blocked_asns:
       - 9009    # M247 (VPN infrastructure)
       - 212238  # Datacamp Limited
   ```

### Account Fraud

**Characteristics:**
- Disposable/temporary email addresses
- Multiple accounts from same IP
- Known fraud patterns

**Mitigation Strategy:**

1. **Enable disposable email detection**
   ```yaml
   security:
     check_disposable_email: true
     disposable_email_action: "block"  # or "flag"
     disposable_email_score: 10
   ```

2. **Use content hashing to detect duplicates**
   ```yaml
   fields:
     hash:
       enabled: true
       fields: ["email", "name"]
   ```

3. **Enable CAPTCHA for suspicious signups**
   ```yaml
   captcha:
     enabled: true
     trigger_on_flagged: true
   ```

---

## Configuration Recipes

### Recipe 1: Public Contact Form

High-protection configuration for a public-facing contact form.

```yaml
id: "contact-form"
name: "Public Contact Form"
waf:
  enabled: true
  mode: "blocking"

thresholds:
  spam_score_block: 70
  spam_score_flag: 40

security:
  honeypot_fields:
    - "website"      # Hidden field labeled "Website"
    - "phone_ext"    # Hidden field labeled "Extension"
  honeypot_action: "block"
  check_disposable_email: true
  disposable_email_action: "flag"
  check_field_anomalies: true

timing:
  enabled: true
  start_paths: ["/contact"]
  end_paths: ["/contact", "/contact/submit"]
  min_time_block: 2
  min_time_flag: 5

keywords:
  inherit_global: true
  additional_flagged:
    - "free consultation:10"
    - "best prices:10"

captcha:
  enabled: true
  provider: "turnstile"
  fallback_to_challenge: true

fields:
  required:
    - name: "email"
      type: "email"
    - name: "message"
      min_length: 10
```

### Recipe 2: Newsletter Signup

Protect against fake signups while maintaining low friction.

```yaml
id: "newsletter"
name: "Newsletter Signup"
waf:
  enabled: true
  mode: "blocking"

thresholds:
  spam_score_block: 60
  spam_score_flag: 30

security:
  check_disposable_email: true
  disposable_email_action: "block"  # Strict for newsletters
  honeypot_fields:
    - "company"
  honeypot_action: "block"

timing:
  enabled: true
  start_paths: ["/", "/blog/*", "/newsletter"]
  end_paths: ["/newsletter/subscribe"]
  min_time_flag: 3  # Quick forms need shorter time

fields:
  hash:
    enabled: true
    fields: ["email"]  # Detect duplicate signups

rate_limiting:
  enabled: true
  requests_per_minute: 5  # Low rate for signups
```

### Recipe 3: E-commerce Checkout

Balanced protection without breaking multi-step checkout flows.

```yaml
id: "checkout"
name: "E-commerce Checkout"
waf:
  enabled: true
  mode: "blocking"

thresholds:
  spam_score_block: 90  # Higher threshold - false positives costly
  spam_score_flag: 60

security:
  # Skip timing for multi-step forms
  timing_token_enabled: false
  check_field_anomalies: true
  check_disposable_email: false  # May have legitimate temp emails

fields:
  ignore:
    - "csrf_token"
    - "cart_id"
    - "payment_nonce"
  required:
    - name: "email"
      type: "email"
    - name: "shipping_address"
    - name: "billing_address"

ip_reputation:
  # More lenient - customers may use VPNs
  flag_score: 70

captcha:
  enabled: true
  provider: "recaptcha_v3"
  min_score: 0.5
```

### Recipe 4: API Endpoints

Relaxed configuration for legitimate API traffic.

```yaml
id: "api-endpoints"
name: "API Endpoints"
waf:
  enabled: true
  mode: "monitoring"  # APIs need careful tuning

thresholds:
  spam_score_block: 100  # Very high - API has own validation
  spam_score_flag: 80

security:
  timing_token_enabled: false  # APIs don't load form pages
  check_field_anomalies: false
  check_disposable_email: false
  honeypot_fields: []  # Not applicable

keywords:
  inherit_global: false  # API may have legitimate keywords

ip_reputation:
  enabled: true
  # Block only confirmed bad actors
  block_score: 90

patterns:
  inherit_global: false
  disabled: ["url", "email", "phone"]  # APIs often contain these
```

### Recipe 5: Partner Portal

Whitelisted IPs with monitoring for visibility.

```yaml
id: "partner-portal"
name: "Partner Portal"
waf:
  enabled: true
  mode: "monitoring"  # Monitor only

whitelist:
  ips:
    - "10.0.0.0/8"        # Internal networks
    - "203.0.113.50"      # Partner office
    - "198.51.100.0/24"   # Partner datacenter

thresholds:
  spam_score_block: 100  # Never block
  spam_score_flag: 50

keywords:
  inherit_global: true
  excluded_blocked:
    - "crypto"  # Partners discuss cryptocurrency
  excluded_flagged:
    - "investment"
```

### Recipe 6: Staging Environment

Full passthrough for testing with optional monitoring.

```yaml
id: "staging"
name: "Staging Environment"
waf:
  enabled: true
  mode: "passthrough"  # Let everything through
  debug_headers: true  # Expose X-WAF-* headers for debugging

# Even in passthrough, timing cookies are set
# This allows testing the timing system
timing:
  enabled: true

# Log everything for debugging
security:
  log_all_requests: true
```

---

## Tuning and Optimization

### The Tuning Workflow

```
 Week 1-2: MONITORING MODE
 ┌─────────────────────────────────────────────────────────┐
 │ 1. Deploy with mode: "monitoring"                       │
 │ 2. All traffic flows through, detections logged only    │
 │ 3. Collect baseline metrics and analyze patterns        │
 │ 4. Review audit logs for false positive patterns        │
 └─────────────────────────────────────────────────────────┘
                          ↓
 Week 3: STRICT MODE TESTING
 ┌─────────────────────────────────────────────────────────┐
 │ 1. Switch to mode: "strict" temporarily                 │
 │ 2. Lower thresholds to catch edge cases                 │
 │ 3. Identify all potential false positives               │
 │ 4. Add exclusions for legitimate patterns               │
 └─────────────────────────────────────────────────────────┘
                          ↓
 Week 4+: BLOCKING MODE
 ┌─────────────────────────────────────────────────────────┐
 │ 1. Switch to mode: "blocking"                           │
 │ 2. Use tuned thresholds from monitoring data            │
 │ 3. Continue monitoring metrics                          │
 │ 4. Adjust as needed based on traffic changes            │
 └─────────────────────────────────────────────────────────┘
```

### Analyzing False Positives

**Signs of false positives:**
- Legitimate users reporting blocked submissions
- High `monitored_requests` count in metrics
- Complaints about CAPTCHA challenges

**Common causes and fixes:**

| Cause | Fix |
|-------|-----|
| CSRF tokens scanned | Add to `fields.ignore` |
| Legitimate URLs blocked | Adjust `spam_score_block` threshold |
| Fast typists flagged | Increase `min_time_flag` |
| Partner IPs flagged | Add to IP whitelist |
| Business keywords blocked | Add to `excluded_blocked` |

### Understanding Threshold Types

The WAF uses two different blocking approaches:

**Request Count Limits (Rate Limiting):**
Limit the NUMBER of requests, regardless of content:
- `ip_rate_limit`: Max requests per IP per minute (default: 30)
- `ip_daily_limit`: Max requests per IP per day (default: 500)
- `fingerprint_rate_limit`: Max requests per fingerprint per minute (default: 20)

**Score-Based Limits:**
Work with SPAM SCORES assigned to suspicious content:
- `spam_score_block`: Block if single request score >= threshold (default: 80)
- `spam_score_flag`: Flag for tracking if score >= threshold (default: 50)
- `ip_spam_score_threshold`: Block IP when CUMULATIVE score over 24h exceeds threshold (default: 500)

**Why both?** Consider an attacker sending many requests with score 60 each:
- Each request passes `spam_score_block=80` (under threshold)
- But after 9 requests, cumulative score = 540 points
- `ip_spam_score_threshold=500` blocks the IP

This catches "low and slow" attacks where individual requests look legitimate.

### Adjusting Thresholds

**Conservative (fewer false positives, more spam):**
```yaml
thresholds:
  spam_score_block: 100
  spam_score_flag: 70
  ip_spam_score_threshold: 750
  ip_rate_limit: 50
  fingerprint_rate_limit: 30
```

**Balanced (default):**
```yaml
thresholds:
  spam_score_block: 80
  spam_score_flag: 50
  ip_spam_score_threshold: 500
  ip_rate_limit: 30
  fingerprint_rate_limit: 20
```

**Aggressive (more blocks, risk of false positives):**
```yaml
thresholds:
  spam_score_block: 60
  spam_score_flag: 30
  ip_spam_score_threshold: 375
  ip_rate_limit: 20
  fingerprint_rate_limit: 15
```

### Per-Vhost Overrides

Different sites may need different thresholds:

```yaml
# High-traffic marketing site - more lenient
vhosts:
  - id: "marketing"
    config:
      thresholds:
        spam_score_block: 90

# Financial services - more strict
  - id: "finance"
    config:
      thresholds:
        spam_score_block: 60
```

### Keyword Exclusion Strategies

**Exclude from blocked list:**
```yaml
keywords:
  inherit_global: true
  excluded_blocked:
    - "casino"  # Site is about gaming industry
```

**Exclude from flagged list:**
```yaml
keywords:
  excluded_flagged:
    - "free"    # Legitimate promotions
    - "winner"  # Contest site
```

### Field Ignore Best Practices

Always ignore security-sensitive fields:
```yaml
fields:
  ignore:
    - "csrf_token"
    - "_token"
    - "captcha"
    - "captcha_response"
    - "password"
    - "password_confirm"
    - "credit_card"
    - "cc_number"
```

---

## Feature Deep Dives

### Timing Tokens

Timing tokens detect bot submissions by measuring how long a user takes to fill out a form.

**How it works:**
1. User loads form page (GET request)
2. Server sets encrypted cookie with timestamp
3. User submits form (POST request)
4. Server calculates time delta
5. Score adjusted based on timing

**Configuration options:**

```yaml
timing:
  enabled: true
  cookie_name: "_waf_timing"
  cookie_ttl: 3600           # Max validity (1 hour)
  min_time_block: 2          # Block under 2 seconds
  min_time_flag: 5           # Flag under 5 seconds
  score_no_cookie: 30        # No timing cookie
  score_too_fast: 40         # Under min_time_block
  score_suspicious: 20       # Under min_time_flag

  # Path matching
  start_paths: ["/contact", "/signup"]
  end_paths: ["/contact/submit", "/signup"]
  path_match_mode: "prefix"  # exact, prefix, or regex
```

**Troubleshooting:**

| Problem | Solution |
|---------|----------|
| Legitimate users blocked | Increase `min_time_block` |
| No cookie errors | Check cookie domain settings |
| AJAX forms fail | Ensure GET loads the page first |
| Multi-step forms | Set `timing_token_enabled: false` on endpoint |

### Behavioral Tracking

ML-based anomaly detection that learns normal traffic patterns.

**How it works:**
1. Define flows (start path → end path)
2. System records submission patterns per hour
3. After learning period, baselines are calculated
4. Anomalies flagged when z-score exceeds threshold

**Configuration:**

```yaml
behavioral:
  enabled: true

  flows:
    - name: "contact-flow"
      start_paths: ["/contact"]
      start_methods: ["GET"]
      end_paths: ["/contact/submit"]
      end_methods: ["POST"]
      path_match_mode: "prefix"

  tracking:
    submission_counts: true
    fill_duration: true
    unique_ips: true
    avg_spam_score: true

  baselines:
    learning_period_days: 14
    min_samples: 100
    recalculate_interval: 3600

  anomaly_detection:
    enabled: true
    std_dev_threshold: 2.0    # Z-score threshold
    action: "score"           # score, log, or block
    score_addition: 15
```

**Baseline metrics calculated:**
- Hourly average submissions
- Standard deviation
- P50, P90, P99 percentiles

### Defense Profiles

Defense profiles provide a DAG-based (Directed Acyclic Graph) system for orchestrating multiple defense mechanisms with flexible execution flows.

**How it works:**
1. Request enters the defense profile executor
2. Graph nodes execute in order (defense checks, operators, actions)
3. Defense nodes return scores, blocked/allowed decisions
4. Operators aggregate results (sum, max, threshold branch)
5. Action nodes determine final response (allow, block, captcha, tarpit)

**Key concepts:**

| Concept | Description |
|---------|-------------|
| **Defense Profile** | A graph defining execution order of defense mechanisms |
| **Defense Node** | Executes a single defense (e.g., honeypot, keyword_filter) |
| **Operator Node** | Aggregates scores (sum, max, threshold_branch) |
| **Action Node** | Terminal action (allow, block, captcha, tarpit) |
| **Multi-Profile Execution** | Run multiple profiles in parallel with aggregation |
| **Defense Lines** | Combine a profile with attack signatures |

**Built-in profiles:**
- `legacy` - Backward compatible with original WAF execution (priority 1000)
- `balanced-web` - Balanced protection for web forms with CAPTCHA (priority 100)
- `strict-api` - High-security for API endpoints with tarpit (priority 50)
- `permissive` - Minimal protection for high-traffic pages (priority 200)
- `high-value` - Maximum protection for payment/signup forms (priority 25)
- `monitor-only` - Runs all checks but never blocks (priority 900)

**Attaching profiles to endpoints:**

```yaml
endpoints:
  - id: contact-form
    defense_profiles:
      enabled: true
      profiles:
        - id: balanced-web
          priority: 100
          weight: 1.0
      aggregation: "OR"        # Block if ANY profile blocks
      score_aggregation: "SUM" # Add scores from all profiles
      short_circuit: true      # Stop after first block
```

**Defense Lines (profiles + signatures):**

```yaml
endpoints:
  - id: wp-login
    defense_lines:
      - enabled: true
        profile_id: strict-api
        signature_ids:
          - builtin_wordpress_login
          - builtin_credential_stuffing
```

> **Note:** For complete documentation including node types, custom profile creation, and API reference, see [Defense Profiles](../DEFENSE_PROFILES.md) and [Attack Signatures](../ATTACK_SIGNATURES.md).

### Fingerprint Profiles

Client fingerprinting for advanced bot detection and rate limiting.

**How it works:**
1. Request headers are analyzed against profile conditions
2. First matching profile (by priority) determines action
3. Fingerprint hash generated from configured headers
4. Per-fingerprint rate limiting applied if enabled

**Built-in profiles:**
- `known-bot` - Search engine crawlers (ignored, priority 50)
- `modern-browser` - Standard browsers with full headers (allow, priority 100)
- `headless-browser` - Automation tools like Puppeteer (flagged +25, priority 120)
- `suspicious-bot` - curl/wget/scripts (flagged +30, priority 150)
- `legacy-browser` - Older browsers with minimal headers (allow +5, priority 200)
- `no-user-agent` - Missing User-Agent header (flagged +40, priority 300)

**Configuration:**

```yaml
fingerprint_profiles:
  enabled: true
  profiles:
    - "modern-browser"
    - "legacy-browser"
  no_match_action: "flag"    # use_default, allow, block, flag
  no_match_score: 15
```

**Custom profile example:**

```yaml
# Create via Admin UI or API
{
  "id": "my-mobile-app",
  "name": "Mobile App",
  "priority": 50,
  "action": "allow",
  "matching": {
    "match_mode": "all",
    "conditions": [
      {"header": "X-App-Token", "condition": "present"},
      {"header": "User-Agent", "condition": "matches", "pattern": "MyApp/"}
    ]
  },
  "rate_limiting": {
    "enabled": true,
    "fingerprint_rate_limit": 60
  }
}
```

**Fingerprint rate limiting benefits:**
- Tracks users across IP changes (mobile networks)
- Limits shared IP impact (NAT/proxy users)
- Detects rotating IP bots by consistent fingerprint

See [Fingerprint Profiles Documentation](../FINGERPRINT_PROFILES.md) for complete reference.

### GeoIP and IP Reputation

Geographic and reputation-based filtering.

**GeoIP Configuration:**

```yaml
geoip:
  enabled: true

  # Block specific countries
  blocked_countries: ["RU", "CN", "KP"]

  # Or whitelist mode (only allow these)
  allowed_countries: ["US", "CA", "GB", "DE"]

  # Flag countries (add score, don't block)
  flagged_countries: ["UA", "RO", "BG"]
  flagged_country_score: 15

  # ASN controls
  blocked_asns: [9009, 212238]
  flagged_asns: [62904]
  flagged_asn_score: 20

  # Datacenter detection
  block_datacenters: false
  flag_datacenters: true
  datacenter_score: 25
```

**IP Reputation Configuration:**

```yaml
ip_reputation:
  enabled: true
  cache_ttl: 86400           # Cache results 24 hours

  # AbuseIPDB integration
  abuseipdb:
    enabled: true
    api_key: "your-api-key"
    min_confidence: 25       # Minimum score to flag
    max_age_days: 90

  # Local blocklist
  local_blocklist:
    enabled: true

  # Custom webhook
  webhook:
    enabled: false
    url: "https://your-service/check-ip"
    timeout: 2000

  # Thresholds
  block_score: 80
  flag_score: 50
  flag_score_addition: 30
```

### CAPTCHA Integration

Challenge suspected bots with CAPTCHA verification.

**Supported providers:**
- reCAPTCHA v2 (checkbox)
- reCAPTCHA v3 (invisible)
- hCaptcha
- Cloudflare Turnstile

**Configuration:**

```yaml
captcha:
  enabled: true
  provider: "turnstile"       # or recaptcha_v2, recaptcha_v3, hcaptcha

  site_key: "your-site-key"
  secret_key: "your-secret-key"

  # When to show CAPTCHA
  trigger_on_block: true      # Show instead of blocking
  trigger_score: 60           # Show when score >= this

  # Trust tokens
  trust_token_enabled: true
  trust_token_ttl: 3600       # Valid for 1 hour after solving

  # Provider-specific
  recaptcha_v3:
    min_score: 0.5            # 0.0 = bot, 1.0 = human
```

### Content Hashing

Detect and block duplicate content submissions.

**Configuration:**

```yaml
fields:
  hash:
    enabled: true

    # Hash specific fields (recommended)
    fields:
      - "name"
      - "email"
      - "message"

    # Or hash all fields except ignored ones
    # fields: []  (empty = hash all)
```

**HAProxy integration:**
- Hashes tracked in stick-tables
- Rate limiting per hash
- Prevents repetitive spam attacks

---

## Operational Guidance

### Monitoring with Prometheus

**Available metrics endpoint:** `GET /metrics`

```
# Key metrics to watch
waf_requests_total{vhost="...",outcome="blocked"}
waf_requests_total{vhost="...",outcome="allowed"}
waf_spam_score_histogram{vhost="..."}
waf_timing_token_results{result="too_fast"}
```

**Grafana dashboard queries:**

```promql
# Block rate by vhost
sum(rate(waf_requests_total{outcome="blocked"}[5m])) by (vhost)

# Average spam score
histogram_quantile(0.95, rate(waf_spam_score_histogram[5m]))

# CAPTCHA challenge rate
rate(waf_captcha_challenges_total[5m])
```

### Webhook Notifications

Configure webhooks for real-time alerting:

```yaml
webhooks:
  enabled: true
  url: "https://your-webhook.example.com/waf"

  # Events to notify
  notify_on:
    - blocked
    - honeypot_triggered
    - captcha_challenge
    - disposable_email

  # Include details
  include_form_data: false     # Privacy consideration
  include_headers: true
  include_geo_info: true

  # Rate limiting
  max_per_minute: 100
```

### Bulk Import/Export

Manage keywords and configurations at scale:

```bash
# Export all keywords
curl http://admin:8082/api/bulk/export/keywords > keywords.json

# Import keywords
curl -X POST http://admin:8082/api/bulk/import/keywords \
  -H "Content-Type: application/json" \
  -d @keywords.json

# Export hashes
curl http://admin:8082/api/bulk/export/hashes > hashes.json

# Export whitelist
curl http://admin:8082/api/bulk/export/whitelist > whitelist.json
```

### Multi-Instance Cluster

For high-availability deployments:

1. **Use StatefulSet** for stable instance IDs
2. **Enable HAProxy peer sync** for stick-table replication
3. **Global metrics** are aggregated by cluster leader
4. **Redis** is the single source of truth for configuration

```yaml
# Kubernetes example
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: forms-waf-openresty
spec:
  replicas: 3
  serviceName: forms-waf-openresty-headless
```

---

## Testing with Demo Forms

The mock backend includes built-in HTML forms for testing WAF functionality.

### Available Test Forms

| URL | Form Type | Fields |
|-----|-----------|--------|
| `/contact` | Contact Form | name, email, phone, subject, message |
| `/apply` | Job Application | name, email, phone, resume, cover_letter |

### Accessing Test Forms

```bash
# In development (via HAProxy)
http://localhost:8490/contact
http://localhost:8490/apply

# Direct backend access (bypasses WAF)
http://localhost:8080/contact
http://localhost:8080/apply
```

### Testing WAF Features

**Test honeypot detection:**
Both forms include hidden honeypot fields (`website` for contact, `company` for apply). Fill these fields to trigger honeypot detection:

```bash
curl -X POST http://localhost:8490/contact \
  -d "name=Test&email=test@example.com&subject=Test&message=Hello&website=spam.com"
# Should be blocked or flagged (honeypot filled)
```

**Test timing detection:**
```bash
# Fast submission (no timing cookie) - should be flagged
curl -X POST http://localhost:8490/contact \
  -d "name=Test&email=test@example.com&subject=Test&message=Hello"

# Proper submission (load page first, wait, then submit)
curl -c cookies.txt http://localhost:8490/contact
sleep 3
curl -b cookies.txt -X POST http://localhost:8490/contact \
  -d "name=Test&email=test@example.com&subject=Test&message=Hello"
```

**Test fingerprint profiles:**
```bash
# Suspicious bot (curl User-Agent) - should be flagged
curl -X POST http://localhost:8490/contact \
  -d "name=Test&email=test@example.com&subject=Test&message=Hello"

# Simulate browser
curl -X POST http://localhost:8490/contact \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -d "name=Test&email=test@example.com&subject=Test&message=Hello"
```

**Test spam keywords:**
```bash
# Content with spam keywords
curl -X POST http://localhost:8490/contact \
  -d "name=Test&email=test@example.com&subject=Amazing offer&message=Buy viagra now! Visit http://bit.ly/spam"
# Should be blocked or flagged
```

### Form POST Responses

Successful submissions return JSON:
```json
{
  "status": "success",
  "message": "Contact form received"
}
```

Blocked requests return 403 with block reason in headers:
- `X-WAF-Block-Reason`: Why the request was blocked
- `X-WAF-Spam-Score`: Calculated spam score

---

## Troubleshooting

### Common Issues

#### "Legitimate users getting blocked"

1. Check audit logs for the block reason
2. Review the spam score breakdown
3. Add exclusions for false positive patterns
4. Consider raising `spam_score_block` threshold
5. Add trusted IPs to whitelist

#### "Timing token errors"

1. Ensure GET request loads before POST
2. Check cookie domain matches
3. Verify `start_paths` includes form pages
4. Increase `cookie_ttl` for long forms

#### "GeoIP not working"

1. Check MaxMind database is mounted
2. Verify database path in config
3. Confirm `mmdb` library is available
4. Check `/api/geoip/status` endpoint

#### "High memory usage"

1. Review shared dictionary sizes in nginx.conf
2. Check Redis memory usage
3. Reduce keyword/hash cache TTL
4. Consider sharding by vhost

#### "CAPTCHA not showing"

1. Verify provider credentials
2. Check `trigger_score` threshold
3. Ensure CAPTCHA JS is loading
4. Review browser console for errors

### Debug Headers

Enable debug headers to troubleshoot requests:

```yaml
waf:
  debug_headers: true  # Per-vhost
```

Or globally:
```
EXPOSE_WAF_HEADERS=true
```

Headers exposed:
- `X-WAF-Vhost`: Matched virtual host
- `X-WAF-Endpoint`: Matched endpoint
- `X-WAF-Mode`: Current mode
- `X-WAF-Spam-Score`: Total score
- `X-WAF-Spam-Flags`: Detection flags
- `X-WAF-Form-Hash`: Content hash
- `X-WAF-Would-Block`: Monitoring mode indicator

### Useful API Endpoints

```bash
# System status
curl http://admin:8082/api/status

# Cluster health
curl http://admin:8082/api/cluster/status

# GeoIP status
curl http://admin:8082/api/geoip/status

# Metrics summary
curl http://admin:8082/api/metrics

# Learning statistics
curl http://admin:8082/api/learning/stats

# Behavioral summary
curl http://admin:8082/api/behavioral/summary
```

---

## Best Practices Summary

1. **Always start in monitoring mode** - Never deploy blocking without data
2. **Use timing tokens** - Most effective against simple bots
3. **Configure honeypots** - Zero false positives when done correctly
4. **Layer your defenses** - No single feature is foolproof
5. **Review metrics regularly** - Traffic patterns change
6. **Keep keywords updated** - Spam evolves constantly
7. **Test before blocking** - Use strict mode to find edge cases
8. **Document exclusions** - Know why each exclusion exists
9. **Monitor globally** - Cluster-wide visibility is crucial
10. **Plan for incidents** - Have runbooks for attack scenarios

---

## See Also

- [Attack Playbook](ATTACK_PLAYBOOK.md) - Quick incident response guide
- [Configuration Reference](CONFIGURATION_REFERENCE.md) - Complete config options
- [API Handlers](../API_HANDLERS.md) - Admin API documentation
- [Architecture](../ARCHITECTURE.md) - System design details
- [Cluster Coordination](../CLUSTER_COORDINATION.md) - Multi-instance setup
- [Behavioral Tracking](../BEHAVIORAL_TRACKING.md) - ML-based detection details
