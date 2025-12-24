# Attack Playbook

Quick reference guide for identifying and responding to common attack patterns against form endpoints.

---

## Quick Reference Table

| Attack Type | Key Indicators | Immediate Action | Config Change |
|-------------|----------------|------------------|---------------|
| [Spam Flood](#spam-flood) | High rate, repetitive content | Enable hash rate limiting | Lower block threshold |
| [Bot Campaign](#bot-campaign) | Same fingerprint, instant submit | Enable timing tokens | Block datacenter IPs |
| [Phishing Wave](#phishing-wave) | URLs, shorteners, suspicious TLDs | Add flagged patterns | Enable URL detection |
| [Credential Stuffing](#credential-stuffing) | High IP rate, same form structure | IP rate limit, reputation | Enable CAPTCHA |
| [Geographic Attack](#geographic-attack) | Single country source | Block country | Review GeoIP config |
| [Disposable Email Abuse](#disposable-email-abuse) | Temp email domains | Block disposable emails | Enable email check |
| [Honeypot Bypasses](#honeypot-bypasses) | Empty honeypots, filled forms | Add more honeypots | Randomize field names |
| [Timing Evasion](#timing-evasion) | Wait then submit, rotate sessions | Increase thresholds | Enable behavioral |

---

## Attack Scenarios

### Spam Flood

> **Related Signature:** [`builtin_contact_form_spam`](../ATTACK_SIGNATURES.md) - Pre-configured patterns for contact form spam

**Description:** High volume of spam submissions with repetitive content, typically promoting products, services, or malicious links.

#### Detection Signs

```
Metrics:
- waf_requests_total{outcome="blocked"} spiking
- High spam_score averages (60-80+)
- Repeated form hashes in logs

Logs:
BLOCKED: ... reason=spam_score_exceeded score=85 hash=a1b2c3...
BLOCKED: ... flags=kw:viagra,pattern:url:3,timing:no_cookie
```

#### Immediate Response

1. **Check current block rate:**
   ```bash
   curl http://admin:8082/api/metrics | jq '.blocked_requests'
   ```

2. **Identify common keywords in spam:**
   ```bash
   grep "BLOCKED:" /var/log/nginx/error.log | \
     grep -oP 'flags=[^,]+' | sort | uniq -c | sort -rn | head -20
   ```

3. **Add identified keywords to blocklist:**
   ```bash
   curl -X POST http://admin:8082/api/keywords/blocked \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"keywords": ["identified", "spam", "keywords"]}'
   ```

4. **Block repeat offenders by hash:**
   ```bash
   # Find most common hashes
   grep "BLOCKED:" /var/log/nginx/error.log | \
     grep -oP 'hash=[a-f0-9]+' | sort | uniq -c | sort -rn | head -10

   # Block the hash
   curl -X POST http://admin:8082/api/hashes/blocked \
     -d '{"hashes": ["a1b2c3d4..."]}'
   ```

#### Long-term Mitigation

```yaml
# Lower thresholds during attack
thresholds:
  spam_score_block: 60   # From default 80
  spam_score_flag: 30    # From default 50

# Enable hash rate limiting
fields:
  hash:
    enabled: true
    fields: ["name", "email", "message"]

# HAProxy config - limit to 5 submissions per hash per 10 minutes
stick-table type string len 64 size 100k expire 10m store http_req_rate(600s)
```

#### Verification

```bash
# Check block rate is increasing
watch -n 5 'curl -s http://admin:8082/api/metrics | jq ".blocked_requests"'

# Verify spam is being caught
tail -f /var/log/nginx/error.log | grep "BLOCKED:"
```

---

### Bot Campaign

> **Related Signature:** [`builtin_api_abuse`](../ATTACK_SIGNATURES.md) - Blocks automated tools and scripting libraries

**Description:** Coordinated bot attack with same browser fingerprint across multiple IPs, often submitting forms instantly.

#### Detection Signs

```
Metrics:
- Same X-Submission-Fingerprint across many IPs
- timing:no_cookie or timing:too_fast flags prevalent
- Submissions in < 2 seconds

Logs:
BLOCKED: ip=1.2.3.4 ... flags=timing:too_fast
BLOCKED: ip=5.6.7.8 ... flags=timing:no_cookie
# Same fingerprint appearing from different IPs
```

#### Immediate Response

1. **Check fingerprint distribution:**
   ```bash
   grep "X-Submission-Fingerprint" /var/log/nginx/access.log | \
     awk '{print $NF}' | sort | uniq -c | sort -rn | head -10
   ```

2. **Enable timing tokens if not already:**
   ```bash
   curl -X PUT http://admin:8082/api/timing/config \
     -H "Content-Type: application/json" \
     -d '{
       "enabled": true,
       "min_time_block": 2,
       "min_time_flag": 5,
       "score_no_cookie": 40,
       "score_too_fast": 50
     }'
   ```

3. **Block datacenter IPs:**
   ```bash
   curl -X PUT http://admin:8082/api/geoip/config \
     -d '{"block_datacenters": true}'
   ```

#### Long-term Mitigation

```yaml
# Aggressive timing configuration
timing:
  enabled: true
  min_time_block: 3     # Increase from 2
  min_time_flag: 8      # Increase from 5
  score_no_cookie: 40   # Increase from 30
  score_too_fast: 50    # Increase from 40

# Block datacenter traffic
geoip:
  enabled: true
  block_datacenters: true
  # Or flag only:
  # flag_datacenters: true
  # datacenter_score: 40

# Add honeypots
security:
  honeypot_fields:
    - "website"
    - "fax"
    - "middle_name"
  honeypot_action: "block"
```

#### Verification

```bash
# Check timing token effectiveness
grep "timing:" /var/log/nginx/error.log | \
  grep -oP 'timing:[a-z_]+' | sort | uniq -c

# Verify bot IPs are being blocked
curl http://admin:8082/api/geoip/lookup?ip=1.2.3.4
```

---

### Phishing Wave

**Description:** Submissions containing phishing URLs, often using URL shorteners and suspicious TLDs to evade detection.

#### Detection Signs

```
Metrics:
- High pattern:url counts
- pattern:url_shortener flags
- pattern:suspicious_tld flags

Logs:
BLOCKED: ... flags=pattern:url:5,pattern:url_shortener:bit.ly,pattern:suspicious_tld:xyz
```

#### Immediate Response

1. **Identify URL patterns:**
   ```bash
   grep "url" /var/log/nginx/error.log | \
     grep -oP 'https?://[^\s,]+' | \
     sed 's|/.*||' | sort | uniq -c | sort -rn | head -20
   ```

2. **Lower block threshold temporarily:**
   ```bash
   curl -X PUT http://admin:8082/api/config/thresholds \
     -d '{"spam_score_block": 50}'
   ```

3. **Add specific domain patterns to blocklist:**
   ```bash
   curl -X POST http://admin:8082/api/keywords/blocked \
     -d '{"keywords": ["malicious-domain.xyz", "phishing-site.top"]}'
   ```

#### Long-term Mitigation

```yaml
# Lower thresholds for URL-heavy submissions
thresholds:
  spam_score_block: 60

# The following patterns are already built-in but verify they're active:
# - URL shorteners: +15 each (bit.ly, tinyurl, etc.)
# - Suspicious TLDs: +10 each (.xyz, .top, .loan, etc.)
# - Multiple URLs: +10 per URL beyond 3

# Add custom flagged patterns for specific threats
keywords:
  additional_flagged:
    - "verify-your-account:30"
    - "confirm-identity:25"
    - "suspended-account:25"

# Enable behavioral to catch pattern changes
behavioral:
  enabled: true
  anomaly_detection:
    enabled: true
```

#### Verification

```bash
# Monitor URL-related blocks
tail -f /var/log/nginx/error.log | grep -E "url|shortener|tld"

# Check pattern detection
curl http://admin:8082/api/status | jq '.pattern_stats'
```

---

### Credential Stuffing

> **Related Signatures:** [`builtin_wordpress_login`](../ATTACK_SIGNATURES.md), [`builtin_credential_stuffing`](../ATTACK_SIGNATURES.md) - Brute force and credential stuffing protection

**Description:** Automated login attempts using leaked credential lists, often from multiple IPs with same form structure.

#### Detection Signs

```
Metrics:
- High request rate to login endpoints
- Same form hash repeated rapidly
- Multiple IPs, same submission pattern

Logs:
BLOCKED: path=/login ... flags=hash:rate_exceeded
IP rate exceeded: 1.2.3.4 (45/min, limit 30)
```

#### Immediate Response

1. **Lower IP rate limit:**
   ```bash
   curl -X PUT http://admin:8082/api/config/thresholds \
     -d '{"ip_rate_limit": 10}'
   ```

2. **Enable IP reputation checking:**
   ```bash
   curl -X PUT http://admin:8082/api/reputation/config \
     -d '{
       "enabled": true,
       "block_score": 60,
       "flag_score": 30
     }'
   ```

3. **Enable CAPTCHA on login:**
   ```bash
   curl -X PUT http://admin:8082/api/captcha/config \
     -d '{
       "enabled": true,
       "trigger_on_block": true,
       "trigger_score": 40
     }'
   ```

#### Long-term Mitigation

```yaml
# Endpoint-specific configuration for login
endpoints:
  - id: "login"
    matching:
      paths: ["/login", "/auth/login"]
      methods: ["POST"]

    thresholds:
      spam_score_block: 50

    rate_limiting:
      enabled: true
      requests_per_minute: 5   # Very low for login

    captcha:
      enabled: true
      trigger_on_block: true

# IP reputation
ip_reputation:
  enabled: true
  abuseipdb:
    enabled: true
    api_key: "your-key"
    min_confidence: 20
  block_score: 60
  flag_score: 30
```

#### Verification

```bash
# Check rate limiting effectiveness
grep "rate" /var/log/haproxy.log | tail -20

# Monitor CAPTCHA challenges
curl http://admin:8082/api/metrics | jq '.captcha_challenges'
```

---

### Geographic Attack

**Description:** Attack traffic originating from a single country or region, often exploiting regional infrastructure.

#### Detection Signs

```
Metrics:
- Single country in geo:* flags
- Spike in requests from unusual region
- GeoIP lookup showing concentrated source

Logs:
BLOCKED: ... flags=geo:flagged_country:RU
PROCESSED: ip=x.x.x.x geo=CN asn=12345
```

#### Immediate Response

1. **Identify attack source:**
   ```bash
   grep "geo=" /var/log/nginx/error.log | \
     grep -oP 'geo=[A-Z]+' | sort | uniq -c | sort -rn
   ```

2. **Block the country:**
   ```bash
   curl -X PUT http://admin:8082/api/geoip/config \
     -d '{"blocked_countries": ["XX"]}'  # Replace XX with country code
   ```

3. **Or flag for additional scoring:**
   ```bash
   curl -X PUT http://admin:8082/api/geoip/config \
     -d '{
       "flagged_countries": ["XX"],
       "flagged_country_score": 30
     }'
   ```

#### Long-term Mitigation

```yaml
geoip:
  enabled: true

  # Block countries if legitimate traffic is zero
  blocked_countries: ["KP", "IR"]

  # Flag countries with some legitimate traffic
  flagged_countries: ["RU", "CN", "UA"]
  flagged_country_score: 20

  # Block specific ASNs known for abuse
  blocked_asns: [9009, 212238]

  # Or flag datacenter ASNs
  flag_datacenters: true
  datacenter_score: 25
```

#### Verification

```bash
# Check GeoIP blocks
grep "geo:blocked" /var/log/nginx/error.log | wc -l

# Verify country blocking
curl "http://admin:8082/api/geoip/lookup?ip=1.2.3.4"
```

---

### Disposable Email Abuse

**Description:** Account creation or form submission using temporary/disposable email addresses to avoid tracking.

#### Detection Signs

```
Metrics:
- High disposable:* flag counts
- Common temp email domains in submissions

Logs:
BLOCKED: ... flags=disposable:user@tempmail.com
AUDIT: disposable_email_blocked domains=["tempmail.com", "guerrillamail.com"]
```

#### Immediate Response

1. **Check disposable email domains:**
   ```bash
   grep "disposable:" /var/log/nginx/error.log | \
     grep -oP '@[a-z0-9.-]+' | sort | uniq -c | sort -rn
   ```

2. **Enable blocking (if currently flagging):**
   ```bash
   curl -X PUT http://admin:8082/api/config/security \
     -d '{
       "check_disposable_email": true,
       "disposable_email_action": "block"
     }'
   ```

#### Long-term Mitigation

```yaml
security:
  check_disposable_email: true
  disposable_email_action: "block"  # or "flag"
  disposable_email_score: 20        # if flagging

# The system includes 1000+ known disposable domains
# New domains can be added to the blocklist
```

#### Verification

```bash
# Test detection
curl -X POST http://your-site.com/signup \
  -d "email=test@tempmail.com&name=Test"
# Should be blocked

# Check disposable domain list
curl http://admin:8082/api/status | jq '.disposable_domains_count'
```

---

### Honeypot Bypasses

**Description:** Sophisticated bots that detect and avoid honeypot fields while still submitting spam.

#### Detection Signs

```
Metrics:
- Low honeypot trigger rate
- High spam score without honeypot flags
- Bot-like patterns without honeypot fills

Logs:
BLOCKED: ... flags=timing:too_fast,anomaly:same_length
# Note: no honeypot flags despite bot behavior
```

#### Immediate Response

1. **Add more honeypot fields:**
   ```bash
   curl -X PUT http://admin:8082/api/vhosts/your-vhost \
     -d '{
       "security": {
         "honeypot_fields": [
           "website",
           "url",
           "fax",
           "phone_ext",
           "company_website",
           "homepage"
         ]
       }
     }'
   ```

2. **Verify honeypots are hidden in HTML:**
   ```html
   <!-- Good: CSS hidden -->
   <div style="position: absolute; left: -9999px;">
     <input name="website" tabindex="-1" autocomplete="off">
   </div>

   <!-- Better: Randomized field name -->
   <input name="field_a7x9q" style="display: none;">
   ```

#### Long-term Mitigation

```yaml
security:
  honeypot_fields:
    - "website"
    - "homepage"
    - "company_url"
    - "fax_number"
    - "extension"
  honeypot_action: "block"
  honeypot_score: 100   # If using flag action

# Randomize honeypot field names periodically
# Use JavaScript to dynamically name honeypot fields
# Position honeypots between real fields in DOM
```

#### Best Practices for Honeypots

1. **Use realistic field names** - "website", "phone_ext", not "hp_trap"
2. **Position with CSS, not `type="hidden"`** - Bots ignore hidden inputs
3. **Add tabindex="-1"** - Prevents accidental human interaction
4. **Disable autocomplete** - Prevents browser auto-fill
5. **Rotate field names** - Change names monthly

---

### Timing Evasion

**Description:** Bots that wait before submitting to evade timing detection, or rotate sessions to appear fresh.

#### Detection Signs

```
Metrics:
- Submissions at exactly threshold time (e.g., 5.1 seconds)
- Normal timing but bot-like content
- Session rotation patterns

Logs:
PROCESSED: ... elapsed=5.05s flags=anomaly:same_length,pattern:url:3
# Just above min_time_flag, but clearly bot content
```

#### Immediate Response

1. **Increase timing thresholds:**
   ```bash
   curl -X PUT http://admin:8082/api/timing/config \
     -d '{
       "min_time_block": 5,
       "min_time_flag": 10
     }'
   ```

2. **Enable behavioral tracking:**
   ```bash
   curl -X PUT http://admin:8082/api/vhosts/your-vhost \
     -d '{
       "behavioral": {
         "enabled": true,
         "anomaly_detection": {
           "enabled": true,
           "std_dev_threshold": 1.5,
           "score_addition": 20
         }
       }
     }'
   ```

#### Long-term Mitigation

```yaml
# Increase timing thresholds
timing:
  min_time_block: 5
  min_time_flag: 12
  score_too_fast: 50
  score_suspicious: 30

# Enable behavioral tracking
behavioral:
  enabled: true
  flows:
    - name: "main-form"
      start_paths: ["/form"]
      end_paths: ["/form/submit"]
  anomaly_detection:
    enabled: true
    std_dev_threshold: 1.5  # More sensitive
    score_addition: 20

# Lower overall threshold
thresholds:
  spam_score_block: 70

# Multiple detection layers catch evasion
security:
  check_field_anomalies: true
  honeypot_fields: ["website", "fax"]
```

---

## Incident Response Checklist

### During Active Attack

- [ ] **Identify attack type** from logs and metrics
- [ ] **Apply immediate mitigation** from playbook above
- [ ] **Monitor block rate** to verify mitigation
- [ ] **Check for legitimate user impact** (false positives)
- [ ] **Document attack patterns** for future reference

### Post-Attack

- [ ] **Review logs** for attack timeline
- [ ] **Analyze blocked requests** for patterns
- [ ] **Update blocklists** with new keywords/hashes
- [ ] **Adjust thresholds** if needed
- [ ] **Update honeypots** if bypassed
- [ ] **Document incident** and response

### Preventive Measures

- [ ] **Regular threshold review** monthly
- [ ] **Keyword list updates** weekly
- [ ] **Behavioral baseline checks** after traffic changes
- [ ] **GeoIP block review** quarterly
- [ ] **Honeypot rotation** monthly

---

## Quick Commands Reference

```bash
# Get current metrics
curl http://admin:8082/api/metrics

# View recent blocks
tail -100 /var/log/nginx/error.log | grep "BLOCKED:"

# Check cluster status
curl http://admin:8082/api/cluster/status

# Force sync from Redis
curl -X POST http://admin:8082/api/sync

# Export current config
curl http://admin:8082/api/bulk/export/keywords > keywords-backup.json

# Quick threshold change
curl -X PUT http://admin:8082/api/config/thresholds \
  -d '{"spam_score_block": 60}'

# Add IPs to blocklist
curl -X POST http://admin:8082/api/reputation/blocklist \
  -d '{"ips": ["1.2.3.4", "5.6.7.0/24"]}'

# Check IP reputation
curl "http://admin:8082/api/reputation/check?ip=1.2.3.4"

# GeoIP lookup
curl "http://admin:8082/api/geoip/lookup?ip=1.2.3.4"
```

---

## See Also

- [User Guide](USER_GUIDE.md) - Comprehensive configuration guide
- [Configuration Reference](CONFIGURATION_REFERENCE.md) - All configuration options
- [API Handlers](../API_HANDLERS.md) - Admin API documentation
- [Attack Signatures](../ATTACK_SIGNATURES.md) - Built-in signatures for common attack vectors
- [Defense Profiles](../DEFENSE_PROFILES.md) - DAG-based defense execution
