-- waf_handler.lua
-- Main WAF processing module that orchestrates form parsing, hashing, and filtering
-- Now with dynamic endpoint configuration and virtual host support

local _M = {}

local form_parser = require "form_parser"
local content_hasher = require "content_hasher"
local keyword_filter = require "keyword_filter"
local waf_config = require "waf_config"
local endpoint_matcher = require "endpoint_matcher"
local config_resolver = require "config_resolver"
local vhost_matcher = require "vhost_matcher"
local vhost_resolver = require "vhost_resolver"
local field_learner = require "field_learner"
local metrics = require "metrics"
local captcha_handler = require "captcha_handler"
local webhooks = require "webhooks"
local timing_token = require "timing_token"
local geoip = require "geoip"
local ip_reputation = require "ip_reputation"
local ip_utils = require "ip_utils"
local behavioral_tracker = require "behavioral_tracker"
local fingerprint_profiles = require "fingerprint_profiles"
local cjson = require "cjson.safe"

-- Structured audit logging for security events
-- Outputs JSON formatted log entries for easy parsing by log aggregation tools
local function audit_log(event_type, event_data)
    local log_entry = {
        ["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        event_type = event_type,
        request_id = ngx.var.request_id or tostring(ngx.now()),
        client_ip = ngx.var.http_x_forwarded_for or ngx.var.remote_addr,
        host = ngx.var.http_host or ngx.var.host,
        path = ngx.var.uri,
        method = ngx.req.get_method(),
        user_agent = ngx.var.http_user_agent,
        referer = ngx.var.http_referer,
    }

    -- Merge event-specific data
    if event_data then
        for k, v in pairs(event_data) do
            log_entry[k] = v
        end
    end

    -- Output as JSON to error log (can be parsed by log shippers)
    ngx.log(ngx.NOTICE, "AUDIT: ", cjson.encode(log_entry))
end

-- Generate submission fingerprint (client identifier)
-- Creates a fingerprint based on browser/client characteristics, NOT content
-- Purpose: Detect bot patterns - same client submitting many different form hashes
-- Components: User-Agent, Accept headers, form field names (structure only)
-- Returns: string fingerprint (hex hash)
local function generate_submission_fingerprint(form_data, ngx_vars)
    local resty_sha256 = require "resty.sha256"
    local resty_string = require "resty.string"

    local sha256 = resty_sha256:new()
    if not sha256 then
        return nil
    end

    -- Collect field names only (sorted for consistency)
    -- Intentionally excludes values and lengths - we're identifying the CLIENT, not content
    local fields = {}
    for field_name, _ in pairs(form_data) do
        if type(field_name) == "string" then
            table.insert(fields, field_name)
        end
    end
    table.sort(fields)

    -- Build fingerprint from client characteristics
    local components = {}

    -- 1. User-Agent (primary bot identifier - normalized)
    local ua = ngx_vars.http_user_agent or ""
    ua = ua:sub(1, 100):lower():gsub("%s+", " ")
    table.insert(components, ua)

    -- 2. Accept-Language (browser locale setting)
    local accept_lang = ngx_vars.http_accept_language or ""
    accept_lang = accept_lang:sub(1, 50):lower()
    table.insert(components, accept_lang)

    -- 3. Accept-Encoding (browser capabilities)
    local accept_enc = ngx_vars.http_accept_encoding or ""
    accept_enc = accept_enc:sub(1, 50):lower()
    table.insert(components, accept_enc)

    -- 4. Form field names (structure only, no values)
    table.insert(components, table.concat(fields, ","))

    -- Generate hash
    sha256:update(table.concat(components, "|"))
    local digest = sha256:final()

    -- Return first 16 characters of hex hash (enough for uniqueness)
    return resty_string.to_hex(digest):sub(1, 16)
end

-- Field anomaly detection
-- Returns: { score = number, flags = {} }
-- @param form_data: table of form field key-value pairs
-- @param security_settings: security configuration
-- @param ignore_fields: optional array of field names to exclude from analysis
local function detect_field_anomalies(form_data, security_settings, ignore_fields)
    local result = {
        score = 0,
        flags = {}
    }

    if not form_data or type(form_data) ~= "table" then
        return result
    end

    -- Build ignore set from configurable ignore_fields
    local ignore_set = {}
    if ignore_fields then
        for _, f in ipairs(ignore_fields) do
            ignore_set[f] = true
            ignore_set[f:lower()] = true  -- Also match lowercase version
        end
    end

    -- Gather field statistics
    local text_fields = {}
    local field_lengths = {}
    local total_caps_fields = 0
    local total_text_fields = 0

    for field_name, value in pairs(form_data) do
        if type(value) == "string" and #value > 0 then
            -- Skip fields in the ignore list (CSRF tokens, captchas, etc.)
            local name_lower = field_name:lower()
            local should_skip = ignore_set[field_name] or ignore_set[name_lower]
            -- Also skip fields matching common security patterns
            if not should_skip then
                should_skip = name_lower:match("csrf") or name_lower:match("token") or
                              name_lower:match("captcha") or name_lower:match("password") or
                              name_lower:match("_id$")
            end
            if not should_skip then

                table.insert(text_fields, { name = field_name, value = value })
                table.insert(field_lengths, #value)
                total_text_fields = total_text_fields + 1

                -- Check if field is all caps (more than 3 chars and all uppercase letters)
                if #value > 3 then
                    local alpha_only = value:gsub("[^%a]", "")
                    if #alpha_only > 3 and alpha_only:upper() == alpha_only and alpha_only:lower() ~= alpha_only then
                        total_caps_fields = total_caps_fields + 1
                    end
                end
            end
        end
    end

    -- Anomaly 1: All fields same length (bots often generate fixed-length data)
    if #field_lengths >= 3 then
        local all_same = true
        local first_len = field_lengths[1]
        for i = 2, #field_lengths do
            if field_lengths[i] ~= first_len then
                all_same = false
                break
            end
        end
        if all_same and first_len > 5 then
            result.score = result.score + 15
            table.insert(result.flags, "same_length:" .. first_len)
        end
    end

    -- Anomaly 2: Check for sequential/incremental patterns
    -- Look for values like "aaa", "bbb", "ccc" or "111", "222", "333"
    local sequential_count = 0
    for _, field in ipairs(text_fields) do
        local val = field.value
        -- Check for repeated characters
        if #val >= 3 then
            local first_char = val:sub(1, 1)
            local all_same_char = true
            for i = 2, #val do
                if val:sub(i, i) ~= first_char then
                    all_same_char = false
                    break
                end
            end
            if all_same_char then
                sequential_count = sequential_count + 1
            end
        end

        -- Check for incrementing numbers (123, 1234, etc.)
        if val:match("^%d+$") and #val >= 3 then
            local is_sequential = true
            for i = 2, #val do
                local prev = tonumber(val:sub(i - 1, i - 1))
                local curr = tonumber(val:sub(i, i))
                if curr ~= (prev + 1) % 10 then
                    is_sequential = false
                    break
                end
            end
            if is_sequential then
                sequential_count = sequential_count + 1
            end
        end
    end

    if sequential_count >= 2 then
        result.score = result.score + (sequential_count * 5)
        table.insert(result.flags, "sequential:" .. sequential_count)
    end

    -- Anomaly 3: Multiple fields all caps (shouting/bot pattern)
    if total_caps_fields >= 2 then
        result.score = result.score + (total_caps_fields * 5)
        table.insert(result.flags, "all_caps:" .. total_caps_fields)
    end

    -- Anomaly 4: Field value looks like test data (common bot patterns)
    local test_pattern_count = 0
    local test_patterns = {
        "^test[%d]*$", "^asdf+$", "^qwer", "^abc+$", "^xyz+$",
        "^foo$", "^bar$", "^baz$", "^lorem", "^ipsum",
        "^sample$", "^example$", "^dummy$"
    }
    for _, field in ipairs(text_fields) do
        local val_lower = field.value:lower()
        for _, pattern in ipairs(test_patterns) do
            if val_lower:match(pattern) then
                test_pattern_count = test_pattern_count + 1
                break
            end
        end
    end

    if test_pattern_count >= 2 then
        result.score = result.score + (test_pattern_count * 8)
        table.insert(result.flags, "test_data:" .. test_pattern_count)
    end

    -- Anomaly 5: Extremely long field values without spaces (likely encoded/binary data)
    for _, field in ipairs(text_fields) do
        if #field.value > 200 then
            local space_count = 0
            for _ in field.value:gmatch("%s") do
                space_count = space_count + 1
            end
            -- Less than 1 space per 50 characters is suspicious for text
            if space_count < (#field.value / 50) then
                result.score = result.score + 10
                table.insert(result.flags, "no_spaces:" .. field.name)
            end
        end
    end

    return result
end

-- Process incoming request
function _M.process_request()
    local method = ngx.req.get_method()
    local path = ngx.var.uri
    local host = ngx.var.http_host or ngx.var.host
    local content_type = ngx.var.content_type or ""

    -- Step 0: Resolve full request context (vhost + endpoint)
    local context = vhost_resolver.resolve_request_context(host, path, method)
    local summary = vhost_resolver.get_context_summary(context)

    -- Check if WAF debug headers should be exposed to clients
    -- Global toggle has precedence: when OFF, no debug anywhere
    -- When global is ON, per-vhost settings can enable/disable for specific vhosts
    local global_expose_headers = waf_config.expose_waf_headers()
    local vhost_debug_override = nil

    -- Check for per-vhost debug header override
    if context and context.waf then
        vhost_debug_override = context.waf.debug_headers
    end

    -- Final debug decision: global must be ON first, then check vhost override
    local expose_headers = global_expose_headers
    if global_expose_headers and vhost_debug_override ~= nil then
        expose_headers = vhost_debug_override
    end

    -- Always set X-WAF-Debug header for HAProxy (even for non-form requests)
    ngx.req.set_header("X-WAF-Debug", expose_headers and "on" or "off")

    -- Set context headers early (only if expose_waf_headers is enabled)
    if expose_headers then
        ngx.header["X-WAF-Vhost"] = summary.vhost_id
        ngx.header["X-WAF-Vhost-Match"] = summary.vhost_match
        ngx.header["X-WAF-Endpoint"] = summary.endpoint_id or "global"
        ngx.header["X-WAF-Match-Type"] = summary.endpoint_match
        ngx.header["X-WAF-Mode"] = summary.mode
    end

    -- Store context for use in balancer phase
    ngx.ctx.waf_context = context
    ngx.ctx.waf_routing = vhost_resolver.get_routing(context)

    -- Set upstream URL for nginx proxy_pass (dynamic routing based on vhost config)
    local upstream_url = vhost_resolver.get_upstream_url(context)
    if upstream_url then
        ngx.var.upstream_url = upstream_url
    else
        -- Fallback to global HAProxy (uses HAPROXY_UPSTREAM/HAPROXY_UPSTREAM_SSL env vars)
        local global_routing = waf_config.get_routing()
        if global_routing.upstream_ssl then
            ngx.var.upstream_url = "https://" .. (global_routing.haproxy_upstream_ssl or "haproxy:8443")
        else
            ngx.var.upstream_url = "http://" .. (global_routing.haproxy_upstream or "haproxy:8080")
        end
    end

    -- Set rate limiting headers for HAProxy (request headers, not response)
    local rate_limiting = vhost_resolver.get_rate_limiting(context)
    if rate_limiting and rate_limiting.enabled then
        ngx.req.set_header("X-WAF-Rate-Limit", "on")
        ngx.req.set_header("X-WAF-Rate-Limit-Value", tostring(rate_limiting.requests_per_minute or 30))
    else
        ngx.req.set_header("X-WAF-Rate-Limit", "off")
    end

    -- Send WAF mode to HAProxy so it knows whether to block or just track
    -- In monitoring/passthrough mode, HAProxy should track but not block
    ngx.req.set_header("X-WAF-Mode", summary.mode)

    -- Send dynamic thresholds to HAProxy for per-vhost/endpoint enforcement
    local haproxy_thresholds = vhost_resolver.get_thresholds(context)
    ngx.req.set_header("X-WAF-Spam-Threshold", tostring(haproxy_thresholds.spam_score_block or 80))
    ngx.req.set_header("X-WAF-Hash-Rate-Threshold", tostring(haproxy_thresholds.hash_count_block or 10))
    ngx.req.set_header("X-WAF-IP-Spam-Threshold", tostring(haproxy_thresholds.ip_spam_score_threshold or 500))
    ngx.req.set_header("X-WAF-Fingerprint-Threshold", tostring(haproxy_thresholds.fingerprint_rate_limit or 20))

    -- Check if WAF should be skipped
    if vhost_resolver.should_skip_waf(context) then
        if expose_headers then
            ngx.header["X-WAF-Skipped"] = "true"
            ngx.header["X-WAF-Skip-Reason"] = context.reason or "unknown"
        end
        ngx.log(ngx.DEBUG, string.format(
            "WAF SKIPPED: host=%s path=%s vhost=%s endpoint=%s reason=%s",
            host, path, summary.vhost_id, summary.endpoint_id or "none", context.reason or "unknown"
        ))
        -- Even in passthrough mode, set timing cookie on GET requests
        -- This ensures timing validation works when form is submitted
        if method == "GET" then
            local timing_config = vhost_resolver.get_timing_config(context)
            if timing_config and timing_config.enabled then
                local current_path = ngx.var.uri
                if timing_token.should_set_token_for_path(current_path, timing_config) then
                    timing_token.set_token(context)
                end
            end
        end
        metrics.record_request(summary.vhost_id, summary.endpoint_id, "skipped", 0)
        return
    end

    -- Get effective endpoint config from context
    local effective_config = context.endpoint

    -- Only process configured HTTP methods with form data
    -- Default: POST/PUT/PATCH, but can be overridden per endpoint
    local allowed_methods = {"POST", "PUT", "PATCH"}
    if effective_config and effective_config.matching and effective_config.matching.methods then
        allowed_methods = effective_config.matching.methods
    end

    local method_allowed = false
    for _, m in ipairs(allowed_methods) do
        if m == "*" or m:upper() == method then
            method_allowed = true
            break
        end
    end

    if not method_allowed then
        -- Not a form submission method
        -- But if this is a GET request, set timing token for future form submissions
        -- Now uses vhost timing config for path-aware timing
        if method == "GET" then
            local timing_config = vhost_resolver.get_timing_config(context)
            if timing_config and timing_config.enabled then
                local current_path = ngx.var.uri
                if timing_token.should_set_token_for_path(current_path, timing_config) then
                    timing_token.set_token(context)
                end
            end
        end
        metrics.record_request(summary.vhost_id, summary.endpoint_id, "allowed", 0)
        return
    end

    -- Check if this is a form submission (content type check)
    local valid_content_type = false
    local allowed_content_types = {"application/x-www-form-urlencoded", "multipart/form-data", "application/json"}

    if effective_config and effective_config.matching and effective_config.matching.content_types then
        allowed_content_types = effective_config.matching.content_types
    end

    for _, ct in ipairs(allowed_content_types) do
        if ct == "*" or content_type:find(ct, 1, true) then
            valid_content_type = true
            break
        end
    end

    if not valid_content_type then
        -- Not a form content type, record as allowed passthrough
        metrics.record_request(summary.vhost_id, summary.endpoint_id, "allowed", 0)
        return
    end

    -- Get client IP (considering proxies)
    local client_ip = ngx.var.http_x_forwarded_for or ngx.var.remote_addr
    if client_ip then
        -- Take first IP if multiple
        client_ip = client_ip:match("([^,]+)")
    end

    -- Check IP allowlist first (supports both exact IPs and CIDR ranges)
    local allowlist = ngx.shared.ip_whitelist
    local cidr_cache = ngx.shared.ip_whitelist_cidr
    local cidr_list = nil

    -- Load CIDR list from cache if available
    if cidr_cache then
        local cidr_json = cidr_cache:get("cidrs")
        if cidr_json then
            cidr_list = cjson.decode(cidr_json)
        end
    end

    -- Check both exact IP match and CIDR range match
    if ip_utils.is_ip_allowlisted(client_ip, allowlist, cidr_list) then
        if expose_headers then
            ngx.header["X-Allowed-IP"] = "true"
        end
        metrics.record_request(summary.vhost_id, summary.endpoint_id, "allowed", 0)
        return
    end

    -- Initialize pre-form variables for early IP checks
    local early_spam_score = 0
    local early_spam_flags = {}
    local early_blocked = false
    local early_block_reason = nil

    -- GeoIP check (optional feature - gracefully degrades if not configured)
    -- Checks country restrictions, ASN blocking, and datacenter detection
    if geoip.is_available() then
        local geo_result = geoip.check_ip(client_ip, effective_config)
        if geo_result.blocked then
            early_blocked = true
            early_block_reason = geo_result.reason
            if expose_headers then
                ngx.header["X-GeoIP-Country"] = geo_result.geo.country_code or "unknown"
                ngx.header["X-GeoIP-ASN"] = tostring(geo_result.geo.asn or "unknown")
            end
        else
            early_spam_score = early_spam_score + geo_result.score
            for _, flag in ipairs(geo_result.flags) do
                table.insert(early_spam_flags, flag)
            end
        end
        -- Store geo info in context for later use
        ngx.ctx.geo_info = geo_result.geo
    end

    -- IP Reputation check (optional feature - gracefully degrades if not configured)
    -- Checks AbuseIPDB, local blocklist, custom webhooks
    if ip_reputation.is_available() then
        local rep_result = ip_reputation.check_ip(client_ip, effective_config)
        if rep_result.blocked then
            early_blocked = true
            early_block_reason = rep_result.reason
        else
            early_spam_score = early_spam_score + rep_result.score
            for _, flag in ipairs(rep_result.flags) do
                table.insert(early_spam_flags, flag)
            end
        end
        -- Store reputation info for audit logging
        ngx.ctx.reputation_info = rep_result.details
    end

    -- Early block for GeoIP/Reputation (before parsing form body)
    if early_blocked then
        local should_block = vhost_resolver.should_block(context)

        if should_block then
            if expose_headers then
                ngx.header["X-Blocked"] = "true"
                ngx.header["X-Block-Reason"] = early_block_reason
            end

            ngx.log(ngx.WARN, string.format(
                "BLOCKED_EARLY: ip=%s host=%s path=%s vhost=%s endpoint=%s reason=%s",
                client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                early_block_reason
            ))

            audit_log("request_blocked_early", {
                vhost_id = summary.vhost_id,
                endpoint_id = summary.endpoint_id,
                reason = early_block_reason,
                geo_info = ngx.ctx.geo_info,
                reputation_info = ngx.ctx.reputation_info,
            })

            metrics.record_request(summary.vhost_id, summary.endpoint_id, "blocked", 0)

            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header["Content-Type"] = "application/json"
            local error_response = { error = "Request blocked" }
            if expose_headers then
                error_response.reason = early_block_reason
            end
            ngx.say(cjson.encode(error_response))
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        else
            -- Monitoring mode - log but don't block
            if expose_headers then
                ngx.header["X-WAF-Would-Block"] = "true"
                ngx.header["X-WAF-Block-Reason"] = early_block_reason
            end
            ngx.log(ngx.WARN, string.format(
                "MONITORING (would block early): ip=%s host=%s path=%s vhost=%s endpoint=%s reason=%s",
                client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                early_block_reason
            ))
        end
    end

    -- Parse form data
    local form_data, err = form_parser.parse()
    if err then
        ngx.log(ngx.WARN, "Form parsing error: ", err)
        -- Continue without blocking on parse errors
        metrics.record_request(summary.vhost_id, summary.endpoint_id, "allowed", 0)
        return
    end

    if not form_data or next(form_data) == nil then
        -- Empty form, allow through
        metrics.record_request(summary.vhost_id, summary.endpoint_id, "allowed", 0)
        return
    end

    -- Record form submission for metrics
    metrics.record_form_submission(summary.vhost_id, summary.endpoint_id)

    -- Field learning: Record observed fields for configuration assistance
    -- Uses probabilistic sampling and batching to minimize performance impact
    local endpoint_id = summary.endpoint_id
    local vhost_id = summary.vhost_id
    field_learner.record_fields(form_data, endpoint_id, vhost_id)

    -- Validate required fields if configured
    local valid, field_errors = vhost_resolver.validate_fields(context, form_data)
    if not valid and vhost_resolver.should_block(context) then
        metrics.record_validation_error(summary.vhost_id, summary.endpoint_id)
        metrics.record_request(summary.vhost_id, summary.endpoint_id, "blocked", 0)
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Validation failed",
            errors = field_errors,
            vhost = summary.vhost_id,
            endpoint = summary.endpoint_id
        }))
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    -- Initialize response tracking (include early scores from GeoIP/reputation)
    local spam_score = early_spam_score or 0
    local spam_flags = early_spam_flags or {}
    local blocked = false
    local block_reason = nil

    -- Get thresholds from context
    local thresholds = vhost_resolver.get_thresholds(context)

    -- Get security settings
    local security = vhost_resolver.get_security_settings(context)

    -- Step 0a: Timing token validation
    -- Check if submission has valid timing (not too fast, has cookie)
    -- Now uses vhost timing config for path-aware validation
    local timing_config = vhost_resolver.get_timing_config(context)
    if timing_config and timing_config.enabled then
        local current_path = ngx.var.uri
        if timing_token.should_validate_for_path(current_path, timing_config) then
            local timing_result = timing_token.validate_token(context)
            if timing_result.score > 0 then
                spam_score = spam_score + timing_result.score
                if timing_result.flag then
                    table.insert(spam_flags, timing_result.flag)
                end
                ngx.log(ngx.INFO, string.format(
                    "TIMING_CHECK: ip=%s vhost=%s reason=%s score=%d elapsed=%s",
                    client_ip, summary.vhost_id, timing_result.reason, timing_result.score,
                    timing_result.elapsed and string.format("%.2fs", timing_result.elapsed) or "n/a"
                ))
            end
            -- Strip timing cookie before forwarding to backend
            timing_token.strip_cookie(context)

            -- Store timing result for behavioral tracking (elapsed time)
            ngx.ctx.timing_result = timing_result
        end
    end

    -- Step 0a2: Behavioral tracking - match flow and check anomalies
    -- Check if this request matches a behavioral flow (end path)
    local behavioral_context = nil
    local vhost_config = context.vhost_config
    if vhost_config and vhost_config.behavioral and vhost_config.behavioral.enabled then
        local flows = vhost_config.behavioral.flows
        if flows and #flows > 0 then
            local matched_flow = behavioral_tracker.match_flow(flows, path, method, false) -- false = end path
            if matched_flow then
                behavioral_context = {
                    vhost_id = summary.vhost_id,
                    flow_name = matched_flow.name,
                    vhost_config = vhost_config
                }
                ngx.ctx.behavioral_context = behavioral_context

                -- Check for anomalies against baseline
                local behavioral_result = behavioral_tracker.check_anomaly(behavioral_context)
                if behavioral_result.score > 0 then
                    spam_score = spam_score + behavioral_result.score
                    for _, flag in ipairs(behavioral_result.flags) do
                        table.insert(spam_flags, flag)
                    end
                    ngx.log(ngx.INFO, string.format(
                        "BEHAVIORAL_ANOMALY: ip=%s vhost=%s flow=%s score=%d z_score=%.2f",
                        client_ip, summary.vhost_id, matched_flow.name, behavioral_result.score,
                        behavioral_result.details.z_score or 0
                    ))
                end
            end
        end
    end

    -- Step 0b: Honeypot field detection
    -- Check if any configured honeypot fields have values (bots fill hidden fields)
    local honeypot_fields = vhost_resolver.get_honeypot_fields(context)
    if #honeypot_fields > 0 then
        for _, hp_field in ipairs(honeypot_fields) do
            local hp_value = form_data[hp_field] or form_data[hp_field:lower()]
            if hp_value and hp_value ~= "" then
                -- Honeypot triggered!
                table.insert(spam_flags, "honeypot:" .. hp_field)

                ngx.log(ngx.WARN, string.format(
                    "HONEYPOT: ip=%s host=%s path=%s field=%s value=%s action=%s",
                    client_ip, host, path, hp_field, tostring(hp_value):sub(1, 50), security.honeypot_action
                ))

                -- Structured audit log for honeypot
                audit_log("honeypot_triggered", {
                    vhost_id = summary.vhost_id,
                    endpoint_id = summary.endpoint_id,
                    honeypot_field = hp_field,
                    value_preview = tostring(hp_value):sub(1, 50),
                    action = security.honeypot_action,
                })

                if security.honeypot_action == "block" then
                    -- Set blocked flag - actual blocking respects mode (monitoring vs blocking)
                    blocked = true
                    block_reason = "honeypot_triggered"
                    -- Send webhook notification for honeypot trigger
                    webhooks.notify_honeypot(context, hp_field)
                else
                    -- Flag mode: add score
                    spam_score = spam_score + security.honeypot_score
                end
            end
        end
    end

    -- Step 1: Keyword filtering
    -- Get ignore fields to exclude from keyword scanning (e.g., CSRF tokens)
    local keyword_ignore_fields = vhost_resolver.get_ignore_fields(context)
    local keyword_result = keyword_filter.scan(form_data, keyword_ignore_fields)

    -- Apply context-specific keyword exclusions
    if keyword_result.blocked_keywords and #keyword_result.blocked_keywords > 0 then
        local filtered_blocked = {}
        for _, kw in ipairs(keyword_result.blocked_keywords) do
            if not vhost_resolver.is_keyword_excluded(context, kw, "blocked") then
                table.insert(filtered_blocked, kw)
            end
        end

        if #filtered_blocked > 0 and vhost_resolver.should_inherit_global_keywords(context) then
            blocked = true
            block_reason = "blocked_keyword"
            for _, kw in ipairs(filtered_blocked) do
                table.insert(spam_flags, "kw:" .. kw)
            end
        end
    end

    -- Add score from flagged keywords (with exclusions)
    if keyword_result.flagged_keywords then
        for _, kw in ipairs(keyword_result.flagged_keywords) do
            if not vhost_resolver.is_keyword_excluded(context, kw, "flagged") then
                table.insert(spam_flags, "flag:" .. kw)
            end
        end
    end

    -- Only add score if inheriting global keywords
    if vhost_resolver.should_inherit_global_keywords(context) then
        spam_score = spam_score + (keyword_result.score or 0)
    end

    -- Check context-specific additional keywords (vhost + endpoint)
    local additional = vhost_resolver.get_additional_keywords(context)
    if #additional.blocked > 0 or #additional.flagged > 0 then
        -- Build exclude set from ignore fields
        local additional_ignore = vhost_resolver.get_ignore_fields(context)
        local additional_exclude = {}
        for _, f in ipairs(additional_ignore) do
            additional_exclude[f] = true
        end
        local combined_text = form_parser.get_combined_text(form_data, additional_exclude):lower()

        for _, kw in ipairs(additional.blocked) do
            if combined_text:find(kw:lower(), 1, true) then
                blocked = true
                block_reason = "additional_blocked_keyword"
                table.insert(spam_flags, "add_kw:" .. kw)
            end
        end

        for _, entry in ipairs(additional.flagged) do
            local kw, score_str = entry:match("([^:]+):?(%d*)")
            local kw_score = tonumber(score_str) or 10
            if kw and combined_text:find(kw:lower(), 1, true) then
                spam_score = spam_score + kw_score
                table.insert(spam_flags, "add_flag:" .. kw)
            end
        end
    end

    -- Step 2: Content hashing
    -- Inverted paradigm: if specific fields configured, hash ONLY those
    -- This prevents bots from changing hash by adding random fields
    -- Canonical location: fields.hash = { enabled: bool, fields: [...] }
    local hash_config = vhost_resolver.get_hash_config(context)
    local form_hash

    if hash_config.enabled and hash_config.fields and #hash_config.fields > 0 then
        -- Hash ONLY the specified fields (sorted alphabetically in hash_fields)
        form_hash = content_hasher.hash_fields(form_data, hash_config.fields)
    else
        -- Hash all fields, excluding configured ignored fields (CSRF tokens, etc.)
        local ignore_fields = vhost_resolver.get_ignore_fields(context)
        local exclude_set = {}
        for _, f in ipairs(ignore_fields) do
            exclude_set[f:lower()] = true
        end
        form_hash = content_hasher.hash_form(form_data, { exclude_fields = exclude_set })
    end

    -- Check if hash is in blocklist
    if form_hash and form_hash ~= "empty" then
        local hash_blocked = keyword_filter.is_hash_blocked(form_hash)
        if hash_blocked then
            blocked = true
            block_reason = "blocked_hash"
            table.insert(spam_flags, "hash:blocked")
        end
    end

    -- Step 2b: Expected fields validation
    -- If endpoint specifies expected_fields (optional) or required fields, flag/block any unexpected fields
    -- Required fields are inherently expected, so we combine both lists
    local expected_fields = vhost_resolver.get_expected_fields(context)
    local required_fields = vhost_resolver.get_required_fields(context)

    -- Build combined set of allowed fields (required + expected + ignored)
    local has_field_restrictions = (expected_fields and #expected_fields > 0) or (required_fields and #required_fields > 0)

    if has_field_restrictions then
        local allowed_set = {}

        -- Required fields are expected
        if required_fields then
            for _, f in ipairs(required_fields) do
                allowed_set[f:lower()] = true
            end
        end

        -- Optional expected fields
        if expected_fields then
            for _, f in ipairs(expected_fields) do
                allowed_set[f:lower()] = true
            end
        end

        -- Ignored fields (CSRF tokens etc.) are always allowed
        local ignore_fields = vhost_resolver.get_ignore_fields(context)
        for _, f in ipairs(ignore_fields) do
            allowed_set[f:lower()] = true
        end

        -- Honeypot fields are expected (they're intentionally added to catch bots)
        for _, f in ipairs(honeypot_fields) do
            allowed_set[f:lower()] = true
        end

        local unexpected_fields = {}
        for field_name, _ in pairs(form_data) do
            if type(field_name) == "string" then
                local field_lower = field_name:lower()
                -- Field is unexpected if not in allowed set
                if not allowed_set[field_lower] then
                    table.insert(unexpected_fields, field_name)
                end
            end
        end

        if #unexpected_fields > 0 then
            -- Get action for unexpected fields (default: flag)
            local unexpected_action = vhost_resolver.get_unexpected_fields_action(context)
            if unexpected_action == "block" then
                blocked = true
                block_reason = "unexpected_fields"
            elseif unexpected_action == "filter" then
                -- Remove unexpected fields from form_data and reconstruct request body
                for _, f in ipairs(unexpected_fields) do
                    form_data[f] = nil
                end
                -- Reconstruct request body based on content type
                local new_body = form_parser.reconstruct_body(form_data, content_type)
                if new_body then
                    ngx.req.set_body_data(new_body)
                    ngx.req.set_header("X-WAF-Filtered", "true")
                    ngx.req.set_header("X-WAF-Filtered-Fields", table.concat(unexpected_fields, ","))
                end
            elseif unexpected_action ~= "ignore" then
                -- Default: flag (add score)
                spam_score = spam_score + (5 * #unexpected_fields)
            end
            for _, f in ipairs(unexpected_fields) do
                table.insert(spam_flags, "unexpected:" .. f)
            end
        end
    end

    -- Step 3: Pattern-based scoring
    local should_inherit_patterns = true
    if context.endpoint then
        should_inherit_patterns = config_resolver.should_inherit_global_patterns(context.endpoint)
    end

    if should_inherit_patterns then
        -- Get ignore fields to exclude from pattern scanning (e.g., CSRF tokens)
        local ignore_fields = vhost_resolver.get_ignore_fields(context)
        local pattern_result = keyword_filter.pattern_scan(form_data, ignore_fields)

        -- Filter out disabled patterns
        if pattern_result.flags and context.endpoint then
            for _, flag_entry in ipairs(pattern_result.flags) do
                local flag_name = flag_entry:match("([^:]+)")
                if not config_resolver.is_pattern_disabled(context.endpoint, flag_name) then
                    table.insert(spam_flags, "pattern:" .. flag_entry)
                end
            end
        elseif pattern_result.flags then
            for _, flag_entry in ipairs(pattern_result.flags) do
                table.insert(spam_flags, "pattern:" .. flag_entry)
            end
        end

        -- Add pattern score
        spam_score = spam_score + (pattern_result.score or 0)
    end

    -- Check endpoint-specific custom patterns
    if context.endpoint then
        local custom_patterns = config_resolver.get_custom_patterns(context.endpoint)
        if #custom_patterns > 0 then
            -- Build exclude set from ignore fields
            local custom_ignore_fields = vhost_resolver.get_ignore_fields(context)
            local exclude_set = {}
            for _, f in ipairs(custom_ignore_fields) do
                exclude_set[f] = true
            end
            local combined_text = form_parser.get_combined_text(form_data, exclude_set)
            for _, pattern_def in ipairs(custom_patterns) do
                local matches = {}
                for match in combined_text:gmatch(pattern_def.pattern) do
                    table.insert(matches, match)
                end
                if #matches > 0 then
                    local pattern_score = (pattern_def.score or 10) * math.min(#matches, 5)
                    spam_score = spam_score + pattern_score
                    table.insert(spam_flags, "ep_pattern:" .. (pattern_def.flag or "custom") .. ":" .. #matches)
                end
            end
        end
    end

    -- Step 3b: Disposable email detection
    if security.check_disposable_email then
        local disposable_result = keyword_filter.check_disposable_emails(form_data)
        if disposable_result.found then
            -- Found disposable email(s)
            for _, email in ipairs(disposable_result.emails) do
                table.insert(spam_flags, "disposable:" .. email)
            end

            if security.disposable_email_action == "block" then
                blocked = true
                block_reason = "disposable_email"
                ngx.log(ngx.WARN, string.format(
                    "DISPOSABLE_EMAIL: ip=%s host=%s path=%s emails=%s",
                    client_ip, host, path, table.concat(disposable_result.emails, ",")
                ))
                -- Structured audit log for disposable email
                audit_log("disposable_email_blocked", {
                    vhost_id = summary.vhost_id,
                    endpoint_id = summary.endpoint_id,
                    disposable_emails = disposable_result.emails,
                    domains = disposable_result.domains,
                })
                -- Send webhook notification for disposable email
                webhooks.notify_disposable_email(context, disposable_result.emails)
            elseif security.disposable_email_action ~= "ignore" then
                -- Default: flag (add score)
                spam_score = spam_score + (security.disposable_email_score * #disposable_result.emails)
            end
        end
    end

    -- Step 3c: Field anomaly detection
    -- Detects bot-like patterns: same field lengths, sequential data, all caps, test data
    if security.check_field_anomalies ~= false then  -- Enabled by default
        -- Pass ignore_fields to exclude CSRF tokens, captchas, etc. from anomaly detection
        local anomaly_ignore_fields = vhost_resolver.get_ignore_fields(context)
        local anomaly_result = detect_field_anomalies(form_data, security, anomaly_ignore_fields)
        if anomaly_result.score > 0 then
            spam_score = spam_score + anomaly_result.score
            for _, flag in ipairs(anomaly_result.flags) do
                table.insert(spam_flags, "anomaly:" .. flag)
            end
        end
    end

    -- Step 3d: Generate submission fingerprint using profile matching
    -- Fingerprint profiles detect client types (browser, bot, script) and select headers for fingerprinting
    -- The profile-based approach allows matching on header presence/absence patterns
    local fp_config = vhost_resolver.get_fingerprint_profiles(context)
    local fp_result = fingerprint_profiles.process_request(form_data, ngx.var, fp_config)

    -- Add fingerprint profile score to spam score
    if fp_result.score and fp_result.score > 0 then
        spam_score = spam_score + fp_result.score
    end

    -- Add fingerprint profile flags
    if fp_result.flags then
        for _, flag in ipairs(fp_result.flags) do
            table.insert(spam_flags, flag)
        end
    end

    -- Handle profile-based blocking
    if fp_result.blocked then
        blocked = true
        block_reason = "fingerprint_profile_block"
    end

    local submission_fingerprint = fp_result.fingerprint
    local fingerprint_profile_id = fp_result.profile_id

    -- Step 4: Check spam score threshold
    local block_threshold = vhost_resolver.get_block_threshold(context)
    if spam_score >= block_threshold then
        blocked = true
        block_reason = "spam_score_exceeded"
        table.insert(spam_flags, "score:exceeded")
    end

    -- Set request headers for HAProxy (upstream) - always set for internal use
    if form_hash and form_hash ~= "empty" then
        ngx.req.set_header("X-Form-Hash", form_hash)
    end
    ngx.req.set_header("X-Spam-Score", tostring(spam_score))
    ngx.req.set_header("X-Spam-Flags", table.concat(spam_flags, ","))
    ngx.req.set_header("X-Client-IP", client_ip)
    if submission_fingerprint then
        ngx.req.set_header("X-Submission-Fingerprint", submission_fingerprint)
    end
    if fingerprint_profile_id then
        ngx.req.set_header("X-Fingerprint-Profile", fingerprint_profile_id)
    end
    -- Override fingerprint rate limit if profile specifies one
    if fp_result.fingerprint_rate_limit then
        ngx.req.set_header("X-WAF-Fingerprint-Threshold", tostring(fp_result.fingerprint_rate_limit))
    end

    -- Determine if we should actually block
    local should_block = blocked and vhost_resolver.should_block(context)

    -- Set response headers for debugging (only if expose_waf_headers is enabled)
    if expose_headers then
        if form_hash and form_hash ~= "empty" then
            ngx.header["X-Form-Hash"] = form_hash
        end
        ngx.header["X-Spam-Score"] = tostring(spam_score)
        ngx.header["X-Spam-Flags"] = table.concat(spam_flags, ",")
        ngx.header["X-Client-IP"] = client_ip
        if submission_fingerprint then
            ngx.header["X-Submission-Fingerprint"] = submission_fingerprint
        end
        if fingerprint_profile_id then
            ngx.header["X-Fingerprint-Profile"] = fingerprint_profile_id
        end

        -- Always show blocked state and reason when debug headers enabled
        if blocked then
            ngx.header["X-WAF-Would-Block"] = "true"
            ngx.header["X-WAF-Block-Reason"] = block_reason
            ngx.header["X-WAF-Blocked"] = should_block and "true" or "false"
        end
    end

    -- In monitoring mode, log but don't block
    if blocked and not should_block then
        ngx.log(ngx.WARN, string.format(
            "MONITORING (would block): ip=%s host=%s path=%s vhost=%s endpoint=%s reason=%s score=%d hash=%s fp=%s fp_profile=%s flags=%s",
            client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
            block_reason, spam_score, form_hash or "none", submission_fingerprint or "none",
            fingerprint_profile_id or "default", table.concat(spam_flags, ",")
        ))
        metrics.record_request(summary.vhost_id, summary.endpoint_id, "monitored", spam_score)

        -- Record behavioral tracking data (if flow matched)
        if ngx.ctx.behavioral_context then
            local fill_duration = ngx.ctx.timing_result and ngx.ctx.timing_result.elapsed or nil
            behavioral_tracker.record_submission(
                ngx.ctx.behavioral_context,
                fill_duration,
                spam_score,
                "monitored",
                client_ip
            )
        end
        return
    end

    -- If blocked at OpenResty level, check CAPTCHA before actually blocking
    if should_block then
        -- Check if CAPTCHA should be used instead of blocking
        local captcha_config = captcha_handler.get_captcha_config(context)

        if captcha_config and captcha_config.enabled then
            -- Check for valid trust token first
            if captcha_handler.has_valid_trust(context, client_ip) then
                -- User has solved CAPTCHA recently, allow through
                ngx.log(ngx.INFO, string.format(
                    "CAPTCHA_TRUSTED: ip=%s host=%s path=%s vhost=%s endpoint=%s reason=%s score=%d",
                    client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                    block_reason, spam_score
                ))
                metrics.record_request(summary.vhost_id, summary.endpoint_id, "captcha_trusted", spam_score)
                -- Don't block, continue to proxy
            else
                -- No valid trust token, serve CAPTCHA challenge
                ngx.log(ngx.WARN, string.format(
                    "CAPTCHA_CHALLENGE: ip=%s host=%s path=%s vhost=%s endpoint=%s reason=%s score=%d",
                    client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                    block_reason, spam_score
                ))
                metrics.record_request(summary.vhost_id, summary.endpoint_id, "captcha_challenged", spam_score)

                -- Send webhook notification for CAPTCHA challenge (async, non-blocking)
                webhooks.notify_captcha_triggered(context, block_reason)

                return captcha_handler.serve_challenge(context, form_data, block_reason, client_ip)
            end
        else
            -- No CAPTCHA enabled, use original blocking behavior
            if expose_headers then
                ngx.header["X-Blocked"] = "true"
                ngx.header["X-Block-Reason"] = block_reason
            end

            -- Log the block
            ngx.log(ngx.WARN, string.format(
                "BLOCKED: ip=%s host=%s path=%s vhost=%s endpoint=%s reason=%s score=%d hash=%s fp=%s fp_profile=%s flags=%s",
                client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                block_reason, spam_score, form_hash or "none", submission_fingerprint or "none",
                fingerprint_profile_id or "default", table.concat(spam_flags, ",")
            ))

            -- Structured audit log
            audit_log("request_blocked", {
                vhost_id = summary.vhost_id,
                endpoint_id = summary.endpoint_id,
                reason = block_reason,
                spam_score = spam_score,
                form_hash = form_hash,
                spam_flags = spam_flags,
                fingerprint = submission_fingerprint,
                fingerprint_profile = fingerprint_profile_id,
            })

            -- Record blocked request in metrics
            metrics.record_request(summary.vhost_id, summary.endpoint_id, "blocked", spam_score)

            -- Record behavioral tracking data (if flow matched)
            if ngx.ctx.behavioral_context then
                local fill_duration = ngx.ctx.timing_result and ngx.ctx.timing_result.elapsed or nil
                behavioral_tracker.record_submission(
                    ngx.ctx.behavioral_context,
                    fill_duration,
                    spam_score,
                    "blocked",
                    client_ip
                )
            end

            -- Send webhook notification (async, non-blocking)
            webhooks.notify_blocked(context, block_reason, spam_score, spam_flags)

            -- Return 403 with JSON error (minimal info to client)
            ngx.status = ngx.HTTP_FORBIDDEN
            ngx.header["Content-Type"] = "application/json"
            local error_response = { error = "Request blocked" }
            if expose_headers then
                error_response.reason = block_reason
                error_response.vhost = summary.vhost_id
                error_response.endpoint = summary.endpoint_id
                error_response.request_id = ngx.var.request_id or ngx.now()
            end
            ngx.say(cjson.encode(error_response))
            return ngx.exit(ngx.HTTP_FORBIDDEN)
        end
    end

    -- Log processing info
    ngx.log(ngx.INFO, string.format(
        "PROCESSED: ip=%s host=%s path=%s vhost=%s endpoint=%s mode=%s score=%d hash=%s fp=%s fp_profile=%s flags=%s",
        client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
        summary.mode, spam_score, form_hash or "none", submission_fingerprint or "none",
        fingerprint_profile_id or "default", table.concat(spam_flags, ",")
    ))

    -- Record allowed request in metrics
    metrics.record_request(summary.vhost_id, summary.endpoint_id, "allowed", spam_score)

    -- Record behavioral tracking data (if flow matched)
    if ngx.ctx.behavioral_context then
        local fill_duration = ngx.ctx.timing_result and ngx.ctx.timing_result.elapsed or nil
        behavioral_tracker.record_submission(
            ngx.ctx.behavioral_context,
            fill_duration,
            spam_score,
            "allowed",
            client_ip
        )
    end
end

-- Get routing decision for balancer phase
-- Returns: {use_haproxy = bool, upstream_url = string|nil, haproxy_backend = string|nil}
function _M.get_routing_decision()
    local routing = ngx.ctx.waf_routing
    if not routing then
        return {use_haproxy = true}
    end

    return {
        use_haproxy = routing.use_haproxy,
        upstream = routing.upstream,
        haproxy_backend = routing.haproxy_backend
    }
end

-- Get vhost context (for use in other modules)
function _M.get_context()
    return ngx.ctx.waf_context
end

return _M
