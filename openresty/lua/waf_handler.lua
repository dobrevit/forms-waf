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
local trusted_proxies = require "trusted_proxies"
local behavioral_tracker = require "behavioral_tracker"
local fingerprint_profiles = require "fingerprint_profiles"
local header_consistency = require "header_consistency"
local cjson = require "cjson.safe"
local charset = require "charset"

-- Lazy-load defense profile multi-executor to avoid startup overhead
local _multi_executor
local _defense_mechanisms_loaded = false

local function get_multi_executor()
    -- Ensure defense mechanisms are registered on first use
    if not _defense_mechanisms_loaded then
        require "defense_mechanisms"
        _defense_mechanisms_loaded = true
    end

    if not _multi_executor then
        _multi_executor = require "defense_profile_multi_executor"
    end
    return _multi_executor
end

-- F08: HMAC key for log integrity (optional)
local LOG_HMAC_KEY = os.getenv("WAF_LOG_HMAC_KEY")

local collect_trace

--- The request id, stable for the life of the request.
--
-- $request_id is NOT cached by this nginx build: every read of
-- ngx.var.request_id mints a fresh value. Two adjacent reads in one request
-- return different ids, which quietly made every id the WAF emitted useless for
-- correlation -- the audit log entry and the webhook for the same request
-- carried different "request ids", and neither matched the response header.
-- Read once, cached on ngx.ctx, shared by everything that reports an id.
local function request_id()
    local rid = ngx.ctx.waf_request_id
    if not rid then
        rid = ngx.var.request_id
        if not rid or rid == "" then
            -- Hex, matching $request_id's shape. A decimal timestamp would be
            -- unqueryable: the route and RBAC patterns for /decisions/{id} are
            -- hex-only, so an id that is not hex records a decision nobody can
            -- look up -- the one thing the id exists for.
            rid = ngx.md5(string.format("%s:%s:%s",
                ngx.now(), ngx.worker.pid(), ngx.var.connection or "0"))
        end
        ngx.ctx.waf_request_id = rid
    end
    return rid
end

-- Append to whichever trace a result carries. Scores added outside the profile
-- executor -- vhost keywords here, defense lines in the multi-executor -- have
-- to land in the trace too, or the detail view shows a total that its own
-- breakdown does not account for.
local function add_trace_entry(profile_result, entry)
    if type(profile_result) ~= "table" then return end

    if type(profile_result.trace) == "table" then
        table.insert(profile_result.trace, entry)
        return
    end

    -- Multi-profile result: no top-level trace, so carry these in a list the
    -- flattener folds in alongside the per-profile ones.
    profile_result.extra_trace = profile_result.extra_trace or {}
    table.insert(profile_result.extra_trace, entry)
end

-- Keep a would-block decision so "what happens if I switch this to blocking?"
-- becomes a query rather than a log grep.
--
-- There are two would-block branches in process_request and both must record.
-- Capturing only one would silently understate the impact of promoting an
-- endpoint, which is the one thing this feature exists to get right.
--
-- The recorder buffers in a shared dict and a timer drains it: the request path
-- must not touch Redis, and a timer per request would exhaust the timer pool.
-- Resolved once and cached, following get_multi_executor above. This runs on
-- every would-block request, and pcall(require, ...) on a hot path is overhead
-- for a lookup whose answer never changes. _shadow_tried keeps a failed require
-- from being retried on every request too.
local _shadow_recorder
local _shadow_tried = false

local function get_shadow_recorder()
    if not _shadow_tried then
        _shadow_tried = true
        local ok, mod = pcall(require, "shadow_recorder")
        if ok then _shadow_recorder = mod end
    end
    return _shadow_recorder
end

-- The executor returns a per-node trace per profile. Flatten them into one list
-- so a detail view can read the decision top to bottom without knowing how many
-- profiles ran.
collect_trace = function(profile_result)
    if type(profile_result) ~= "table" then return nil end

    -- Single-profile results carry the trace directly; multi-profile results
    -- nest one per profile.
    if profile_result.trace then
        return profile_result.trace
    end

    local results = profile_result.profile_results
    if type(results) ~= "table" then return profile_result.extra_trace end

    local flat = {}
    for profile_id, r in pairs(results) do
        if type(r) == "table" and type(r.trace) == "table" then
            for _, entry in ipairs(r.trace) do
                if type(entry) == "table" then
                    entry.profile = profile_id
                    flat[#flat + 1] = entry
                end
            end
        end
    end
    for _, entry in ipairs(profile_result.extra_trace or {}) do
        flat[#flat + 1] = entry
    end
    return flat
end

local function record_shadow_decision(summary, client_ip, host, path, method, profile_result)
    local shadow_recorder = get_shadow_recorder()
    if not shadow_recorder then
        return
    end
    shadow_recorder.record({
        vhost_id    = summary.vhost_id,
        endpoint_id = summary.endpoint_id,
        client_ip   = client_ip,
        host        = host,
        path        = path,
        method      = method,
        score       = profile_result.score or 0,
        blocked_by  = profile_result.blocked_by,
        flags       = profile_result.flags,
    })
end

-- Structured audit logging for security events
-- Outputs JSON formatted log entries for easy parsing by log aggregation tools
-- F08: Optionally adds HMAC signature for log integrity verification
local function audit_log(event_type, event_data)
    local log_entry = {
        ["@timestamp"] = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        event_type = event_type,
        request_id = request_id(),
        client_ip = trusted_proxies.get_client_ip(),  -- F01: Use secure IP extraction
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

    -- F08: Add HMAC signature for log integrity if key is configured
    -- Uses proper RFC 2104 HMAC-SHA256: H((K ⊕ opad) || H((K ⊕ ipad) || message))
    if LOG_HMAC_KEY and LOG_HMAC_KEY ~= "" then
        local password_utils = require "password_utils"
        local resty_string = require "resty.string"

        local log_json = cjson.encode(log_entry)
        local hmac_digest = password_utils.hmac_sha256(LOG_HMAC_KEY, log_json)
        log_entry["_integrity"] = resty_string.to_hex(hmac_digest):sub(1, 16)  -- Short signature
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
--- Called from log_by_lua. Records the decision stashed during the access
--- phase, with the status the client actually received attached.
function _M.log_decision()
    local decision = ngx.ctx.waf_decision
    if not decision then
        return
    end

    local ok, recorder = pcall(require, "decision_recorder")
    if not ok or not recorder then
        return
    end

    local status = ngx.status
    -- What happened, from the response rather than from what the pipeline
    -- intended: monitoring mode returns 200 on a verdict of "block", and the
    -- record has to say the request was allowed through.
    local action
    if status == 403 then
        action = "blocked"
    elseif status == 429 then
        action = "tarpit"
    elseif ngx.ctx.waf_captcha_challenged then
        action = "challenged"
    elseif decision.profile_action == "block" then
        action = "would_block"
    else
        action = "allowed"
    end

    decision.action = action
    decision.status = status
    pcall(recorder.record, decision)
end

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

    -- Always set vhost/endpoint headers as request headers for HAProxy routing
    ngx.req.set_header("X-WAF-Vhost", summary.vhost_id or "")
    ngx.req.set_header("X-WAF-Endpoint", summary.endpoint_id or "global")

    -- Set context headers as response headers (only if expose_waf_headers is enabled)
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

    -- Get client IP securely (F01: trusted proxy validation)
    -- Uses nginx real_ip module result, which respects set_real_ip_from directives
    local client_ip = trusted_proxies.get_client_ip()

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

    -- ========================================================================
    -- DEFENSE PROFILE EXECUTION
    -- All defense processing is now handled by the profile system
    -- If no profiles configured, the "legacy" profile is used as default
    -- ========================================================================
    local defense_profiles_config = nil
    local using_default_profile = false

    -- Check endpoint first, then vhost for defense_profiles config
    if effective_config and effective_config.defense_profiles then
        defense_profiles_config = effective_config.defense_profiles
    elseif context.vhost_config and context.vhost_config.defense_profiles then
        defense_profiles_config = context.vhost_config.defense_profiles
    end

    -- If no profiles configured or disabled, use legacy profile as default
    if not defense_profiles_config or not defense_profiles_config.enabled or
       not defense_profiles_config.profiles or #defense_profiles_config.profiles == 0 then
        defense_profiles_config = {
            enabled = true,
            profiles = {
                {id = "legacy", priority = 100, weight = 1}
            },
            aggregation = "OR",
            score_aggregation = "SUM",
            short_circuit = true
        }
        using_default_profile = true
    end

    -- Execute defense profiles (always runs - either configured or default legacy)
    if defense_profiles_config.enabled then

        local multi_executor = get_multi_executor()

        -- Build request context for profile execution
        local request_context = {
            client_ip = client_ip,
            host = host,
            path = path,
            method = method,
            content_type = content_type,
            user_agent = ngx.var.http_user_agent,
            accept_language = ngx.var.http_accept_language,
            accept_encoding = ngx.var.http_accept_encoding,
            referer = ngx.var.http_referer,
            -- Form data will be parsed later if needed by defense mechanisms
            ngx_vars = ngx.var,
            vhost_id = summary.vhost_id,
            endpoint_id = summary.endpoint_id,
            endpoint_config = effective_config,
            vhost_config = context.vhost_config,
            context = context,
        }

        -- Execute all configured profiles
        local profile_result = multi_executor.execute(defense_profiles_config, request_context)

        -- Check vhost/endpoint additional keywords (runs once, after all profiles)
        -- This is separate from defense profiles to avoid duplicate evaluation
        local additional_kw = vhost_resolver.get_additional_keywords(context)
        if additional_kw and (#additional_kw.blocked > 0 or #additional_kw.flagged > 0) then
            -- Parse form data for keyword checking
            local kw_form_data, _ = form_parser.parse()
            if kw_form_data then
                local kw_ignore = vhost_resolver.get_ignore_fields(context)
                local kw_exclude = {}
                for _, f in ipairs(kw_ignore) do
                    kw_exclude[f] = true
                end
                local combined_text = form_parser.get_combined_text(kw_form_data, kw_exclude):lower()

                -- Ensure profile_result.flags exists
                profile_result.flags = profile_result.flags or {}

                -- Track already-checked keywords to avoid duplicates from vhost+endpoint merge
                local checked_blocked = {}
                local checked_flagged = {}

                -- Check additional blocked keywords
                for _, kw in ipairs(additional_kw.blocked) do
                    local kw_lower = kw:lower()
                    if not checked_blocked[kw_lower] and combined_text:find(kw_lower, 1, true) then
                        checked_blocked[kw_lower] = true
                        table.insert(profile_result.flags, "vhost:add_kw:" .. kw)
                        profile_result.action = "block"
                        profile_result.blocked_by = profile_result.blocked_by or {}
                        table.insert(profile_result.blocked_by, "additional_keyword")
                        add_trace_entry(profile_result, {
                            defense = "additional_keyword",
                            score = 0,
                            blocked = true,
                            flags = { "vhost:add_block:" .. kw },
                        })
                        ngx.log(ngx.INFO, "ADDITIONAL_KEYWORD_BLOCK: keyword=", kw)
                    end
                end

                -- Check additional flagged keywords (add to score)
                for _, entry in ipairs(additional_kw.flagged) do
                    local kw, score_str = entry:match("([^:]+):?(%d*)")
                    local kw_score = tonumber(score_str) or 10
                    local kw_lower = kw and kw:lower()
                    if kw_lower and not checked_flagged[kw_lower] and combined_text:find(kw_lower, 1, true) then
                        checked_flagged[kw_lower] = true
                        profile_result.score = (profile_result.score or 0) + kw_score
                        table.insert(profile_result.flags, "vhost:add_flag:" .. kw)
                        add_trace_entry(profile_result, {
                            defense = "additional_keyword",
                            score = kw_score,
                            flags = { "vhost:add_flag:" .. kw },
                        })
                    end
                end
            end
        end

        -- Re-check threshold after vhost keyword scores are added
        -- This ensures that if vhost keywords push score over threshold, action changes to block
        if profile_result.action ~= "block" then
            local block_threshold = vhost_resolver.get_block_threshold(context)
            if profile_result.score and profile_result.score >= block_threshold then
                profile_result.action = "block"
                profile_result.blocked_by = profile_result.blocked_by or {}
                table.insert(profile_result.blocked_by, "spam_score_exceeded")
                profile_result.flags = profile_result.flags or {}
                table.insert(profile_result.flags, "score:exceeded")
                ngx.log(ngx.INFO, string.format(
                    "THRESHOLD_EXCEEDED: ip=%s score=%d threshold=%d",
                    client_ip, profile_result.score, block_threshold
                ))
            end
        end

        -- Log profile execution
        ngx.log(ngx.INFO, string.format(
            "DEFENSE_PROFILES: ip=%s host=%s path=%s vhost=%s endpoint=%s action=%s score=%d profiles=%d blocked_by=%s flags=%s time=%.2fms default=%s",
            client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
            profile_result.action, profile_result.score or 0,
            profile_result.profiles_executed or 0,
            profile_result.blocked_by and table.concat(profile_result.blocked_by, ",") or "none",
            profile_result.flags and table.concat(profile_result.flags, ",") or "none",
            profile_result.execution_time_ms or 0,
            using_default_profile and "yes" or "no"
        ))

        -- Set debug headers if enabled
        if expose_headers then
            ngx.header["X-Defense-Profiles-Executed"] = tostring(profile_result.profiles_executed or 0)
            ngx.header["X-Defense-Profiles-Score"] = tostring(profile_result.score or 0)
            ngx.header["X-Defense-Profiles-Action"] = profile_result.action
            ngx.header["X-Defense-Profiles-Default"] = using_default_profile and "true" or "false"
            if profile_result.blocked_by and #profile_result.blocked_by > 0 then
                ngx.header["X-Defense-Profiles-Blocked-By"] = table.concat(profile_result.blocked_by, ",")
            end
            if profile_result.flags and #profile_result.flags > 0 then
                ngx.header["X-Defense-Profiles-Flags"] = table.concat(profile_result.flags, ",")
            end
        end

        -- Stash the verdict for the log phase. Recording happens there, not in
        -- the branches below, because there are six of them -- block, captcha,
        -- tarpit, flag, monitor, allow -- and covering five is the failure this
        -- feature exists to avoid. The log phase sees exactly one outcome per
        -- request, and the real one.
        -- Returned on every response, not gated behind WAF_EXPOSE_HEADERS. It is
        -- the handle support needs to look a decision up, and it reveals nothing
        -- about the verdict -- unlike the score and flag headers, which is what
        -- that flag exists to keep in.
        ngx.header["X-WAF-Request-Id"] = request_id()

        ngx.ctx.waf_decision = {
            request_id   = request_id(),
            vhost_id     = summary.vhost_id,
            endpoint_id  = summary.endpoint_id,
            client_ip    = client_ip,
            host         = host,
            path         = path,
            method       = method,
            user_agent   = ngx.var.http_user_agent,
            mode         = summary.mode,
            score        = profile_result.score,
            flags        = profile_result.flags,
            blocked_by   = profile_result.blocked_by,
            block_reason = profile_result.block_reason,
            profile_action = profile_result.action,
            trace        = collect_trace(profile_result),
        }

        -- Handle profile result actions
        if profile_result.action == "block" then
            local should_block = vhost_resolver.should_block(context)

            if should_block then
                -- Set nginx variables for logging (internal, not exposed to client)
                local form_hash = ngx.ctx.form_hash or ""
                ngx.var.waf_spam_score = tostring(profile_result.score or 0)
                ngx.var.waf_spam_flags = profile_result.flags and table.concat(profile_result.flags, ",") or ""
                ngx.var.waf_form_hash = form_hash
                ngx.var.waf_blocked = "true"

                if expose_headers then
                    -- Also set response headers for debugging
                    ngx.header["X-WAF-Spam-Score"] = tostring(profile_result.score or 0)
                    ngx.header["X-WAF-Spam-Flags"] = profile_result.flags and table.concat(profile_result.flags, ",") or ""
                    ngx.header["X-WAF-Form-Hash"] = form_hash
                    ngx.header["X-WAF-Blocked"] = "true"
                    ngx.header["X-Block-Reason"] = "defense_profile"
                end

                ngx.log(ngx.WARN, string.format(
                    "BLOCKED_BY_PROFILE: ip=%s host=%s path=%s vhost=%s endpoint=%s blocked_by=%s score=%d flags=%s",
                    client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                    profile_result.blocked_by and table.concat(profile_result.blocked_by, ",") or "unknown",
                    profile_result.score or 0,
                    profile_result.flags and table.concat(profile_result.flags, ",") or "none"
                ))

                audit_log("request_blocked_by_profile", {
                    vhost_id = summary.vhost_id,
                    endpoint_id = summary.endpoint_id,
                    profiles_executed = profile_result.profiles_executed,
                    blocked_by = profile_result.blocked_by,
                    score = profile_result.score,
                    flags = profile_result.flags,
                })

                metrics.record_request(summary.vhost_id, summary.endpoint_id, "blocked", profile_result.score or 0)

                ngx.status = ngx.HTTP_FORBIDDEN
                ngx.header["Content-Type"] = "application/json"
                local error_response = { error = "Request blocked" }
                if expose_headers then
                    error_response.reason = "defense_profile"
                    error_response.blocked_by = profile_result.blocked_by
                end
                ngx.say(cjson.encode(error_response))
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            else
                -- Monitoring mode - log but don't block
                -- Set nginx variables for logging (internal, not exposed to client)
                local form_hash = ngx.ctx.form_hash or ""
                local fingerprint = ngx.ctx.fingerprint
                local fingerprint_profile = ngx.ctx.fingerprint_profile
                ngx.var.waf_spam_score = tostring(profile_result.score or 0)
                ngx.var.waf_spam_flags = profile_result.flags and table.concat(profile_result.flags, ",") or ""
                ngx.var.waf_form_hash = form_hash
                ngx.var.waf_blocked = "would_block"

                -- Set request headers for HAProxy (needed for rate limiting counters)
                ngx.req.set_header("X-WAF-Spam-Score", tostring(profile_result.score or 0))
                if profile_result.flags and #profile_result.flags > 0 then
                    ngx.req.set_header("X-WAF-Spam-Flags", table.concat(profile_result.flags, ","))
                end
                ngx.req.set_header("X-WAF-Client-IP", client_ip)
                if fingerprint then
                    ngx.req.set_header("X-WAF-Form-Fingerprint", fingerprint)
                end
                if fingerprint_profile then
                    ngx.req.set_header("X-WAF-Fingerprint-Profile", fingerprint_profile)
                end
                if form_hash and form_hash ~= "" then
                    ngx.req.set_header("X-WAF-Form-Hash", form_hash)
                end

                if expose_headers then
                    -- Also set response headers for debugging
                    -- Note: x-waf-fingerprint and x-waf-fingerprint-profile are set by HAProxy
                    ngx.header["X-WAF-Spam-Score"] = tostring(profile_result.score or 0)
                    ngx.header["X-WAF-Spam-Flags"] = profile_result.flags and table.concat(profile_result.flags, ",") or ""
                    ngx.header["X-WAF-Form-Hash"] = form_hash
                    ngx.header["X-WAF-Blocked"] = "would_block"
                    ngx.header["X-WAF-Would-Block"] = "true"
                    ngx.header["X-WAF-Block-Reason"] = "defense_profile"
                end
                ngx.log(ngx.WARN, string.format(
                    "MONITORING (profile would block): ip=%s host=%s path=%s vhost=%s endpoint=%s blocked_by=%s score=%d flags=%s",
                    client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                    profile_result.blocked_by and table.concat(profile_result.blocked_by, ",") or "unknown",
                    profile_result.score or 0,
                    profile_result.flags and table.concat(profile_result.flags, ",") or "none"
                ))
                metrics.record_request(summary.vhost_id, summary.endpoint_id, "monitored", profile_result.score or 0)
                record_shadow_decision(summary, client_ip, host, path, method, profile_result)
                -- Return to continue to proxy_pass - HAProxy will use the request headers we set
                return
            end

        elseif profile_result.action == "captcha" then
            -- Serve CAPTCHA challenge
            local captcha_config = captcha_handler.get_captcha_config(context)
            if captcha_config and captcha_config.enabled then
                if captcha_handler.has_valid_trust(context, client_ip) then
                    -- User has solved CAPTCHA recently, allow through
                    ngx.log(ngx.INFO, string.format(
                        "CAPTCHA_TRUSTED (profile): ip=%s vhost=%s endpoint=%s",
                        client_ip, summary.vhost_id, summary.endpoint_id or "global"
                    ))
                    metrics.record_request(summary.vhost_id, summary.endpoint_id, "captcha_trusted", profile_result.score or 0)
                    -- Continue processing
                else
                    ngx.log(ngx.WARN, string.format(
                        "CAPTCHA_CHALLENGE (profile): ip=%s vhost=%s endpoint=%s score=%d",
                        client_ip, summary.vhost_id, summary.endpoint_id or "global",
                        profile_result.score or 0
                    ))
                    metrics.record_request(summary.vhost_id, summary.endpoint_id, "captcha_challenged", profile_result.score or 0)
                    -- Read by log_decision to record action "challenged".
                    -- Without it a challenge is indistinguishable from a plain
                    -- allow in the decision log.
                    ngx.ctx.waf_captcha_challenged = true
                    return captcha_handler.serve_challenge(context, nil, "defense_profile", client_ip)
                end
            end

        elseif profile_result.action == "tarpit" then
            -- Delay the response (tarpit)
            local delay = 5 -- default 5 seconds
            if profile_result.action_config and profile_result.action_config.delay_seconds then
                delay = profile_result.action_config.delay_seconds
            end

            ngx.log(ngx.WARN, string.format(
                "TARPIT (profile): ip=%s vhost=%s endpoint=%s delay=%ds score=%d",
                client_ip, summary.vhost_id, summary.endpoint_id or "global",
                delay, profile_result.score or 0
            ))

            ngx.sleep(delay)

            -- After tarpit, check if we should block
            if profile_result.action_config and profile_result.action_config.then_action == "block" then
                metrics.record_request(summary.vhost_id, summary.endpoint_id, "blocked", profile_result.score or 0)
                ngx.status = ngx.HTTP_FORBIDDEN
                ngx.header["Content-Type"] = "application/json"
                ngx.say(cjson.encode({ error = "Request blocked" }))
                return ngx.exit(ngx.HTTP_FORBIDDEN)
            end

        elseif profile_result.action == "flag" then
            -- Flag action: add to spam score but allow through
            -- Set headers for downstream processing
            ngx.req.set_header("X-WAF-Spam-Score", tostring(profile_result.score or 0))
            ngx.req.set_header("X-WAF-Spam-Flags", profile_result.flags and table.concat(profile_result.flags, ",") or "")
            ngx.log(ngx.INFO, string.format(
                "FLAGGED (profile): ip=%s vhost=%s endpoint=%s score=%d flags=%s",
                client_ip, summary.vhost_id, summary.endpoint_id or "global",
                profile_result.score or 0,
                profile_result.flags and table.concat(profile_result.flags, ",") or "none"
            ))

        elseif profile_result.action == "monitor" then
            -- Monitor only: log but don't affect processing
            ngx.log(ngx.INFO, string.format(
                "MONITOR (profile): ip=%s vhost=%s endpoint=%s score=%d flags=%s",
                client_ip, summary.vhost_id, summary.endpoint_id or "global",
                profile_result.score or 0,
                profile_result.flags and table.concat(profile_result.flags, ",") or "none"
            ))
        end

        -- Check if this is a "would block" scenario (action=block but mode=monitoring)
        local is_monitoring_would_block = profile_result.action == "block" and not vhost_resolver.should_block(context)

        -- If we get here with allow/flag/monitor OR monitoring-mode block, continue processing
        -- but skip the legacy inline defense checks since profiles handled it
        if profile_result.action == "allow" or profile_result.action == "flag" or
           profile_result.action == "monitor" or is_monitoring_would_block then

            -- Set would-block header for monitoring mode
            if is_monitoring_would_block then
                if expose_headers then
                    ngx.header["X-WAF-Would-Block"] = "true"
                    ngx.header["X-WAF-Block-Reason"] = "defense_profile"
                end
                ngx.log(ngx.WARN, string.format(
                    "WOULD_BLOCK (profile): ip=%s host=%s path=%s vhost=%s endpoint=%s blocked_by=%s score=%d",
                    client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                    profile_result.blocked_by and table.concat(profile_result.blocked_by, ",") or "unknown",
                    profile_result.score or 0
                ))
                metrics.record_request(summary.vhost_id, summary.endpoint_id, "monitored", profile_result.score or 0)
                record_shadow_decision(summary, client_ip, host, path, method, profile_result)
            else
                metrics.record_request(summary.vhost_id, summary.endpoint_id, "allowed", profile_result.score or 0)
            end

            -- Set request headers for HAProxy with profile results
            ngx.req.set_header("X-WAF-Spam-Score", tostring(profile_result.score or 0))
            if profile_result.flags and #profile_result.flags > 0 then
                ngx.req.set_header("X-WAF-Spam-Flags", table.concat(profile_result.flags, ","))
            end
            ngx.req.set_header("X-WAF-Client-IP", client_ip)

            -- Set fingerprint headers from ngx.ctx (populated by defense mechanisms)
            -- HAProxy handles counting based on these values
            local fingerprint = ngx.ctx.fingerprint
            local fingerprint_profile = ngx.ctx.fingerprint_profile
            if fingerprint then
                ngx.req.set_header("X-WAF-Form-Fingerprint", fingerprint)
                if expose_headers then
                    ngx.header["x-waf-fingerprint"] = fingerprint
                end
            end
            if fingerprint_profile then
                ngx.req.set_header("X-WAF-Fingerprint-Profile", fingerprint_profile)
                if expose_headers then
                    ngx.header["x-waf-fingerprint-profile"] = fingerprint_profile
                end
            end

            -- Set content hash header from ngx.ctx (populated by defense mechanisms)
            -- HAProxy handles counting based on this value
            local form_hash = ngx.ctx.form_hash
            if form_hash then
                ngx.req.set_header("X-WAF-Form-Hash", form_hash)
                if expose_headers then
                    ngx.header["x-waf-hash"] = form_hash
                end
            end

            -- Set geo info headers if available
            local geo_info = ngx.ctx.geo_info
            if geo_info and expose_headers then
                ngx.header["X-GeoIP-Country"] = geo_info.country_code or "unknown"
                ngx.header["X-GeoIP-ASN"] = tostring(geo_info.asn or "unknown")
            end

            -- Set nginx variables for logging (internal, not exposed to client)
            ngx.var.waf_spam_score = tostring(profile_result.score or 0)
            ngx.var.waf_spam_flags = profile_result.flags and table.concat(profile_result.flags, ",") or ""
            ngx.var.waf_form_hash = form_hash or ""
            ngx.var.waf_blocked = is_monitoring_would_block and "would_block" or "false"

            if expose_headers then
                -- Also set response headers for debugging
                ngx.header["X-WAF-Spam-Score"] = tostring(profile_result.score or 0)
                ngx.header["X-WAF-Spam-Flags"] = profile_result.flags and table.concat(profile_result.flags, ",") or ""
                ngx.header["X-WAF-Form-Hash"] = form_hash or ""
                ngx.header["X-WAF-Blocked"] = is_monitoring_would_block and "would_block" or "false"
            end

            ngx.log(ngx.INFO, string.format(
                "PROCESSED (profile): ip=%s host=%s path=%s vhost=%s endpoint=%s action=%s score=%d fp=%s hash=%s",
                client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
                is_monitoring_would_block and "would_block" or profile_result.action,
                profile_result.score or 0,
                fingerprint or "none",
                form_hash or "none"
            ))

            -- Profiles handled everything
            return
        end
    end

    -- This should never be reached - profile execution handles all cases
    ngx.log(ngx.ERR, "UNEXPECTED: Defense profile execution did not return a result")
    metrics.record_request(summary.vhost_id, summary.endpoint_id, "error", 0)
end

-- LEGACY INLINE DEFENSE CODE REMOVED
-- All defense processing is now handled by the profile system
-- The "legacy" profile provides backwards-compatible behavior

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
