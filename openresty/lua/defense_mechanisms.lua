-- defense_mechanisms.lua
-- Registers all defense mechanisms with the profile executor
-- Each mechanism wraps an existing module and provides standardized output

local _M = {}

local executor = require "defense_profile_executor"

-- Lazy-load modules to avoid circular dependencies
local function get_geoip()
    return require "geoip"
end

local function get_ip_reputation()
    return require "ip_reputation"
end

local function get_ip_utils()
    return require "ip_utils"
end

local function get_behavioral_tracker()
    return require "behavioral_tracker"
end

local function get_fingerprint_profiles()
    return require "fingerprint_profiles"
end

-- Helper to safely get form data
local function get_form_data(request_context)
    if request_context.form_data then
        return request_context.form_data
    end
    -- Try to read from ngx if available
    if ngx and ngx.req then
        ngx.req.read_body()
        local args, err = ngx.req.get_post_args()
        if args then
            request_context.form_data = args
            return args
        end
    end
    return {}
end

-- Helper to get endpoint config
local function get_config(request_context)
    return request_context.endpoint_config or request_context.vhost_config or {}
end

-- ============================================================================
-- IP ALLOWLIST
-- Check if client IP is in the allowlist
-- ============================================================================
executor.register_defense("ip_allowlist", function(request_context, node_config)
    local ip_utils = get_ip_utils()
    local cjson = require "cjson.safe"

    -- Get allowlist from shared dict (same as waf_handler.lua)
    local allowlist_dict = ngx.shared.ip_whitelist
    local cidr_cache = ngx.shared.ip_whitelist_cidr
    local cidr_list = nil

    -- Load CIDR list from cache if available
    if cidr_cache then
        local cidr_json = cidr_cache:get("cidrs")
        if cidr_json then
            cidr_list = cjson.decode(cidr_json)
        end
    end

    if ip_utils.is_ip_allowlisted(request_context.client_ip, allowlist_dict, cidr_list) then
        return executor.result_allowed("ip_in_allowlist", {"ip_allowlisted"}, {
            ip = request_context.client_ip
        })
    end

    -- Not in allowlist, continue checking
    return executor.result_score(0, {}, {checked = true})
end)

-- ============================================================================
-- GEOIP
-- Geographic and ASN-based filtering
-- ============================================================================
executor.register_defense("geoip", function(request_context, node_config)
    local geoip = get_geoip()

    if not geoip.is_available() then
        return executor.result_score(0, {}, {skipped = true, reason = "geoip_not_available"})
    end

    local config = get_config(request_context)
    local result = geoip.check_ip(request_context.client_ip, config)

    -- Store geo info in context for later use
    if ngx and ngx.ctx then
        ngx.ctx.geo_info = result.geo
    end

    if result.blocked then
        return executor.result_blocked(result.reason, result.flags or {}, {
            geo = result.geo
        })
    end

    return executor.result_score(result.score or 0, result.flags or {}, {
        geo = result.geo
    })
end)

-- ============================================================================
-- IP REPUTATION
-- Check IP against reputation databases (AbuseIPDB, local blocklist, webhooks)
-- ============================================================================
executor.register_defense("ip_reputation", function(request_context, node_config)
    local ip_reputation = get_ip_reputation()

    if not ip_reputation.is_available() then
        return executor.result_score(0, {}, {skipped = true, reason = "ip_reputation_not_available"})
    end

    local config = get_config(request_context)
    local result = ip_reputation.check_ip(request_context.client_ip, config)

    -- Store reputation info for audit logging
    if ngx and ngx.ctx then
        ngx.ctx.reputation_info = result.details
    end

    if result.blocked then
        return executor.result_blocked(result.reason, result.flags or {}, {
            details = result.details
        })
    end

    return executor.result_score(result.score or 0, result.flags or {}, {
        details = result.details
    })
end)

-- ============================================================================
-- TIMING TOKEN
-- Validate form fill timing (detect instant bot submissions)
-- ============================================================================
executor.register_defense("timing_token", function(request_context, node_config)
    local config = get_config(request_context)
    local form_data = get_form_data(request_context)

    -- Check if timing token feature is enabled
    if not config.timing_token or not config.timing_token.enabled then
        return executor.result_score(0, {}, {skipped = true, reason = "timing_token_disabled"})
    end

    -- Get timing token field name
    local field_name = config.timing_token.field_name or "_t"
    local token = form_data[field_name]

    if not token then
        -- No token present - score penalty
        local score = node_config.missing_score or 20
        return executor.result_score(score, {"timing_token_missing"}, {})
    end

    -- Validate the timing token
    local timing_handler = require "timing_handler"
    local result = timing_handler.validate_token(token, config.timing_token)

    if ngx and ngx.ctx then
        ngx.ctx.timing_result = result
    end

    return executor.result_score(result.score or 0, result.flags or {}, {
        elapsed = result.elapsed,
        valid = result.valid
    })
end)

-- ============================================================================
-- BEHAVIORAL
-- Detect anomalies in user behavior patterns
-- ============================================================================
executor.register_defense("behavioral", function(request_context, node_config)
    local behavioral = get_behavioral_tracker()
    local config = get_config(request_context)

    -- Check if behavioral tracking is enabled
    if not config.behavioral or not config.behavioral.enabled then
        return executor.result_score(0, {}, {skipped = true, reason = "behavioral_disabled"})
    end

    local form_data = get_form_data(request_context)
    local result = behavioral.analyze_submission(request_context.client_ip, form_data, config)

    if ngx and ngx.ctx then
        ngx.ctx.behavioral_context = result.context
    end

    return executor.result_score(result.score or 0, result.flags or {}, {
        velocity = result.velocity,
        pattern_match = result.pattern_match
    })
end)

-- ============================================================================
-- HONEYPOT
-- Detect bots filling hidden honeypot fields
-- ============================================================================
executor.register_defense("honeypot", function(request_context, node_config)
    local config = get_config(request_context)
    local form_data = get_form_data(request_context)

    -- Check if honeypot is enabled
    if not config.honeypot or not config.honeypot.enabled then
        return executor.result_score(0, {}, {skipped = true, reason = "honeypot_disabled"})
    end

    -- Get honeypot field names
    local field_names = config.honeypot.field_names or {"website", "url", "homepage", "fax"}
    local action = node_config.action or config.honeypot.action or "block"
    local score = node_config.score or config.honeypot.score or 50

    -- Check if any honeypot field is filled
    for _, field_name in ipairs(field_names) do
        local value = form_data[field_name]
        if value and value ~= "" then
            -- Honeypot triggered
            if action == "block" then
                return executor.result_blocked("honeypot_triggered", {"honeypot:" .. field_name}, {
                    field = field_name
                })
            else
                return executor.result_score(score, {"honeypot:" .. field_name}, {
                    field = field_name
                })
            end
        end
    end

    return executor.result_score(0, {}, {checked = true})
end)

-- ============================================================================
-- KEYWORD FILTER
-- Scan content for blocked/flagged keywords
-- Full legacy implementation with ignore_fields, exclusions, and global inheritance
-- ============================================================================
executor.register_defense("keyword_filter", function(request_context, node_config)
    local form_data = get_form_data(request_context)
    local keyword_filter = require "keyword_filter"
    local vhost_resolver = require "vhost_resolver"
    local context = request_context.context

    -- Get ignore fields to exclude from keyword scanning (e.g., CSRF tokens)
    local ignore_fields = vhost_resolver.get_ignore_fields(context)

    -- Scan form data for keywords (passing ignore_fields as exclude list)
    local result = keyword_filter.scan(form_data, ignore_fields)

    local score = result.score or 0
    local flags = {}
    local blocked_keywords = {}
    local flagged_keywords = {}

    -- Check for signature patterns (from attack signatures)
    local sig_patterns = node_config and node_config.signature_patterns
    if sig_patterns then
        -- Check blocked keywords from signatures
        if sig_patterns.blocked_keywords then
            for _, kw in ipairs(sig_patterns.blocked_keywords) do
                local kw_lower = kw:lower()
                for field_name, field_value in pairs(form_data or {}) do
                    if type(field_value) == "string" then
                        local value_lower = field_value:lower()
                        if value_lower:find(kw_lower, 1, true) then
                            ngx.log(ngx.INFO, "SIGNATURE_BLOCK: keyword matched: ", kw, " in field: ", field_name)
                            table.insert(flags, "sig:blocked_kw:" .. kw)
                            return executor.result_blocked("signature_keyword_blocked", flags, {
                                matched_keyword = kw,
                                field = field_name
                            })
                        end
                    end
                end
            end
        end

        -- Check flagged keywords from signatures
        if sig_patterns.flagged_keywords then
            for _, entry in ipairs(sig_patterns.flagged_keywords) do
                local kw = entry.keyword or entry
                local entry_score = entry.score or 15
                local kw_lower = kw:lower()
                for field_name, field_value in pairs(form_data or {}) do
                    if type(field_value) == "string" then
                        local value_lower = field_value:lower()
                        if value_lower:find(kw_lower, 1, true) then
                            score = score + entry_score
                            table.insert(flags, "sig:flagged_kw:" .. kw)
                            ngx.log(ngx.DEBUG, "SIGNATURE_FLAG: keyword matched: ", kw, " score=", entry_score)
                        end
                    end
                end
            end
        end

        -- Check blocked patterns (regex) from signatures
        if sig_patterns.blocked_patterns then
            for _, pattern in ipairs(sig_patterns.blocked_patterns) do
                for field_name, field_value in pairs(form_data or {}) do
                    if type(field_value) == "string" then
                        local ok, matched = pcall(function()
                            return field_value:match(pattern)
                        end)
                        if ok and matched then
                            ngx.log(ngx.INFO, "SIGNATURE_BLOCK: pattern matched: ", pattern, " in field: ", field_name)
                            table.insert(flags, "sig:blocked_pattern")
                            return executor.result_blocked("signature_pattern_blocked", flags, {
                                matched_pattern = pattern,
                                field = field_name
                            })
                        end
                    end
                end
            end
        end

        -- Check flagged patterns (regex) from signatures
        if sig_patterns.flagged_patterns then
            for _, entry in ipairs(sig_patterns.flagged_patterns) do
                local pattern = entry.pattern or entry
                local entry_score = entry.score or 15
                for field_name, field_value in pairs(form_data or {}) do
                    if type(field_value) == "string" then
                        local ok, matched = pcall(function()
                            return field_value:match(pattern)
                        end)
                        if ok and matched then
                            score = score + entry_score
                            table.insert(flags, "sig:flagged_pattern")
                        end
                    end
                end
            end
        end
    end

    -- Apply context-specific keyword exclusions for blocked keywords
    if result.blocked_keywords and #result.blocked_keywords > 0 then
        for _, kw in ipairs(result.blocked_keywords) do
            if not vhost_resolver.is_keyword_excluded(context, kw, "blocked") then
                table.insert(blocked_keywords, kw)
            end
        end
    end

    -- Apply context-specific keyword exclusions for flagged keywords
    if result.flagged_keywords and #result.flagged_keywords > 0 then
        for _, kw in ipairs(result.flagged_keywords) do
            if not vhost_resolver.is_keyword_excluded(context, kw, "flagged") then
                table.insert(flagged_keywords, kw)
                table.insert(flags, "kw:" .. kw)
            end
        end
    end

    -- Check if should block based on global keywords inheritance
    if #blocked_keywords > 0 then
        if vhost_resolver.should_inherit_global_keywords(context) then
            for _, kw in ipairs(blocked_keywords) do
                table.insert(flags, "kw:" .. kw)
            end
            return executor.result_blocked("keyword_blocked", flags, {
                blocked_keywords = blocked_keywords,
                flagged_keywords = flagged_keywords
            })
        end
    end

    return executor.result_score(score, flags, {
        blocked_keywords = blocked_keywords,
        flagged_keywords = flagged_keywords
    })
end)

-- ============================================================================
-- CONTENT HASH
-- Generates content hash and passes to HAProxy via headers (HAProxy does counting)
-- Respects legacy configuration: fields.hash.enabled, fields.hash.fields, ignore_fields
-- ============================================================================
executor.register_defense("content_hash", function(request_context, node_config)
    local form_data = get_form_data(request_context)
    local content_hasher = require "content_hasher"
    local vhost_resolver = require "vhost_resolver"

    local context = request_context.context
    local hash

    -- Check for field-specific hash configuration
    local hash_config = vhost_resolver.get_hash_config(context)

    if hash_config.enabled and hash_config.fields and #hash_config.fields > 0 then
        -- Hash ONLY the specified fields (prevents bots from changing hash by adding fields)
        hash = content_hasher.hash_fields(form_data, hash_config.fields)
    else
        -- Hash all fields, excluding ignored fields (CSRF tokens, captcha, etc.)
        local ignore_fields = vhost_resolver.get_ignore_fields(context)
        local exclude_set = {}
        for _, f in ipairs(ignore_fields) do
            exclude_set[f:lower()] = true
        end
        hash = content_hasher.hash_form(form_data, { exclude_fields = exclude_set })
    end

    -- Store full 64-character hash in context for header generation
    -- HAProxy will handle counting and blocking based on this header
    if hash and ngx and ngx.ctx then
        ngx.ctx.form_hash = hash
    end

    return executor.result_score(0, {}, {hash = hash})
end)

-- ============================================================================
-- EXPECTED FIELDS
-- Validate form has only expected fields
-- Full legacy implementation with combined field set and all 4 actions
-- ============================================================================
executor.register_defense("expected_fields", function(request_context, node_config)
    local form_data = get_form_data(request_context)
    local vhost_resolver = require "vhost_resolver"
    local form_parser = require "form_parser"
    local context = request_context.context

    -- Get field configurations from vhost_resolver
    local expected_fields = vhost_resolver.get_expected_fields(context)
    local required_fields = vhost_resolver.get_required_fields(context)
    local ignore_fields = vhost_resolver.get_ignore_fields(context)
    local honeypot_fields = vhost_resolver.get_honeypot_fields(context) or {}

    -- Check if there are any field restrictions
    local has_restrictions = (#expected_fields > 0) or (#required_fields > 0)
    if not has_restrictions then
        return executor.result_score(0, {}, {skipped = true, reason = "no_field_restrictions"})
    end

    -- Build combined allowed set (required + expected + ignored + honeypot)
    local allowed_set = {}
    for _, f in ipairs(required_fields) do
        allowed_set[f:lower()] = true
    end
    for _, f in ipairs(expected_fields) do
        allowed_set[f:lower()] = true
    end
    for _, f in ipairs(ignore_fields) do
        allowed_set[f:lower()] = true
    end
    for _, f in ipairs(honeypot_fields) do
        allowed_set[f:lower()] = true
    end

    -- Find unexpected fields
    local unexpected = {}
    for field_name, _ in pairs(form_data) do
        if type(field_name) == "string" then
            if not allowed_set[field_name:lower()] then
                table.insert(unexpected, field_name)
            end
        end
    end

    if #unexpected > 0 then
        -- Get action for unexpected fields from config
        local action = vhost_resolver.get_unexpected_fields_action(context)

        if action == "block" then
            return executor.result_blocked("unexpected_fields", {"unexpected_field"}, {
                unexpected = unexpected
            })
        elseif action == "filter" then
            -- Remove unexpected fields and reconstruct body
            for _, f in ipairs(unexpected) do
                form_data[f] = nil
            end
            local new_body = form_parser.reconstruct_body(form_data, request_context.content_type)
            if new_body then
                ngx.req.set_body_data(new_body)
                ngx.req.set_header("X-WAF-Filtered", "true")
                ngx.req.set_header("X-WAF-Filtered-Fields", table.concat(unexpected, ","))
            end
            return executor.result_score(0, {"filtered:" .. #unexpected}, {
                unexpected = unexpected,
                action = "filtered"
            })
        elseif action == "ignore" then
            -- Do nothing - just log
            return executor.result_score(0, {}, {
                unexpected = unexpected,
                action = "ignored"
            })
        else
            -- Default: "flag" - add score
            local score_per_field = node_config.score or 5
            return executor.result_score(score_per_field * #unexpected, {"unexpected_field"}, {
                unexpected = unexpected
            })
        end
    end

    return executor.result_score(0, {}, {checked = true})
end)

-- ============================================================================
-- PATTERN SCAN
-- Regex-based content scanning for spam patterns
-- ============================================================================
executor.register_defense("pattern_scan", function(request_context, node_config)
    local config = get_config(request_context)
    local form_data = get_form_data(request_context)

    -- Check if pattern scanning is enabled
    if not config.patterns or not config.patterns.enabled then
        return executor.result_score(0, {}, {skipped = true, reason = "patterns_disabled"})
    end

    local pattern_scanner = require "pattern_scanner"
    local result = pattern_scanner.scan(form_data, config.patterns)

    return executor.result_score(result.score or 0, result.flags or {}, {
        matches = result.matches
    })
end)

-- ============================================================================
-- DISPOSABLE EMAIL
-- Detect disposable/temporary email addresses
-- ============================================================================
executor.register_defense("disposable_email", function(request_context, node_config)
    local config = get_config(request_context)
    local form_data = get_form_data(request_context)

    -- Check if disposable email detection is enabled
    if not config.disposable_email or not config.disposable_email.enabled then
        return executor.result_score(0, {}, {skipped = true, reason = "disposable_email_disabled"})
    end

    local action = node_config.action or config.disposable_email.action or "flag"
    local score = node_config.score or config.disposable_email.score or 30

    -- Find email fields
    local email_fields = config.disposable_email.fields or {"email", "e-mail", "mail"}
    local disposable_checker = require "disposable_email"

    for _, field_name in ipairs(email_fields) do
        local email = form_data[field_name]
        if email and email ~= "" then
            local is_disposable = disposable_checker.is_disposable(email)
            if is_disposable then
                if action == "block" then
                    return executor.result_blocked("disposable_email", {"disposable_email"}, {
                        email = email,
                        field = field_name
                    })
                else
                    return executor.result_score(score, {"disposable_email"}, {
                        email = email,
                        field = field_name
                    })
                end
            end
        end
    end

    return executor.result_score(0, {}, {checked = true})
end)

-- ============================================================================
-- FIELD ANOMALIES
-- Detect bot-like field filling patterns
-- Full legacy implementation with all 5 anomaly checks
-- ============================================================================
executor.register_defense("field_anomalies", function(request_context, node_config)
    local form_data = get_form_data(request_context)
    local vhost_resolver = require "vhost_resolver"
    local context = request_context.context

    local score = 0
    local flags = {}

    if not form_data or type(form_data) ~= "table" then
        return executor.result_score(0, {}, {skipped = true})
    end

    -- Build ignore set from configurable ignore_fields
    local ignore_fields = vhost_resolver.get_ignore_fields(context)
    local ignore_set = {}
    for _, f in ipairs(ignore_fields) do
        ignore_set[f] = true
        ignore_set[f:lower()] = true
    end

    -- Gather field statistics
    local text_fields = {}
    local field_lengths = {}
    local total_caps_fields = 0

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
            score = score + 15
            table.insert(flags, "same_length:" .. first_len)
        end
    end

    -- Anomaly 2: Check for sequential/incremental patterns
    local sequential_count = 0
    for _, field in ipairs(text_fields) do
        local val = field.value

        -- Check for repeated characters (aaa, bbb, 111, etc.)
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
        score = score + (sequential_count * 5)
        table.insert(flags, "sequential:" .. sequential_count)
    end

    -- Anomaly 3: Multiple fields all caps (shouting/bot pattern)
    if total_caps_fields >= 2 then
        score = score + (total_caps_fields * 5)
        table.insert(flags, "all_caps:" .. total_caps_fields)
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
        score = score + (test_pattern_count * 8)
        table.insert(flags, "test_data:" .. test_pattern_count)
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
                score = score + 10
                table.insert(flags, "no_spaces:" .. field.name)
            end
        end
    end

    return executor.result_score(score, flags, {})
end)

-- ============================================================================
-- FINGERPRINT
-- Client fingerprinting and bot detection
-- Generates fingerprint and passes to HAProxy via headers (HAProxy does counting)
-- Also checks user agent patterns from attack signatures
-- ============================================================================
executor.register_defense("fingerprint", function(request_context, node_config)
    local fingerprint_profiles = get_fingerprint_profiles()
    local config = get_config(request_context)
    local form_data = get_form_data(request_context)

    -- Build ngx_vars for fingerprinting
    local ngx_vars = request_context.ngx_vars or ngx.var

    -- Check for signature patterns first (from attack signatures)
    local sig_patterns = node_config and node_config.signature_patterns
    if sig_patterns then
        local user_agent = request_context.user_agent or ""
        local score = 0
        local flags = {}

        -- Check blocked user agent patterns (immediate block)
        if sig_patterns.blocked_user_agents then
            for _, pattern in ipairs(sig_patterns.blocked_user_agents) do
                local ok, matched = pcall(function()
                    return user_agent:match(pattern)
                end)
                if ok and matched then
                    ngx.log(ngx.INFO, "SIGNATURE_BLOCK: user_agent matched blocked pattern: ", pattern)
                    return executor.result_blocked("signature_ua_blocked", {"sig:blocked_ua:" .. pattern}, {
                        matched_pattern = pattern,
                        user_agent = user_agent
                    })
                end
            end
        end

        -- Check flagged user agent patterns (add score)
        if sig_patterns.flagged_user_agents then
            for _, entry in ipairs(sig_patterns.flagged_user_agents) do
                local pattern = entry.pattern or entry
                local entry_score = entry.score or 20
                local ok, matched = pcall(function()
                    return user_agent:match(pattern)
                end)
                if ok and matched then
                    score = score + entry_score
                    table.insert(flags, "sig:flagged_ua:" .. pattern)
                    ngx.log(ngx.DEBUG, "SIGNATURE_FLAG: user_agent matched flagged pattern: ", pattern, " score=", entry_score)
                end
            end
        end

        -- If signature patterns added score, combine with fingerprint result
        if score > 0 then
            -- Still run fingerprint profiles for additional checks
            local fp_config = config.fingerprint or {
                enabled = true,
                profiles = nil,
                no_match_action = "use_default",
                no_match_score = 15
            }
            local result = fingerprint_profiles.process_request(form_data, ngx_vars, fp_config)

            if ngx and ngx.ctx then
                ngx.ctx.fingerprint = result.fingerprint
                ngx.ctx.fingerprint_profile = result.profile_id
            end

            -- Combine scores
            local total_score = score + (result.score or 0)
            for _, flag in ipairs(result.flags or {}) do
                table.insert(flags, flag)
            end

            if result.blocked then
                return executor.result_blocked("fingerprint_blocked", flags, {
                    profile = result.profile_id,
                    fingerprint = result.fingerprint,
                    signature_score = score
                })
            end

            return executor.result_score(total_score, flags, {
                profile = result.profile_id,
                fingerprint = result.fingerprint,
                matched_profiles = result.matched_profile_ids,
                signature_score = score
            })
        end
    end

    -- Get fingerprint config from endpoint/vhost config
    local fp_config = config.fingerprint or {
        enabled = true,
        profiles = nil,
        no_match_action = "use_default",
        no_match_score = 15
    }

    -- Process fingerprint request
    local result = fingerprint_profiles.process_request(form_data, ngx_vars, fp_config)

    -- Store fingerprint in context for header generation
    -- HAProxy will handle counting based on these headers
    if ngx and ngx.ctx then
        ngx.ctx.fingerprint = result.fingerprint
        ngx.ctx.fingerprint_profile = result.profile_id
    end

    if result.blocked then
        return executor.result_blocked("fingerprint_blocked", result.flags or {}, {
            profile = result.profile_id,
            fingerprint = result.fingerprint
        })
    end

    return executor.result_score(result.score or 0, result.flags or {}, {
        profile = result.profile_id,
        fingerprint = result.fingerprint,
        matched_profiles = result.matched_profile_ids
    })
end)

-- ============================================================================
-- HEADER CONSISTENCY
-- Detect inconsistent browser headers (common in bots)
-- ============================================================================
executor.register_defense("header_consistency", function(request_context, node_config)
    local score = 0
    local flags = {}

    local user_agent = request_context.user_agent or ""
    local accept_language = request_context.accept_language or ""
    local accept_encoding = request_context.accept_encoding or ""

    -- Check for missing headers that browsers always send
    if accept_language == "" then
        score = score + 5
        table.insert(flags, "missing_accept_language")
    end

    if accept_encoding == "" then
        score = score + 3
        table.insert(flags, "missing_accept_encoding")
    end

    -- Check for inconsistent claims
    -- Chrome user agent but missing Chrome-specific headers
    if user_agent:match("Chrome") then
        -- Chrome should have certain behaviors
        if not accept_encoding:match("gzip") then
            score = score + 5
            table.insert(flags, "chrome_no_gzip")
        end
    end

    -- Firefox user agent checks
    if user_agent:match("Firefox") then
        if not accept_encoding:match("gzip") then
            score = score + 5
            table.insert(flags, "firefox_no_gzip")
        end
    end

    -- Empty user agent is highly suspicious
    if user_agent == "" then
        score = score + 15
        table.insert(flags, "missing_user_agent")
    end

    return executor.result_score(score, flags, {})
end)

-- ============================================================================
-- RATE LIMITER
-- Rate limiting based on various keys (IP, fingerprint, etc.)
-- ============================================================================
executor.register_defense("rate_limiter", function(request_context, node_config)
    local config = get_config(request_context)

    -- Get rate limit settings
    local window = node_config.window_seconds or config.rate_limit_window or 60
    local max_requests = node_config.max_requests or config.rate_limit_max or 30
    local key_type = node_config.key_type or "ip"

    -- Build rate limit key
    local key
    if key_type == "ip" then
        key = "ratelimit:ip:" .. request_context.client_ip
    elseif key_type == "fingerprint" then
        key = "ratelimit:fp:" .. (request_context.fingerprint or request_context.client_ip)
    else
        key = "ratelimit:ip:" .. request_context.client_ip
    end

    -- Check rate limit using shared dict
    local rate_limit_dict = ngx.shared.rate_limit
    if not rate_limit_dict then
        return executor.result_score(0, {}, {skipped = true, reason = "rate_limit_dict_not_available"})
    end

    local count, err = rate_limit_dict:incr(key, 1, 0, window)
    if not count then
        ngx.log(ngx.WARN, "Rate limit incr failed: ", err)
        return executor.result_score(0, {}, {error = err})
    end

    if count > max_requests then
        local action = node_config.action or "block"
        if action == "block" then
            return executor.result_blocked("rate_limit_exceeded", {"rate_limited"}, {
                count = count,
                max = max_requests,
                window = window
            })
        else
            local score = node_config.score or 50
            return executor.result_score(score, {"rate_limited"}, {
                count = count,
                max = max_requests
            })
        end
    end

    return executor.result_score(0, {}, {
        count = count,
        max = max_requests,
        remaining = max_requests - count
    })
end)

-- ============================================================================
-- OBSERVATION: FIELD LEARNER
-- Learns field names and patterns for automatic field discovery
-- Does not affect scoring/blocking - purely observation
-- ============================================================================
executor.register_observation("field_learner", function(request_context, node_config)
    local field_learner = require "field_learner"
    local form_data = get_form_data(request_context)

    -- Record fields for learning
    field_learner.record_fields(
        form_data,
        request_context.endpoint_id or "unknown",
        request_context.vhost_id or "default"
    )

    return {learned = true}
end)

-- Initialize all defenses
function _M.init()
    ngx.log(ngx.INFO, "Defense mechanisms registered: ", table.concat(executor.list_defenses(), ", "))
    ngx.log(ngx.INFO, "Observation mechanisms registered: ", table.concat(executor.list_observations(), ", "))
end

return _M
