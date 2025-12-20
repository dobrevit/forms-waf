-- config_resolver.lua
-- Resolves effective configuration by merging endpoint config with global defaults
-- Implements inheritance model: Global -> Group -> Endpoint -> Method

local _M = {}

local cjson = require "cjson.safe"
local waf_config = require "waf_config"

-- Default endpoint configuration (used when no endpoint config exists)
-- Canonical field names:
--   fields.ignore (not ignore_fields)
--   fields.expected (not expected_fields)
--   fields.honeypot (array of field names)
--   fields.hash (object with enabled/fields)
local DEFAULT_ENDPOINT_CONFIG = {
    enabled = true,
    mode = "blocking",
    thresholds = nil,  -- Will use global thresholds
    keywords = {
        inherit_global = true,
        additional_blocked = {},
        additional_flagged = {},
        excluded_blocked = {},
        excluded_flagged = {}
    },
    patterns = {
        inherit_global = true,
        disabled = {},
        custom = {}
    },
    rate_limiting = {
        enabled = true
    },
    fields = {
        required = {},
        max_length = {},
        ignore = {"_csrf", "_token", "csrf_token", "authenticity_token", "captcha", "g-recaptcha-response", "h-captcha-response"},
        expected = {},
        honeypot = {},
        hash = {
            enabled = false,
            fields = {}
        }
    },
    actions = {
        on_block = "reject",
        on_flag = "tag",
        log_level = "info"
    }
}

-- Deep merge two tables (target is modified in place)
local function deep_merge(target, source)
    if type(source) ~= "table" then
        return source
    end

    if type(target) ~= "table" then
        target = {}
    end

    for key, value in pairs(source) do
        if type(value) == "table" and type(target[key]) == "table" then
            deep_merge(target[key], value)
        else
            target[key] = value
        end
    end

    return target
end

-- Shallow copy a table
local function shallow_copy(t)
    if type(t) ~= "table" then
        return t
    end
    local copy = {}
    for k, v in pairs(t) do
        copy[k] = v
    end
    return copy
end

-- Deep copy a table
local function deep_copy(t)
    if type(t) ~= "table" then
        return t
    end
    local copy = {}
    for k, v in pairs(t) do
        if type(v) == "table" then
            copy[k] = deep_copy(v)
        else
            copy[k] = v
        end
    end
    return copy
end

-- Merge thresholds (endpoint overrides global)
local function merge_thresholds(global_thresholds, endpoint_thresholds)
    local result = shallow_copy(global_thresholds)

    if endpoint_thresholds then
        for key, value in pairs(endpoint_thresholds) do
            if value ~= nil then
                result[key] = value
            end
        end
    end

    return result
end

-- Merge keyword configuration
local function merge_keywords(global_keywords, endpoint_keywords)
    local result = {
        blocked = {},
        flagged = {},
        inherit_global = true
    }

    if not endpoint_keywords then
        result.inherit_global = true
        return result
    end

    result.inherit_global = endpoint_keywords.inherit_global ~= false

    -- Copy additional keywords
    if endpoint_keywords.additional_blocked then
        for _, kw in ipairs(endpoint_keywords.additional_blocked) do
            table.insert(result.blocked, kw)
        end
    end

    if endpoint_keywords.additional_flagged then
        for _, kw in ipairs(endpoint_keywords.additional_flagged) do
            table.insert(result.flagged, kw)
        end
    end

    -- Store exclusions for runtime filtering
    result.excluded_blocked = endpoint_keywords.excluded_blocked or {}
    result.excluded_flagged = endpoint_keywords.excluded_flagged or {}

    return result
end

-- Merge pattern configuration
local function merge_patterns(global_patterns, endpoint_patterns)
    local result = {
        inherit_global = true,
        disabled = {},
        custom = {}
    }

    if not endpoint_patterns then
        return result
    end

    result.inherit_global = endpoint_patterns.inherit_global ~= false

    -- Support canonical name (disabled) and legacy (disabled_patterns)
    local disabled_list = endpoint_patterns.disabled or endpoint_patterns.disabled_patterns
    if disabled_list then
        for _, pattern in ipairs(disabled_list) do
            result.disabled[pattern] = true
        end
    end

    -- Support canonical name (custom) and legacy (custom_patterns)
    result.custom = endpoint_patterns.custom or endpoint_patterns.custom_patterns or {}

    return result
end

-- Merge rate limiting configuration
local function merge_rate_limiting(global_config, endpoint_config)
    local result = {
        enabled = true,
        requests_per_minute = global_config.ip_rate_limit or 30,
        requests_per_hour = nil,
        burst_limit = nil
    }

    if not endpoint_config then
        return result
    end

    if endpoint_config.enabled ~= nil then
        result.enabled = endpoint_config.enabled
    end

    if endpoint_config.requests_per_minute then
        result.requests_per_minute = endpoint_config.requests_per_minute
    end

    if endpoint_config.requests_per_hour then
        result.requests_per_hour = endpoint_config.requests_per_hour
    end

    if endpoint_config.burst_limit then
        result.burst_limit = endpoint_config.burst_limit
    end

    return result
end

-- Merge field configuration
local function merge_fields(endpoint_fields)
    local result = deep_copy(DEFAULT_ENDPOINT_CONFIG.fields)

    if not endpoint_fields then
        return result
    end

    if endpoint_fields.required then
        result.required = endpoint_fields.required
    end

    if endpoint_fields.max_length then
        for field, length in pairs(endpoint_fields.max_length) do
            result.max_length[field] = length
        end
    end

    -- Support canonical name (ignore) and legacy (ignore_fields)
    local ignore_list = endpoint_fields.ignore or endpoint_fields.ignore_fields
    if ignore_list then
        -- Merge ignore fields (add to defaults)
        local ignore_set = {}
        for _, f in ipairs(result.ignore) do
            ignore_set[f] = true
        end
        for _, f in ipairs(ignore_list) do
            if not ignore_set[f] then
                table.insert(result.ignore, f)
            end
        end
    end

    -- Copy honeypot fields (for bot detection)
    if endpoint_fields.honeypot then
        result.honeypot = endpoint_fields.honeypot
    end

    -- Support canonical name (expected) and legacy (expected_fields)
    local expected_list = endpoint_fields.expected or endpoint_fields.expected_fields
    if expected_list then
        result.expected = expected_list
    end

    -- Support canonical name (hash) and legacy (hash_content)
    local hash_config = endpoint_fields.hash or endpoint_fields.hash_content
    if hash_config then
        if type(hash_config) == "table" then
            -- New format: {enabled: true, fields: [...]}
            if hash_config.enabled ~= nil or hash_config.fields then
                result.hash = {
                    enabled = hash_config.enabled ~= false,
                    fields = hash_config.fields or {}
                }
            else
                -- Legacy format: array of field names (hash_content was just a list)
                result.hash = {
                    enabled = true,
                    fields = hash_config
                }
            end
        end
    end

    return result
end

-- Merge action configuration
local function merge_actions(endpoint_actions)
    local result = deep_copy(DEFAULT_ENDPOINT_CONFIG.actions)

    if not endpoint_actions then
        return result
    end

    if endpoint_actions.on_block then
        result.on_block = endpoint_actions.on_block
    end

    if endpoint_actions.on_flag then
        result.on_flag = endpoint_actions.on_flag
    end

    if endpoint_actions.log_level then
        result.log_level = endpoint_actions.log_level
    end

    if endpoint_actions.notify_webhook then
        result.notify_webhook = endpoint_actions.notify_webhook
    end

    return result
end

-- Apply mode-specific threshold adjustments
local function apply_mode_adjustments(thresholds, mode)
    if mode == "strict" then
        -- Strict mode: lower thresholds by 25%
        return {
            spam_score_block = math.floor((thresholds.spam_score_block or 80) * 0.75),
            spam_score_flag = math.floor((thresholds.spam_score_flag or 50) * 0.75),
            hash_count_block = math.floor((thresholds.hash_count_block or 10) * 0.75),
            ip_rate_limit = math.floor((thresholds.ip_rate_limit or 30) * 0.75),
            ip_spam_score_threshold = math.floor((thresholds.ip_spam_score_threshold or 500) * 0.75),
            fingerprint_rate_limit = math.floor((thresholds.fingerprint_rate_limit or 20) * 0.75)
        }
    elseif mode == "monitoring" then
        -- Monitoring mode: keep thresholds but they won't block
        return thresholds
    elseif mode == "passthrough" then
        -- Passthrough mode: thresholds don't matter
        return thresholds
    end

    -- Default (blocking mode): use thresholds as-is
    return thresholds
end

-- Main resolution function
-- Merges endpoint config with global defaults to produce effective configuration
function _M.resolve(endpoint_config)
    local global_thresholds = waf_config.get_thresholds()

    -- If no endpoint config, use global defaults
    if not endpoint_config then
        return {
            endpoint_id = nil,
            enabled = true,
            mode = "blocking",
            thresholds = global_thresholds,
            keywords = {
                inherit_global = true,
                blocked = {},
                flagged = {},
                excluded_blocked = {},
                excluded_flagged = {}
            },
            patterns = {
                inherit_global = true,
                disabled = {},
                custom = {}
            },
            rate_limiting = {
                enabled = true,
                requests_per_minute = global_thresholds.ip_rate_limit or 30
            },
            fields = deep_copy(DEFAULT_ENDPOINT_CONFIG.fields),
            actions = deep_copy(DEFAULT_ENDPOINT_CONFIG.actions)
        }
    end

    -- Determine effective mode
    local mode = endpoint_config.mode or "blocking"

    -- Merge thresholds
    local thresholds = merge_thresholds(global_thresholds, endpoint_config.thresholds)

    -- Apply mode-specific adjustments
    thresholds = apply_mode_adjustments(thresholds, mode)

    -- Build resolved configuration
    local resolved = {
        endpoint_id = endpoint_config.id,
        enabled = endpoint_config.enabled ~= false,
        mode = mode,
        thresholds = thresholds,
        keywords = merge_keywords(nil, endpoint_config.keywords),
        patterns = merge_patterns(nil, endpoint_config.patterns),
        rate_limiting = merge_rate_limiting(global_thresholds, endpoint_config.rate_limiting),
        fields = merge_fields(endpoint_config.fields),
        actions = merge_actions(endpoint_config.actions),
        security = endpoint_config.security,  -- Pass through security settings (honeypot, disposable email, etc.)
        metadata = endpoint_config.metadata
    }

    return resolved
end

-- Check if request should skip WAF processing entirely
function _M.should_skip_waf(resolved_config)
    if not resolved_config then
        return false
    end

    -- Skip if disabled
    if not resolved_config.enabled then
        return true
    end

    -- Skip if passthrough mode
    if resolved_config.mode == "passthrough" then
        return true
    end

    return false
end

-- Check if WAF should block (vs just monitor)
function _M.should_block(resolved_config)
    if not resolved_config then
        return true  -- Default: blocking enabled
    end

    -- Don't block if disabled or passthrough
    if not resolved_config.enabled or resolved_config.mode == "passthrough" then
        return false
    end

    -- Don't block in monitoring mode
    if resolved_config.mode == "monitoring" then
        return false
    end

    return true
end

-- Get effective spam score threshold for blocking
function _M.get_block_threshold(resolved_config)
    if not resolved_config or not resolved_config.thresholds then
        return 80  -- Default
    end
    return resolved_config.thresholds.spam_score_block or 80
end

-- Get effective spam score threshold for flagging
function _M.get_flag_threshold(resolved_config)
    if not resolved_config or not resolved_config.thresholds then
        return 50  -- Default
    end
    return resolved_config.thresholds.spam_score_flag or 50
end

-- Check if a keyword is excluded for this endpoint
function _M.is_keyword_excluded(resolved_config, keyword, keyword_type)
    if not resolved_config or not resolved_config.keywords then
        return false
    end

    local exclusions
    if keyword_type == "blocked" then
        exclusions = resolved_config.keywords.excluded_blocked
    else
        exclusions = resolved_config.keywords.excluded_flagged
    end

    if not exclusions then
        return false
    end

    for _, excluded in ipairs(exclusions) do
        if excluded:lower() == keyword:lower() then
            return true
        end
    end

    return false
end

-- Check if a pattern is disabled for this endpoint
function _M.is_pattern_disabled(resolved_config, pattern_flag)
    if not resolved_config or not resolved_config.patterns then
        return false
    end

    return resolved_config.patterns.disabled[pattern_flag] == true
end

-- Get additional keywords for this endpoint
function _M.get_additional_keywords(resolved_config)
    if not resolved_config or not resolved_config.keywords then
        return {blocked = {}, flagged = {}}
    end

    return {
        blocked = resolved_config.keywords.blocked or {},
        flagged = resolved_config.keywords.flagged or {}
    }
end

-- Get custom patterns for this endpoint
function _M.get_custom_patterns(resolved_config)
    if not resolved_config or not resolved_config.patterns then
        return {}
    end

    return resolved_config.patterns.custom or {}
end

-- Check if global keywords should be used
function _M.should_inherit_global_keywords(resolved_config)
    if not resolved_config or not resolved_config.keywords then
        return true
    end
    return resolved_config.keywords.inherit_global ~= false
end

-- Check if global patterns should be used
function _M.should_inherit_global_patterns(resolved_config)
    if not resolved_config or not resolved_config.patterns then
        return true
    end
    return resolved_config.patterns.inherit_global ~= false
end

-- Get fields to ignore during hashing
function _M.get_ignore_fields(resolved_config)
    if not resolved_config or not resolved_config.fields then
        return DEFAULT_ENDPOINT_CONFIG.fields.ignore
    end
    return resolved_config.fields.ignore or DEFAULT_ENDPOINT_CONFIG.fields.ignore
end

-- Validate field requirements
function _M.validate_fields(resolved_config, form_data)
    local errors = {}

    if not resolved_config or not resolved_config.fields then
        return true, errors
    end

    -- Check required fields
    if resolved_config.fields.required then
        for _, field in ipairs(resolved_config.fields.required) do
            if not form_data[field] or form_data[field] == "" then
                table.insert(errors, "Missing required field: " .. field)
            end
        end
    end

    -- Check max length
    if resolved_config.fields.max_length then
        for field, max_len in pairs(resolved_config.fields.max_length) do
            if form_data[field] and type(form_data[field]) == "string" then
                if #form_data[field] > max_len then
                    table.insert(errors, "Field '" .. field .. "' exceeds max length of " .. max_len)
                end
            end
        end
    end

    return #errors == 0, errors
end

return _M
