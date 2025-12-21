-- vhost_resolver.lua
-- Resolves effective configuration for virtual hosts
-- Implements inheritance: Global -> Vhost -> Endpoint

local _M = {}

local cjson = require "cjson.safe"
local waf_config = require "waf_config"
local vhost_matcher = require "vhost_matcher"
local endpoint_matcher = require "endpoint_matcher"
local config_resolver = require "config_resolver"

-- Default vhost configuration
local DEFAULT_VHOST_CONFIG = {
    enabled = true,
    waf = {
        enabled = true,
        default_mode = "blocking"
    },
    routing = {
        use_haproxy = true,
        haproxy_backend = nil
    },
    thresholds = nil,  -- Inherit from global
    keywords = {
        inherit_global = true,
        additional_blocked = {},
        additional_flagged = {},
        excluded_blocked = {},
        excluded_flagged = {}
    },
    endpoints = {
        inherit_global = true,
        custom_endpoints = {}
    }
}

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

-- Merge thresholds (vhost overrides global)
local function merge_thresholds(global_thresholds, vhost_thresholds)
    local result = shallow_copy(global_thresholds)

    if vhost_thresholds then
        for key, value in pairs(vhost_thresholds) do
            if value ~= nil then
                result[key] = value
            end
        end
    end

    return result
end

-- Merge keyword configuration
local function merge_keywords(vhost_keywords)
    local result = {
        inherit_global = true,
        additional_blocked = {},
        additional_flagged = {},
        excluded_blocked = {},
        excluded_flagged = {}
    }

    if not vhost_keywords then
        return result
    end

    result.inherit_global = vhost_keywords.inherit_global ~= false

    if vhost_keywords.additional_blocked then
        result.additional_blocked = vhost_keywords.additional_blocked
    end

    if vhost_keywords.additional_flagged then
        result.additional_flagged = vhost_keywords.additional_flagged
    end

    if vhost_keywords.excluded_blocked then
        result.excluded_blocked = vhost_keywords.excluded_blocked
    end

    if vhost_keywords.excluded_flagged then
        result.excluded_flagged = vhost_keywords.excluded_flagged
    end

    return result
end

-- Resolve routing configuration
-- Resolves haproxy_upstream with fallback: vhost override -> global config -> default
-- Note: upstream_ssl is the toggle that determines whether to use haproxy_upstream_ssl
local function resolve_routing(vhost_config)
    -- Get global routing config
    local global_routing = waf_config.get_routing()

    local result = {
        use_haproxy = true,
        haproxy_backend = nil,
        haproxy_upstream = global_routing.haproxy_upstream,  -- HTTP endpoint
        haproxy_upstream_ssl = global_routing.haproxy_upstream_ssl,  -- HTTPS endpoint
        upstream_ssl = global_routing.upstream_ssl,  -- Toggle: use SSL endpoint
        haproxy_timeout = global_routing.haproxy_timeout,
        upstream = nil
    }

    if not vhost_config then
        return result
    end

    if vhost_config.routing then
        if vhost_config.routing.use_haproxy ~= nil then
            result.use_haproxy = vhost_config.routing.use_haproxy
        end
        if vhost_config.routing.haproxy_backend then
            result.haproxy_backend = vhost_config.routing.haproxy_backend
        end
        -- Vhost-specific HAProxy upstream overrides
        if vhost_config.routing.haproxy_upstream then
            result.haproxy_upstream = vhost_config.routing.haproxy_upstream
        end
        if vhost_config.routing.haproxy_upstream_ssl then
            result.haproxy_upstream_ssl = vhost_config.routing.haproxy_upstream_ssl
        end
        -- Vhost-specific SSL toggle override (haproxy_ssl is legacy alias for upstream_ssl)
        if vhost_config.routing.upstream_ssl ~= nil then
            result.upstream_ssl = vhost_config.routing.upstream_ssl
        elseif vhost_config.routing.haproxy_ssl ~= nil then
            -- Legacy support: haproxy_ssl as alias for upstream_ssl
            result.upstream_ssl = vhost_config.routing.haproxy_ssl
        end
        -- Upstream configuration is nested under routing (for direct routing)
        if vhost_config.routing.upstream then
            result.upstream = vhost_config.routing.upstream
        end
    end

    -- Also support legacy top-level upstream config
    if not result.upstream and vhost_config.upstream then
        result.upstream = vhost_config.upstream
    end

    return result
end

-- Resolve WAF settings for vhost
local function resolve_waf_settings(vhost_config)
    local result = {
        enabled = true,
        mode = "blocking",
        debug_headers = nil  -- nil = inherit from global, true/false = explicit override
    }

    if not vhost_config or not vhost_config.waf then
        -- Set default_mode as alias for backward compatibility
        result.default_mode = result.mode
        return result
    end

    if vhost_config.waf.enabled ~= nil then
        result.enabled = vhost_config.waf.enabled
    end

    -- Support both "mode" and "default_mode" for backward compatibility
    if vhost_config.waf.mode then
        result.mode = vhost_config.waf.mode
    elseif vhost_config.waf.default_mode then
        result.mode = vhost_config.waf.default_mode
    end

    -- Set default_mode as alias pointing to the same value
    result.default_mode = result.mode

    -- Per-vhost debug header override (nil = inherit from global)
    if vhost_config.waf.debug_headers ~= nil then
        result.debug_headers = vhost_config.waf.debug_headers
    end

    return result
end

-- Resolve timing configuration for vhost with inheritance from global
local function resolve_timing_config(vhost_config)
    -- Default timing config (inherits from global timing_token defaults)
    local result = {
        enabled = false,
        cookie_ttl = 3600,
        min_time_block = 2,
        min_time_flag = 5,
        score_no_cookie = 30,
        score_too_fast = 40,
        score_suspicious = 20,
        start_paths = {},
        end_paths = {},
        path_match_mode = "exact"
    }

    -- No vhost timing config, return defaults (disabled)
    if not vhost_config or not vhost_config.timing then
        return result
    end

    local vhost_timing = vhost_config.timing

    -- Override with vhost-specific values
    if vhost_timing.enabled ~= nil then
        result.enabled = vhost_timing.enabled
    end
    if vhost_timing.cookie_ttl then
        result.cookie_ttl = vhost_timing.cookie_ttl
    end
    if vhost_timing.min_time_block then
        result.min_time_block = vhost_timing.min_time_block
    end
    if vhost_timing.min_time_flag then
        result.min_time_flag = vhost_timing.min_time_flag
    end
    if vhost_timing.score_no_cookie then
        result.score_no_cookie = vhost_timing.score_no_cookie
    end
    if vhost_timing.score_too_fast then
        result.score_too_fast = vhost_timing.score_too_fast
    end
    if vhost_timing.score_suspicious then
        result.score_suspicious = vhost_timing.score_suspicious
    end
    if vhost_timing.start_paths then
        result.start_paths = vhost_timing.start_paths
    end
    if vhost_timing.end_paths then
        result.end_paths = vhost_timing.end_paths
    end
    if vhost_timing.path_match_mode then
        result.path_match_mode = vhost_timing.path_match_mode
    end

    return result
end

-- Main resolution function for vhost
-- Returns complete resolved configuration for a vhost
function _M.resolve(vhost_id)
    local vhost_config = vhost_matcher.get_config(vhost_id)
    local global_thresholds = waf_config.get_thresholds()

    -- Start with defaults
    local resolved = {
        vhost_id = vhost_id,
        is_default = vhost_id == vhost_matcher.DEFAULT_VHOST,
        enabled = true,
        waf = resolve_waf_settings(vhost_config),
        routing = resolve_routing(vhost_config),
        timing = resolve_timing_config(vhost_config),
        thresholds = merge_thresholds(global_thresholds, vhost_config and vhost_config.thresholds),
        keywords = merge_keywords(vhost_config and vhost_config.keywords),
        endpoints = {
            inherit_global = true,
            custom_endpoints = {}
        },
        metadata = vhost_config and vhost_config.metadata
    }

    -- Handle vhost enabled state
    if vhost_config and vhost_config.enabled == false then
        resolved.enabled = false
    end

    -- Handle endpoint inheritance
    if vhost_config and vhost_config.endpoints then
        resolved.endpoints.inherit_global = vhost_config.endpoints.inherit_global ~= false
        if vhost_config.endpoints.custom_endpoints then
            resolved.endpoints.custom_endpoints = vhost_config.endpoints.custom_endpoints
        end
    end

    return resolved
end

-- Resolve full request context (vhost + endpoint)
-- This is the main function called during request processing
function _M.resolve_request_context(host, path, method)
    -- 1. Match vhost
    local vhost_id, vhost_match_type = vhost_matcher.match(host)
    local vhost_resolved = _M.resolve(vhost_id)

    -- 2. Check if vhost is disabled
    if not vhost_resolved.enabled then
        return {
            vhost = vhost_resolved,
            vhost_match_type = vhost_match_type,
            endpoint = nil,
            endpoint_match_type = "none",
            skip_waf = true,
            reason = "vhost_disabled"
        }
    end

    -- 3. Check if WAF is disabled for this vhost
    if not vhost_resolved.waf.enabled then
        return {
            vhost = vhost_resolved,
            vhost_match_type = vhost_match_type,
            endpoint = nil,
            endpoint_match_type = "none",
            skip_waf = true,
            reason = "waf_disabled"
        }
    end

    -- 4. Match endpoint (vhost-specific first, then global)
    local endpoint_id, endpoint_match_type, endpoint_scope = endpoint_matcher.match_with_vhost(path, method, vhost_id)
    local endpoint_config = endpoint_matcher.get_config(endpoint_id)
    local endpoint_resolved = config_resolver.resolve(endpoint_config)

    -- 5. Apply vhost-level overrides to endpoint config
    if endpoint_resolved then
        -- Inherit vhost mode if:
        -- 1. endpoint_config is nil (no explicit endpoint configured), OR
        -- 2. endpoint_config exists but has no explicit mode field
        -- Note: config_resolver.resolve() defaults mode to "blocking" if not set,
        -- but we want to inherit vhost mode in that case.
        local should_inherit_vhost_mode = not endpoint_config or not endpoint_config.mode
        if should_inherit_vhost_mode and vhost_resolved.waf and vhost_resolved.waf.mode then
            endpoint_resolved.mode = vhost_resolved.waf.mode
        end

        -- Merge vhost thresholds with endpoint thresholds
        if vhost_resolved.thresholds then
            for key, value in pairs(vhost_resolved.thresholds) do
                if endpoint_resolved.thresholds[key] == nil then
                    endpoint_resolved.thresholds[key] = value
                end
            end
        end

        -- Apply vhost keyword exclusions
        if vhost_resolved.keywords then
            -- Add vhost excluded keywords to endpoint
            if vhost_resolved.keywords.excluded_blocked then
                for _, kw in ipairs(vhost_resolved.keywords.excluded_blocked) do
                    table.insert(endpoint_resolved.keywords.excluded_blocked, kw)
                end
            end
            if vhost_resolved.keywords.excluded_flagged then
                for _, kw in ipairs(vhost_resolved.keywords.excluded_flagged) do
                    table.insert(endpoint_resolved.keywords.excluded_flagged, kw)
                end
            end

            -- Add vhost additional keywords to endpoint
            if vhost_resolved.keywords.additional_blocked then
                for _, kw in ipairs(vhost_resolved.keywords.additional_blocked) do
                    table.insert(endpoint_resolved.keywords.blocked, kw)
                end
            end
            if vhost_resolved.keywords.additional_flagged then
                for _, kw in ipairs(vhost_resolved.keywords.additional_flagged) do
                    table.insert(endpoint_resolved.keywords.flagged, kw)
                end
            end

            -- Set inherit flag based on both vhost and endpoint
            endpoint_resolved.keywords.inherit_global =
                vhost_resolved.keywords.inherit_global and
                endpoint_resolved.keywords.inherit_global
        end
    end

    -- 6. Determine if WAF should be skipped
    local skip_waf = config_resolver.should_skip_waf(endpoint_resolved)

    return {
        vhost = vhost_resolved,
        vhost_match_type = vhost_match_type,
        endpoint = endpoint_resolved,
        endpoint_match_type = endpoint_match_type,
        endpoint_scope = endpoint_scope,  -- "vhost" or "global" or nil
        skip_waf = skip_waf,
        reason = skip_waf and (endpoint_resolved and endpoint_resolved.mode == "passthrough" and "passthrough" or "disabled") or nil
    }
end

-- Check if request should skip WAF
function _M.should_skip_waf(context)
    if not context then
        return false
    end
    return context.skip_waf == true
end

-- Check if request should be blocked (vs monitored)
function _M.should_block(context)
    if not context or not context.endpoint then
        -- No endpoint config, use vhost default mode
        if context and context.vhost and context.vhost.waf then
            local mode = context.vhost.waf.mode or context.vhost.waf.default_mode or "blocking"
            return mode == "blocking" or mode == "strict"
        end
        return true  -- Default: blocking
    end

    return config_resolver.should_block(context.endpoint)
end

-- Get effective mode for request
function _M.get_mode(context)
    if not context then
        return "blocking"
    end

    -- Endpoint mode takes priority
    if context.endpoint and context.endpoint.mode then
        return context.endpoint.mode
    end

    -- Fall back to vhost mode
    if context.vhost and context.vhost.waf then
        return context.vhost.waf.mode or context.vhost.waf.default_mode or "blocking"
    end

    return "blocking"
end

-- Get effective thresholds for request
function _M.get_thresholds(context)
    if not context then
        return waf_config.get_thresholds()
    end

    if context.endpoint and context.endpoint.thresholds then
        return context.endpoint.thresholds
    end

    if context.vhost and context.vhost.thresholds then
        return context.vhost.thresholds
    end

    return waf_config.get_thresholds()
end

-- Get spam score block threshold
function _M.get_block_threshold(context)
    local thresholds = _M.get_thresholds(context)
    return thresholds.spam_score_block or 80
end

-- Get spam score flag threshold
function _M.get_flag_threshold(context)
    local thresholds = _M.get_thresholds(context)
    return thresholds.spam_score_flag or 50
end

-- Check if keyword is excluded
function _M.is_keyword_excluded(context, keyword, keyword_type)
    if not context or not context.endpoint then
        return false
    end
    return config_resolver.is_keyword_excluded(context.endpoint, keyword, keyword_type)
end

-- Check if should inherit global keywords
function _M.should_inherit_global_keywords(context)
    if not context then
        return true
    end

    -- Check vhost level
    if context.vhost and context.vhost.keywords then
        if not context.vhost.keywords.inherit_global then
            return false
        end
    end

    -- Check endpoint level
    if context.endpoint then
        return config_resolver.should_inherit_global_keywords(context.endpoint)
    end

    return true
end

-- Get routing info for request
function _M.get_routing(context)
    if not context or not context.vhost then
        -- Return defaults with global HAProxy upstream
        local global_routing = waf_config.get_routing()
        return {
            use_haproxy = true,
            haproxy_backend = nil,
            haproxy_upstream = global_routing.haproxy_upstream,
            haproxy_upstream_ssl = global_routing.haproxy_upstream_ssl,
            upstream_ssl = global_routing.upstream_ssl,
            haproxy_timeout = global_routing.haproxy_timeout,
            upstream = nil
        }
    end
    return context.vhost.routing
end

-- Get rate limiting config for request
function _M.get_rate_limiting(context)
    -- Get global thresholds
    local thresholds = waf_config.get_thresholds()

    -- Default rate limiting config based on global settings
    local default_rate_limiting = {
        enabled = thresholds.rate_limiting_enabled ~= false,  -- default true
        requests_per_minute = thresholds.ip_rate_limit or 30
    }

    -- Check endpoint-level rate limiting first (most specific)
    if context and context.endpoint and context.endpoint.rate_limiting then
        local endpoint_rl = context.endpoint.rate_limiting
        -- Endpoint can override global enabled state
        -- Use explicit check to handle false value correctly
        local enabled = default_rate_limiting.enabled
        if endpoint_rl.enabled ~= nil then
            enabled = endpoint_rl.enabled
        end
        return {
            enabled = enabled,
            requests_per_minute = endpoint_rl.requests_per_minute or default_rate_limiting.requests_per_minute
        }
    end

    -- Check vhost-level rate limiting
    if context and context.vhost and context.vhost.rate_limiting then
        local vhost_rl = context.vhost.rate_limiting
        local enabled = default_rate_limiting.enabled
        if vhost_rl.enabled ~= nil then
            enabled = vhost_rl.enabled
        end
        return {
            enabled = enabled,
            requests_per_minute = vhost_rl.requests_per_minute or default_rate_limiting.requests_per_minute
        }
    end

    -- Return global defaults
    return default_rate_limiting
end

-- Get timing configuration for request context
-- Returns resolved timing config from vhost, or nil if not available
function _M.get_timing_config(context)
    if not context or not context.vhost then
        return nil
    end
    return context.vhost.timing
end

-- Get upstream URL based on routing config
-- For HAProxy routing: returns HAProxy address with SSL support
-- For direct routing: returns one of the configured upstream servers with SSL support
-- Routing uses two separate endpoints:
--   haproxy_upstream: HTTP endpoint (FQDN:port)
--   haproxy_upstream_ssl: HTTPS endpoint (FQDN:port)
--   upstream_ssl: boolean toggle - when true, use haproxy_upstream_ssl
-- Configuration is hierarchical: vhost -> global -> env var -> default
function _M.get_upstream_url(context)
    local global_routing = waf_config.get_routing()

    if not context or not context.vhost then
        -- Default to HAProxy with appropriate endpoint based on upstream_ssl toggle
        if global_routing.upstream_ssl then
            return "https://" .. (global_routing.haproxy_upstream_ssl or "haproxy:8443")
        end
        return "http://" .. (global_routing.haproxy_upstream or "haproxy:8080")
    end

    local routing = context.vhost.routing
    if not routing then
        if global_routing.upstream_ssl then
            return "https://" .. (global_routing.haproxy_upstream_ssl or "haproxy:8443")
        end
        return "http://" .. (global_routing.haproxy_upstream or "haproxy:8080")
    end

    if routing.use_haproxy or routing.use_haproxy == nil then
        -- HAProxy mode (default): resolve SSL toggle hierarchically
        -- Check vhost override first, then fall back to global
        local use_ssl = routing.upstream_ssl
        if use_ssl == nil then
            -- Legacy support: check haproxy_ssl as alias
            use_ssl = routing.haproxy_ssl
        end
        if use_ssl == nil then
            use_ssl = global_routing.upstream_ssl
        end

        if use_ssl then
            local upstream = routing.haproxy_upstream_ssl or global_routing.haproxy_upstream_ssl or "haproxy:8443"
            return "https://" .. upstream
        else
            local upstream = routing.haproxy_upstream or global_routing.haproxy_upstream or "haproxy:8080"
            return "http://" .. upstream
        end
    else
        -- Direct routing mode (use_haproxy = false)
        local server = vhost_matcher.select_upstream_server(context.vhost.vhost_id)
        if not server then
            ngx.log(ngx.WARN, "Direct routing configured but no upstream servers, falling back to HAProxy")
            if global_routing.upstream_ssl then
                return "https://" .. (global_routing.haproxy_upstream_ssl or "haproxy:8443")
            end
            return "http://" .. (global_routing.haproxy_upstream or "haproxy:8080")
        end

        -- Resolve SSL hierarchically for direct upstream
        local ssl = routing.upstream and routing.upstream.ssl
        if ssl == nil then
            ssl = global_routing.upstream_ssl  -- global/env default
        end
        local scheme = ssl and "https" or "http"

        -- Add port if not present
        if not server:match(":%d+$") then
            server = server .. (ssl and ":443" or ":80")
        end

        return scheme .. "://" .. server
    end
end

-- Get HAProxy backend name (for X-Haproxy-Backend header)
function _M.get_haproxy_backend(context)
    if not context or not context.vhost or not context.vhost.routing then
        return nil
    end
    return context.vhost.routing.haproxy_backend
end

-- Get ignore fields for WAF inspection
function _M.get_ignore_fields(context)
    if context and context.endpoint then
        return config_resolver.get_ignore_fields(context.endpoint)
    end
    return {"_csrf", "_token", "csrf_token", "authenticity_token", "captcha", "g-recaptcha-response", "h-captcha-response"}
end

-- Get hash configuration
-- Returns: { enabled = bool, fields = {field1, field2, ...} }
-- Canonical location: fields.hash
function _M.get_hash_config(context)
    if context and context.endpoint and context.endpoint.fields then
        local fields_config = context.endpoint.fields
        if fields_config.hash then
            return fields_config.hash
        end
    end
    -- Default: disabled (user must explicitly enable and specify fields)
    return { enabled = false, fields = {} }
end

-- Backward compatibility alias
_M.get_hash_content_config = _M.get_hash_config

-- Get expected fields for the endpoint (optional fields that are allowed)
-- Returns: array of expected field names, or empty array if not configured
function _M.get_expected_fields(context)
    if context and context.endpoint and context.endpoint.fields then
        local fields_config = context.endpoint.fields
        if fields_config.expected and type(fields_config.expected) == "table" then
            return fields_config.expected
        end
    end
    return {}
end

-- Get required fields for the endpoint (these are also implicitly expected)
-- Returns: array of required field names, or empty array if not configured
function _M.get_required_fields(context)
    if context and context.endpoint and context.endpoint.fields then
        local fields_config = context.endpoint.fields
        if fields_config.required and type(fields_config.required) == "table" then
            return fields_config.required
        end
    end
    return {}
end

-- Get action for unexpected fields
-- Returns: "flag" (default), "block", or "ignore"
function _M.get_unexpected_fields_action(context)
    if context and context.endpoint and context.endpoint.fields then
        local fields_config = context.endpoint.fields
        if fields_config.unexpected_action then
            return fields_config.unexpected_action
        end
    end
    return "flag"  -- Default: flag but don't block
end

-- Get honeypot fields for the endpoint
-- Returns: array of honeypot field names, or empty array if not configured
-- Canonical location: fields.honeypot (honeypot action/score in security)
function _M.get_honeypot_fields(context)
    if not context or not context.endpoint then
        return {}
    end

    -- Canonical location: fields.honeypot
    if context.endpoint.fields then
        local fields_config = context.endpoint.fields
        if fields_config.honeypot and type(fields_config.honeypot) == "table" then
            return fields_config.honeypot
        end
    end

    return {}
end

-- Get security settings for the endpoint
-- Returns: table with security options
function _M.get_security_settings(context)
    local defaults = {
        check_disposable_email = false,
        disposable_email_action = "flag",  -- "flag", "block", "ignore"
        disposable_email_score = 20,
        honeypot_action = "block",  -- "flag", "block"
        honeypot_score = 50,
        check_field_anomalies = true,  -- Enabled by default
    }

    if context and context.endpoint and context.endpoint.security then
        local sec = context.endpoint.security
        return {
            check_disposable_email = sec.check_disposable_email or defaults.check_disposable_email,
            disposable_email_action = sec.disposable_email_action or defaults.disposable_email_action,
            disposable_email_score = sec.disposable_email_score or defaults.disposable_email_score,
            honeypot_action = sec.honeypot_action or defaults.honeypot_action,
            honeypot_score = sec.honeypot_score or defaults.honeypot_score,
            check_field_anomalies = sec.check_field_anomalies ~= false,  -- Enabled unless explicitly disabled
        }
    end

    return defaults
end

-- Validate form fields
function _M.validate_fields(context, form_data)
    if context and context.endpoint then
        return config_resolver.validate_fields(context.endpoint, form_data)
    end
    return true, {}
end

-- Get additional keywords from context
function _M.get_additional_keywords(context)
    local result = {blocked = {}, flagged = {}}

    if not context then
        return result
    end

    -- Add vhost keywords
    if context.vhost and context.vhost.keywords then
        if context.vhost.keywords.additional_blocked then
            for _, kw in ipairs(context.vhost.keywords.additional_blocked) do
                table.insert(result.blocked, kw)
            end
        end
        if context.vhost.keywords.additional_flagged then
            for _, kw in ipairs(context.vhost.keywords.additional_flagged) do
                table.insert(result.flagged, kw)
            end
        end
    end

    -- Add endpoint keywords (they're already merged in resolve_request_context)
    if context.endpoint then
        local endpoint_kw = config_resolver.get_additional_keywords(context.endpoint)
        for _, kw in ipairs(endpoint_kw.blocked) do
            table.insert(result.blocked, kw)
        end
        for _, kw in ipairs(endpoint_kw.flagged) do
            table.insert(result.flagged, kw)
        end
    end

    return result
end

-- Get fingerprint profile configuration for request context
-- Implements inheritance: endpoint -> vhost -> global defaults
-- Returns: { enabled, profiles, no_match_action, no_match_score }
function _M.get_fingerprint_profiles(context)
    -- Default fingerprint profile config
    local default = {
        enabled = true,
        profiles = nil,  -- nil = use all global profiles
        no_match_action = "use_default",  -- "use_default" | "flag" | "allow"
        no_match_score = 15
    }

    if not context then
        return default
    end

    -- Helper to merge config with defaults
    local function merge_config(config)
        if not config then
            return nil
        end
        local result = {}
        result.enabled = config.enabled ~= nil and config.enabled or default.enabled
        result.profiles = config.profiles or default.profiles
        result.no_match_action = config.no_match_action or default.no_match_action
        result.no_match_score = config.no_match_score or default.no_match_score
        return result
    end

    -- Check endpoint-level config first (most specific)
    if context.endpoint and context.endpoint.fingerprint_profiles then
        local merged = merge_config(context.endpoint.fingerprint_profiles)
        if merged then
            return merged
        end
    end

    -- Check vhost-level config
    if context.vhost and context.vhost.fingerprint_profiles then
        local merged = merge_config(context.vhost.fingerprint_profiles)
        if merged then
            return merged
        end
    end

    -- Return global defaults
    return default
end

-- Build context summary for headers/logging
function _M.get_context_summary(context)
    if not context then
        return {
            vhost_id = "_default",
            vhost_match = "none",
            endpoint_id = nil,
            endpoint_match = "none",
            endpoint_scope = nil,
            mode = "blocking"
        }
    end

    return {
        vhost_id = context.vhost and context.vhost.vhost_id or "_default",
        vhost_match = context.vhost_match_type or "none",
        endpoint_id = context.endpoint and context.endpoint.endpoint_id or nil,
        endpoint_match = context.endpoint_match_type or "none",
        endpoint_scope = context.endpoint_scope or nil,  -- "vhost" or "global"
        mode = _M.get_mode(context)
    }
end

return _M
