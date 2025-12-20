-- waf_config.lua
-- Configuration management for WAF

local _M = {}

local cjson = require "cjson.safe"

-- Shared dictionary for config
local config_cache = ngx.shared.config_cache

-- Helper to parse boolean environment variables
local function env_bool(name, default)
    local val = os.getenv(name)
    if val == nil then return default end
    val = val:lower()
    return val == "true" or val == "1" or val == "yes"
end

-- Default thresholds
local DEFAULT_THRESHOLDS = {
    -- Per-request spam score thresholds
    spam_score_block = 80,       -- Score at which to block immediately
    spam_score_flag = 50,        -- Score at which to flag for HAProxy

    -- Content hash flood detection
    hash_count_block = 10,       -- Block if same hash seen this many times per minute
    hash_unique_ips_block = 5,   -- Block hash if seen from this many unique IPs

    -- Rate limiting (request counts)
    ip_rate_limit = 30,          -- Max form submissions per minute per IP
    ip_daily_limit = 500,        -- Max form submissions per day per IP
    fingerprint_rate_limit = 20, -- Max submissions per minute per fingerprint
    rate_limiting_enabled = true, -- Global rate limiting toggle

    -- Score-based blocking (cumulative)
    ip_spam_score_threshold = 500, -- Block IP when cumulative spam score over 24h exceeds this

    -- Debug settings
    expose_waf_headers = false,  -- Expose WAF debug headers to clients (X-WAF-*, X-Spam-*)
}

-- Default routing settings (use environment variables with fallbacks)
-- haproxy_upstream: HTTP endpoint address (FQDN:port)
-- haproxy_upstream_ssl: HTTPS endpoint address (FQDN:port)
-- upstream_ssl: boolean toggle - when true, use haproxy_upstream_ssl instead of haproxy_upstream
local DEFAULT_ROUTING = {
    haproxy_upstream = os.getenv("HAPROXY_UPSTREAM") or "haproxy:8080",
    haproxy_upstream_ssl = os.getenv("HAPROXY_UPSTREAM_SSL") or "haproxy:8443",
    upstream_ssl = env_bool("UPSTREAM_SSL", false),
    haproxy_timeout = 30,
}

-- Get thresholds (from Redis cache or defaults)
function _M.get_thresholds()
    local cached = config_cache:get("thresholds")

    if cached then
        local thresholds = cjson.decode(cached)
        if thresholds then
            -- Merge with defaults
            for k, v in pairs(DEFAULT_THRESHOLDS) do
                if not thresholds[k] then
                    thresholds[k] = v
                end
            end
            return thresholds
        end
    end

    return DEFAULT_THRESHOLDS
end

-- Get a specific threshold value
function _M.get_threshold(name)
    local thresholds = _M.get_thresholds()
    return thresholds[name] or DEFAULT_THRESHOLDS[name]
end

-- Get routing config (from Redis cache or defaults)
function _M.get_routing()
    local cached = config_cache:get("routing")

    if cached then
        local routing = cjson.decode(cached)
        if routing then
            -- Merge with defaults
            for k, v in pairs(DEFAULT_ROUTING) do
                if not routing[k] then
                    routing[k] = v
                end
            end
            return routing
        end
    end

    return DEFAULT_ROUTING
end

-- Get HAProxy upstream address (returns appropriate endpoint based on upstream_ssl toggle)
function _M.get_haproxy_upstream()
    local routing = _M.get_routing()
    if routing.upstream_ssl then
        return routing.haproxy_upstream_ssl or DEFAULT_ROUTING.haproxy_upstream_ssl
    end
    return routing.haproxy_upstream or DEFAULT_ROUTING.haproxy_upstream
end

-- Get HAProxy upstream URL (includes scheme based on upstream_ssl toggle)
function _M.get_haproxy_upstream_url()
    local routing = _M.get_routing()
    if routing.upstream_ssl then
        local upstream = routing.haproxy_upstream_ssl or DEFAULT_ROUTING.haproxy_upstream_ssl
        return "https://" .. upstream
    end
    local upstream = routing.haproxy_upstream or DEFAULT_ROUTING.haproxy_upstream
    return "http://" .. upstream
end

-- Check if upstream SSL is enabled
function _M.is_upstream_ssl()
    local routing = _M.get_routing()
    return routing.upstream_ssl == true
end

-- Get HAProxy timeout
function _M.get_haproxy_timeout()
    local routing = _M.get_routing()
    return routing.haproxy_timeout or DEFAULT_ROUTING.haproxy_timeout
end

-- Check if WAF headers should be exposed to clients
function _M.expose_waf_headers()
    local thresholds = _M.get_thresholds()
    return thresholds.expose_waf_headers == true
end

-- Check if rate limiting is globally enabled
function _M.rate_limiting_enabled()
    local thresholds = _M.get_thresholds()
    return thresholds.rate_limiting_enabled ~= false
end

-- Get all config (for admin API)
function _M.get_all()
    return {
        thresholds = _M.get_thresholds(),
        routing = _M.get_routing(),
        defaults = {
            thresholds = DEFAULT_THRESHOLDS,
            routing = DEFAULT_ROUTING,
        },
    }
end

return _M
