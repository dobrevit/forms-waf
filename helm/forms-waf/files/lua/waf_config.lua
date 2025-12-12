-- waf_config.lua
-- Configuration management for WAF

local _M = {}

local cjson = require "cjson.safe"

-- Shared dictionary for config
local config_cache = ngx.shared.config_cache

-- Default thresholds
local DEFAULT_THRESHOLDS = {
    spam_score_block = 80,       -- Score at which to block immediately
    spam_score_flag = 50,        -- Score at which to flag for HAProxy
    hash_count_block = 10,       -- Block if same hash seen this many times
    hash_unique_ips_block = 5,   -- Block hash if seen from this many unique IPs
    ip_rate_limit = 30,          -- Max form submissions per minute per IP
    ip_daily_limit = 500,        -- Max form submissions per day per IP
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

-- Get all config (for admin API)
function _M.get_all()
    return {
        thresholds = _M.get_thresholds(),
        defaults = DEFAULT_THRESHOLDS,
    }
end

return _M
