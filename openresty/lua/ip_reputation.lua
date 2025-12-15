-- ip_reputation.lua
-- IP reputation checking module with external API support
-- This is an OPTIONAL feature - gracefully degrades if not configured
--
-- Supported providers:
-- - AbuseIPDB (requires API key)
-- - Local blocklist (file or Redis-based)
-- - Custom webhook (for internal reputation services)
--
-- All lookups are cached in Redis to minimize API calls

local _M = {}

local cjson = require "cjson.safe"
local http = require "resty.http"

-- Configuration defaults
local DEFAULT_CONFIG = {
    enabled = false,
    cache_ttl = 86400,           -- Cache results for 24 hours
    cache_negative_ttl = 3600,   -- Cache "clean" results for 1 hour

    -- AbuseIPDB settings
    abuseipdb = {
        enabled = false,
        api_key = nil,           -- Must be set to enable
        min_confidence = 25,     -- Minimum confidence score to flag
        max_age_days = 90,       -- Only consider reports from last N days
        score_multiplier = 0.5,  -- Multiply AbuseIPDB score by this for WAF score
    },

    -- Local blocklist settings
    local_blocklist = {
        enabled = true,          -- Always check local blocklist
        redis_key = "waf:reputation:blocked_ips",
    },

    -- Custom webhook for internal reputation service
    webhook = {
        enabled = false,
        url = nil,
        timeout = 2000,          -- 2 second timeout
        headers = {},
    },

    -- Score thresholds
    block_score = 80,            -- Block if reputation score >= this
    flag_score = 50,             -- Flag (add to spam score) if >= this
    flag_score_addition = 30,    -- Score to add when flagged
}

-- Module-level config cache
local config_cache = nil
local config_cache_time = 0
local CONFIG_CACHE_TTL = 60

-- Get configuration from Redis or defaults
function _M.get_config()
    local now = ngx.now()
    if config_cache and (now - config_cache_time) < CONFIG_CACHE_TTL then
        return config_cache
    end

    -- Try to load from Redis
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    if redis then
        local config_json = redis:get("waf:config:ip_reputation")
        if config_json and config_json ~= ngx.null then
            local parsed = cjson.decode(config_json)
            if parsed then
                -- Deep merge with defaults
                local function deep_merge(default, override)
                    local result = {}
                    for k, v in pairs(default) do
                        if type(v) == "table" and type(override[k]) == "table" then
                            result[k] = deep_merge(v, override[k])
                        elseif override[k] ~= nil then
                            result[k] = override[k]
                        else
                            result[k] = v
                        end
                    end
                    for k, v in pairs(override) do
                        if result[k] == nil then
                            result[k] = v
                        end
                    end
                    return result
                end
                config_cache = deep_merge(DEFAULT_CONFIG, parsed)
                config_cache_time = now
                return config_cache
            end
        end
    end

    -- Use defaults
    config_cache = DEFAULT_CONFIG
    config_cache_time = now
    return config_cache
end

-- Check if feature is enabled and has any providers configured
function _M.is_available()
    local config = _M.get_config()
    if not config.enabled then
        return false
    end

    -- Check if at least one provider is configured
    if config.local_blocklist and config.local_blocklist.enabled then
        return true
    end
    if config.abuseipdb and config.abuseipdb.enabled and config.abuseipdb.api_key then
        return true
    end
    if config.webhook and config.webhook.enabled and config.webhook.url then
        return true
    end

    return false
end

-- Get cached reputation for IP
local function get_cached_reputation(redis, ip)
    local cache_key = "waf:reputation:cache:" .. ip
    local cached = redis:get(cache_key)
    if cached and cached ~= ngx.null then
        return cjson.decode(cached)
    end
    return nil
end

-- Cache reputation result
local function cache_reputation(redis, ip, result, config)
    local cache_key = "waf:reputation:cache:" .. ip
    local ttl = result.score > 0 and config.cache_ttl or config.cache_negative_ttl
    redis:setex(cache_key, ttl, cjson.encode(result))
end

-- Check local blocklist
local function check_local_blocklist(redis, ip, config)
    if not config.local_blocklist or not config.local_blocklist.enabled then
        return nil
    end

    local redis_key = config.local_blocklist.redis_key or "waf:reputation:blocked_ips"
    local is_blocked = redis:sismember(redis_key, ip)

    if is_blocked and is_blocked ~= 0 then
        return {
            score = 100,
            source = "local_blocklist",
            reason = "IP in local blocklist",
        }
    end

    return nil
end

-- Query AbuseIPDB
local function check_abuseipdb(ip, config)
    if not config.abuseipdb or not config.abuseipdb.enabled then
        return nil
    end

    local api_key = config.abuseipdb.api_key
    if not api_key or api_key == "" then
        return nil
    end

    local httpc = http.new()
    httpc:set_timeout(3000)  -- 3 second timeout

    local url = string.format(
        "https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=%d",
        ngx.escape_uri(ip),
        config.abuseipdb.max_age_days or 90
    )

    local res, err = httpc:request_uri(url, {
        method = "GET",
        headers = {
            ["Key"] = api_key,
            ["Accept"] = "application/json",
        },
    })

    if not res then
        ngx.log(ngx.WARN, "ip_reputation: AbuseIPDB request failed: ", err)
        return nil
    end

    if res.status ~= 200 then
        ngx.log(ngx.WARN, "ip_reputation: AbuseIPDB returned status ", res.status)
        return nil
    end

    local data = cjson.decode(res.body)
    if not data or not data.data then
        return nil
    end

    local abuse_data = data.data
    local confidence = abuse_data.abuseConfidenceScore or 0
    local min_confidence = config.abuseipdb.min_confidence or 25

    if confidence < min_confidence then
        return {
            score = 0,
            source = "abuseipdb",
            confidence = confidence,
            total_reports = abuse_data.totalReports or 0,
        }
    end

    local multiplier = config.abuseipdb.score_multiplier or 0.5
    return {
        score = math.floor(confidence * multiplier),
        source = "abuseipdb",
        confidence = confidence,
        total_reports = abuse_data.totalReports or 0,
        country_code = abuse_data.countryCode,
        isp = abuse_data.isp,
        usage_type = abuse_data.usageType,
        is_tor = abuse_data.isTor,
    }
end

-- Query custom webhook
local function check_webhook(ip, config)
    if not config.webhook or not config.webhook.enabled then
        return nil
    end

    local url = config.webhook.url
    if not url or url == "" then
        return nil
    end

    local httpc = http.new()
    httpc:set_timeout(config.webhook.timeout or 2000)

    -- Build request URL with IP
    local request_url = url
    if url:find("?") then
        request_url = url .. "&ip=" .. ngx.escape_uri(ip)
    else
        request_url = url .. "?ip=" .. ngx.escape_uri(ip)
    end

    local headers = config.webhook.headers or {}
    headers["Accept"] = "application/json"

    local res, err = httpc:request_uri(request_url, {
        method = "GET",
        headers = headers,
    })

    if not res then
        ngx.log(ngx.WARN, "ip_reputation: webhook request failed: ", err)
        return nil
    end

    if res.status ~= 200 then
        return nil
    end

    local data = cjson.decode(res.body)
    if not data then
        return nil
    end

    -- Expect response format: { score: 0-100, reason: "...", blocked: true/false }
    return {
        score = data.score or 0,
        source = "webhook",
        reason = data.reason,
        blocked = data.blocked,
        metadata = data.metadata,
    }
end

-- Main check function
-- Returns: { score = number, blocked = boolean, reason = string, flags = {}, details = {} }
function _M.check_ip(ip, endpoint_config)
    local result = {
        score = 0,
        blocked = false,
        reason = nil,
        flags = {},
        details = {},
    }

    local config = _M.get_config()

    if not config.enabled then
        return result
    end

    -- Get Redis connection
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    if not redis then
        return result
    end

    -- Check cache first
    local cached = get_cached_reputation(redis, ip)
    if cached then
        result.score = cached.score or 0
        result.details = cached
        result.details.cached = true

        if result.score >= config.block_score then
            result.blocked = true
            result.reason = "reputation_blocked"
            table.insert(result.flags, "reputation:blocked:" .. (cached.source or "cached"))
        elseif result.score >= config.flag_score then
            result.score = config.flag_score_addition
            table.insert(result.flags, "reputation:flagged:" .. (cached.source or "cached"))
        else
            result.score = 0  -- Below threshold, no score addition
        end

        return result
    end

    -- Check all providers and use highest score
    local highest_score = 0
    local highest_result = nil

    -- 1. Local blocklist (instant block)
    local local_result = check_local_blocklist(redis, ip, config)
    if local_result and local_result.score > highest_score then
        highest_score = local_result.score
        highest_result = local_result
    end

    -- 2. AbuseIPDB (if not already blocked)
    if highest_score < config.block_score then
        local abuse_result = check_abuseipdb(ip, config)
        if abuse_result and abuse_result.score > highest_score then
            highest_score = abuse_result.score
            highest_result = abuse_result
        end
    end

    -- 3. Custom webhook (if not already blocked)
    if highest_score < config.block_score then
        local webhook_result = check_webhook(ip, config)
        if webhook_result then
            if webhook_result.blocked then
                highest_score = 100
                highest_result = webhook_result
            elseif webhook_result.score > highest_score then
                highest_score = webhook_result.score
                highest_result = webhook_result
            end
        end
    end

    -- Build final result
    if highest_result then
        result.details = highest_result

        -- Cache the result
        cache_reputation(redis, ip, highest_result, config)

        if highest_score >= config.block_score then
            result.blocked = true
            result.reason = "reputation_blocked"
            result.score = 0  -- Blocked, no score needed
            table.insert(result.flags, "reputation:blocked:" .. highest_result.source)
        elseif highest_score >= config.flag_score then
            result.score = config.flag_score_addition
            table.insert(result.flags, "reputation:flagged:" .. highest_result.source)
        end
    else
        -- No reputation data, cache as clean
        cache_reputation(redis, ip, { score = 0, source = "none" }, config)
    end

    return result
end

-- Add IP to local blocklist
function _M.add_to_blocklist(ip, reason)
    local config = _M.get_config()
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    if not redis then
        return false, "Redis not available"
    end

    local redis_key = config.local_blocklist.redis_key or "waf:reputation:blocked_ips"
    redis:sadd(redis_key, ip)

    -- Clear cache for this IP
    redis:del("waf:reputation:cache:" .. ip)

    ngx.log(ngx.INFO, "ip_reputation: added ", ip, " to blocklist: ", reason or "manual")
    return true
end

-- Remove IP from local blocklist
function _M.remove_from_blocklist(ip)
    local config = _M.get_config()
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    if not redis then
        return false, "Redis not available"
    end

    local redis_key = config.local_blocklist.redis_key or "waf:reputation:blocked_ips"
    redis:srem(redis_key, ip)

    -- Clear cache for this IP
    redis:del("waf:reputation:cache:" .. ip)

    return true
end

-- Get blocklist
function _M.get_blocklist()
    local config = _M.get_config()
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    if not redis then
        -- Return empty array that serializes as [] not {}
        return setmetatable({}, cjson.array_mt)
    end

    local redis_key = config.local_blocklist.redis_key or "waf:reputation:blocked_ips"
    local result = redis:smembers(redis_key)

    -- Ensure result serializes as JSON array even when empty
    if not result or type(result) ~= "table" or #result == 0 then
        return setmetatable({}, cjson.array_mt)
    end

    return result
end

-- Clear cache for IP
function _M.clear_cache(ip)
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    if redis then
        redis:del("waf:reputation:cache:" .. ip)
    end
end

-- Get status for admin API
function _M.get_status()
    local config = _M.get_config()
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    local blocklist_count = 0
    if redis then
        local redis_key = config.local_blocklist.redis_key or "waf:reputation:blocked_ips"
        blocklist_count = redis:scard(redis_key) or 0
    end

    return {
        enabled = config.enabled,
        providers = {
            local_blocklist = config.local_blocklist and config.local_blocklist.enabled,
            abuseipdb = config.abuseipdb and config.abuseipdb.enabled and config.abuseipdb.api_key ~= nil,
            webhook = config.webhook and config.webhook.enabled and config.webhook.url ~= nil,
        },
        blocklist_count = blocklist_count,
        block_score = config.block_score,
        flag_score = config.flag_score,
    }
end

return _M
