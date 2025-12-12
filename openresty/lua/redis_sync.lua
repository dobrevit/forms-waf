-- redis_sync.lua
-- Synchronizes keyword lists and configuration from Redis

local _M = {}

local redis = require "resty.redis"
local keyword_filter = require "keyword_filter"

-- Configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil
local REDIS_DB = tonumber(os.getenv("REDIS_DB")) or 0

-- Sync interval in seconds
local SYNC_INTERVAL = tonumber(os.getenv("WAF_SYNC_INTERVAL")) or 30

-- Redis keys
local KEYS = {
    blocked_keywords = "waf:keywords:blocked",
    flagged_keywords = "waf:keywords:flagged",
    blocked_hashes = "waf:hashes:blocked",
    thresholds = "waf:config:thresholds",
    ip_whitelist = "waf:whitelist:ips",
}

-- Shared dictionaries
local config_cache = ngx.shared.config_cache
local ip_whitelist = ngx.shared.ip_whitelist

-- Get Redis connection
local function get_redis_connection()
    local red = redis:new()
    red:set_timeout(2000) -- 2 second timeout

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        return nil, "failed to connect to Redis: " .. (err or "unknown")
    end

    if REDIS_PASSWORD and REDIS_PASSWORD ~= "" then
        local res, err = red:auth(REDIS_PASSWORD)
        if not res then
            red:close()
            return nil, "Redis auth failed: " .. (err or "unknown")
        end
    end

    if REDIS_DB and REDIS_DB > 0 then
        local res, err = red:select(REDIS_DB)
        if not res then
            red:close()
            return nil, "Redis select failed: " .. (err or "unknown")
        end
    end

    return red
end

-- Return connection to pool
local function close_redis(red)
    if not red then return end

    local ok, err = red:set_keepalive(10000, 100) -- 10s max idle, 100 connections
    if not ok then
        red:close()
    end
end

-- Sync blocked keywords
local function sync_blocked_keywords(red)
    local keywords, err = red:smembers(KEYS.blocked_keywords)
    if not keywords then
        ngx.log(ngx.WARN, "Failed to get blocked keywords: ", err)
        return
    end

    if type(keywords) == "table" and #keywords > 0 then
        local data = table.concat(keywords, "|")
        keyword_filter.update_cache("blocked_keywords", data)
        ngx.log(ngx.DEBUG, "Synced ", #keywords, " blocked keywords")
    else
        keyword_filter.update_cache("blocked_keywords", "")
    end
end

-- Sync flagged keywords (with scores)
local function sync_flagged_keywords(red)
    -- Use HGETALL if stored as hash with scores, or SMEMBERS if set
    local keywords, err = red:smembers(KEYS.flagged_keywords)
    if not keywords then
        ngx.log(ngx.WARN, "Failed to get flagged keywords: ", err)
        return
    end

    if type(keywords) == "table" and #keywords > 0 then
        local data = table.concat(keywords, "|")
        keyword_filter.update_cache("flagged_keywords", data)
        ngx.log(ngx.DEBUG, "Synced ", #keywords, " flagged keywords")
    else
        keyword_filter.update_cache("flagged_keywords", "")
    end
end

-- Sync blocked hashes
local function sync_blocked_hashes(red)
    local hashes, err = red:smembers(KEYS.blocked_hashes)
    if not hashes then
        ngx.log(ngx.WARN, "Failed to get blocked hashes: ", err)
        return
    end

    if type(hashes) == "table" and #hashes > 0 then
        local data = table.concat(hashes, "|")
        keyword_filter.update_cache("blocked_hashes", data)
        ngx.log(ngx.DEBUG, "Synced ", #hashes, " blocked hashes")
    else
        keyword_filter.update_cache("blocked_hashes", "")
    end
end

-- Sync configuration thresholds
local function sync_thresholds(red)
    local config, err = red:hgetall(KEYS.thresholds)
    if not config then
        ngx.log(ngx.WARN, "Failed to get thresholds: ", err)
        return
    end

    if type(config) == "table" then
        local thresholds = {}
        for i = 1, #config, 2 do
            local key = config[i]
            local value = tonumber(config[i + 1])
            if key and value then
                thresholds[key] = value
            end
        end

        -- Store as JSON
        local cjson = require "cjson.safe"
        config_cache:set("thresholds", cjson.encode(thresholds), 120)
        ngx.log(ngx.DEBUG, "Synced thresholds")
    end
end

-- Sync IP whitelist
local function sync_ip_whitelist(red)
    local ips, err = red:smembers(KEYS.ip_whitelist)
    if not ips then
        ngx.log(ngx.WARN, "Failed to get IP whitelist: ", err)
        return
    end

    -- Clear existing whitelist
    ip_whitelist:flush_all()

    if type(ips) == "table" then
        for _, ip in ipairs(ips) do
            ip_whitelist:set(ip, true, 120)
        end
        ngx.log(ngx.DEBUG, "Synced ", #ips, " whitelisted IPs")
    end
end

-- Main sync function
local function do_sync()
    local red, err = get_redis_connection()
    if not red then
        ngx.log(ngx.WARN, "Redis sync failed: ", err)
        return
    end

    -- Perform all syncs
    sync_blocked_keywords(red)
    sync_flagged_keywords(red)
    sync_blocked_hashes(red)
    sync_thresholds(red)
    sync_ip_whitelist(red)

    close_redis(red)

    ngx.log(ngx.INFO, "Redis sync completed")
end

-- Timer handler
local function sync_timer_handler(premature)
    if premature then
        return
    end

    -- Run sync in protected call
    local ok, err = pcall(do_sync)
    if not ok then
        ngx.log(ngx.ERR, "Sync error: ", err)
    end

    -- Reschedule timer
    local ok, err = ngx.timer.at(SYNC_INTERVAL, sync_timer_handler)
    if not ok then
        ngx.log(ngx.ERR, "Failed to reschedule sync timer: ", err)
    end
end

-- Start the sync timer (called from init_worker)
function _M.start_sync_timer()
    -- Only start on worker 0 to avoid duplicate syncs
    -- Actually, let each worker sync its own shared dict
    local ok, err = ngx.timer.at(0, sync_timer_handler)
    if not ok then
        ngx.log(ngx.ERR, "Failed to start sync timer: ", err)
        return
    end
    ngx.log(ngx.INFO, "Redis sync timer started with interval: ", SYNC_INTERVAL, "s")
end

-- Manual sync trigger
function _M.sync_now()
    do_sync()
end

-- Get sync status
function _M.get_status()
    return {
        redis_host = REDIS_HOST,
        redis_port = REDIS_PORT,
        sync_interval = SYNC_INTERVAL,
        filter_stats = keyword_filter.get_stats(),
    }
end

return _M
