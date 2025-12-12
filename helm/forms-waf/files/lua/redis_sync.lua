-- redis_sync.lua
-- Synchronizes keyword lists, configuration, and endpoint configs from Redis

local _M = {}

local redis = require "resty.redis"
local cjson = require "cjson.safe"
local keyword_filter = require "keyword_filter"
local endpoint_matcher = require "endpoint_matcher"

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
    -- Endpoint configuration keys
    endpoint_index = "waf:endpoints:index",
    endpoint_config_prefix = "waf:endpoints:config:",
    endpoint_paths_exact = "waf:endpoints:paths:exact",
    endpoint_paths_prefix = "waf:endpoints:paths:prefix",
    endpoint_paths_regex = "waf:endpoints:paths:regex",
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

-- Sync endpoint index (list of all endpoint IDs)
local function sync_endpoint_index(red)
    -- Get all endpoint IDs from sorted set (ordered by priority)
    local endpoints, err = red:zrange(KEYS.endpoint_index, 0, -1)
    if not endpoints then
        ngx.log(ngx.WARN, "Failed to get endpoint index: ", err)
        return {}
    end

    if type(endpoints) == "table" and #endpoints > 0 then
        local json_data = cjson.encode(endpoints)
        endpoint_matcher.update_cache("endpoint_index", json_data, 120)
        ngx.log(ngx.DEBUG, "Synced ", #endpoints, " endpoint IDs")
        return endpoints
    else
        endpoint_matcher.update_cache("endpoint_index", "[]", 120)
        return {}
    end
end

-- Sync exact path mappings
local function sync_exact_paths(red)
    local paths, err = red:hgetall(KEYS.endpoint_paths_exact)
    if not paths then
        ngx.log(ngx.WARN, "Failed to get exact paths: ", err)
        return
    end

    local path_map = {}
    if type(paths) == "table" then
        for i = 1, #paths, 2 do
            local path_key = paths[i]
            local endpoint_id = paths[i + 1]
            if path_key and endpoint_id then
                path_map[path_key] = endpoint_id
            end
        end
    end

    local json_data = cjson.encode(path_map)
    endpoint_matcher.update_cache("exact_paths", json_data, 120)
    ngx.log(ngx.DEBUG, "Synced exact path mappings")
end

-- Sync prefix patterns
local function sync_prefix_patterns(red)
    -- Prefix patterns stored as sorted set with format "prefix:method:endpoint_id"
    local patterns, err = red:zrange(KEYS.endpoint_paths_prefix, 0, -1, "WITHSCORES")
    if not patterns then
        ngx.log(ngx.WARN, "Failed to get prefix patterns: ", err)
        return
    end

    local prefix_list = {}
    if type(patterns) == "table" then
        -- Patterns come as [value, score, value, score, ...]
        for i = 1, #patterns, 2 do
            local pattern_str = patterns[i]
            local priority = tonumber(patterns[i + 1]) or 100

            -- Parse pattern: "prefix|method|endpoint_id"
            local prefix, method, endpoint_id = pattern_str:match("^(.+)|([^|]+)|([^|]+)$")
            if prefix and endpoint_id then
                table.insert(prefix_list, {
                    prefix = prefix,
                    method = method or "*",
                    endpoint_id = endpoint_id,
                    priority = priority
                })
            end
        end

        -- Sort by prefix length (longest first) for specificity
        table.sort(prefix_list, function(a, b)
            if #a.prefix == #b.prefix then
                return a.priority < b.priority
            end
            return #a.prefix > #b.prefix
        end)
    end

    local json_data = cjson.encode(prefix_list)
    endpoint_matcher.update_cache("prefix_patterns", json_data, 120)
    ngx.log(ngx.DEBUG, "Synced ", #prefix_list, " prefix patterns")
end

-- Sync regex patterns
local function sync_regex_patterns(red)
    -- Regex patterns stored as list with JSON objects
    local patterns, err = red:lrange(KEYS.endpoint_paths_regex, 0, -1)
    if not patterns then
        ngx.log(ngx.WARN, "Failed to get regex patterns: ", err)
        return
    end

    local regex_list = {}
    if type(patterns) == "table" then
        for _, pattern_json in ipairs(patterns) do
            local pattern = cjson.decode(pattern_json)
            if pattern and pattern.pattern and pattern.endpoint_id then
                -- Validate regex pattern
                local ok, err = pcall(ngx.re.match, "", pattern.pattern)
                if ok then
                    table.insert(regex_list, {
                        pattern = pattern.pattern,
                        method = pattern.method or "*",
                        endpoint_id = pattern.endpoint_id,
                        priority = pattern.priority or 100
                    })
                else
                    ngx.log(ngx.WARN, "Invalid regex pattern: ", pattern.pattern, " - ", err)
                end
            end
        end

        -- Sort by priority
        table.sort(regex_list, function(a, b)
            return a.priority < b.priority
        end)
    end

    local json_data = cjson.encode(regex_list)
    endpoint_matcher.update_cache("regex_patterns", json_data, 120)
    ngx.log(ngx.DEBUG, "Synced ", #regex_list, " regex patterns")
end

-- Sync individual endpoint configuration
local function sync_endpoint_config(red, endpoint_id)
    local config_key = KEYS.endpoint_config_prefix .. endpoint_id
    local config_json, err = red:get(config_key)

    if not config_json or config_json == ngx.null then
        ngx.log(ngx.DEBUG, "No config found for endpoint: ", endpoint_id)
        return nil
    end

    local config = cjson.decode(config_json)
    if config then
        endpoint_matcher.cache_config(endpoint_id, config, 120)
        ngx.log(ngx.DEBUG, "Synced config for endpoint: ", endpoint_id)
        return config
    end

    return nil
end

-- Sync all endpoint configurations
local function sync_endpoints(red)
    -- First sync the index to get all endpoint IDs
    local endpoint_ids = sync_endpoint_index(red)

    -- Sync path mappings
    sync_exact_paths(red)
    sync_prefix_patterns(red)
    sync_regex_patterns(red)

    -- Sync individual endpoint configs
    local synced_count = 0
    for _, endpoint_id in ipairs(endpoint_ids) do
        local config = sync_endpoint_config(red, endpoint_id)
        if config then
            synced_count = synced_count + 1
        end
    end

    ngx.log(ngx.DEBUG, "Synced ", synced_count, " endpoint configurations")
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

    -- Sync endpoint configurations
    sync_endpoints(red)

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
        endpoint_stats = endpoint_matcher.get_stats(),
    }
end

-- Get Redis keys (for admin API)
function _M.get_keys()
    return KEYS
end

-- Expose sync functions for admin API
function _M.sync_endpoint(endpoint_id)
    local red, err = get_redis_connection()
    if not red then
        return nil, err
    end

    local config = sync_endpoint_config(red, endpoint_id)
    close_redis(red)

    return config
end

return _M
