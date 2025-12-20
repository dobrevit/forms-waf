-- redis_sync.lua
-- Synchronizes keyword lists, configuration, endpoint configs, and vhost configs from Redis

local _M = {}

local redis = require "resty.redis"
local cjson = require "cjson.safe"
local keyword_filter = require "keyword_filter"
local endpoint_matcher = require "endpoint_matcher"
local vhost_matcher = require "vhost_matcher"
local field_learner = require "field_learner"
local behavioral_tracker = require "behavioral_tracker"

-- Lazy load instance_coordinator to avoid circular dependency
local instance_coordinator = nil
local function get_instance_coordinator()
    if not instance_coordinator then
        instance_coordinator = require "instance_coordinator"
    end
    return instance_coordinator
end

-- Lazy load captcha_handler to avoid circular dependency
local captcha_handler = nil
local function get_captcha_handler()
    if not captcha_handler then
        captcha_handler = require "captcha_handler"
    end
    return captcha_handler
end

-- Lazy load fingerprint_profiles to avoid circular dependency
local fingerprint_profiles = nil
local function get_fingerprint_profiles()
    if not fingerprint_profiles then
        fingerprint_profiles = require "fingerprint_profiles"
    end
    return fingerprint_profiles
end

-- Configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil
local REDIS_DB = tonumber(os.getenv("REDIS_DB")) or 0

-- Sync interval in seconds
local SYNC_INTERVAL = tonumber(os.getenv("WAF_SYNC_INTERVAL")) or 30

-- HAProxy routing defaults from environment
local HAPROXY_UPSTREAM = os.getenv("HAPROXY_UPSTREAM") or "haproxy:80"
local HAPROXY_UPSTREAM_SSL = os.getenv("HAPROXY_UPSTREAM_SSL") or "haproxy:443"
local UPSTREAM_SSL = os.getenv("UPSTREAM_SSL") or "false"
local HAPROXY_TIMEOUT = os.getenv("HAPROXY_TIMEOUT") or "30"

-- Redis keys
local KEYS = {
    blocked_keywords = "waf:keywords:blocked",
    flagged_keywords = "waf:keywords:flagged",
    blocked_hashes = "waf:hashes:blocked",
    thresholds = "waf:config:thresholds",
    routing = "waf:config:routing",
    ip_whitelist = "waf:whitelist:ips",
    -- Endpoint configuration keys
    endpoint_index = "waf:endpoints:index",
    endpoint_config_prefix = "waf:endpoints:config:",
    endpoint_paths_exact = "waf:endpoints:paths:exact",
    endpoint_paths_prefix = "waf:endpoints:paths:prefix",
    endpoint_paths_regex = "waf:endpoints:paths:regex",
    -- Virtual host configuration keys
    vhost_index = "waf:vhosts:index",
    vhost_config_prefix = "waf:vhosts:config:",
    vhost_hosts_exact = "waf:vhosts:hosts:exact",
    vhost_hosts_wildcard = "waf:vhosts:hosts:wildcard",
    -- CAPTCHA configuration keys
    captcha_providers_index = "waf:captcha:providers:index",
    captcha_providers_config_prefix = "waf:captcha:providers:config:",
    captcha_config = "waf:captcha:config",
    -- Fingerprint profile keys
    fingerprint_profiles_index = "waf:fingerprint:profiles:index",
    fingerprint_profiles_config_prefix = "waf:fingerprint:profiles:config:",
    fingerprint_profiles_builtin = "waf:fingerprint:profiles:builtin",
}

-- Shared dictionaries
local config_cache = ngx.shared.config_cache
local ip_whitelist = ngx.shared.ip_whitelist
local ip_whitelist_cidr = ngx.shared.ip_whitelist_cidr

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

-- Helper to parse threshold value (handles numbers and booleans)
local function parse_threshold_value(value_str)
    if value_str == "true" then
        return true
    elseif value_str == "false" then
        return false
    else
        return tonumber(value_str)
    end
end

-- Helper to serialize threshold value for Redis (handles booleans properly)
local function serialize_threshold_value(value)
    if type(value) == "boolean" then
        return value and "true" or "false"
    else
        return tostring(value)
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
            local value = parse_threshold_value(config[i + 1])
            if key and value ~= nil then
                thresholds[key] = value
            end
        end

        -- Store as JSON
        local cjson = require "cjson.safe"
        config_cache:set("thresholds", cjson.encode(thresholds), 120)
        ngx.log(ngx.DEBUG, "Synced thresholds")
    end
end

-- Sync routing configuration
local function sync_routing(red)
    local config, err = red:hgetall(KEYS.routing)
    if not config then
        ngx.log(ngx.WARN, "Failed to get routing config: ", err)
        return
    end

    -- Start with env variable defaults
    local routing = {
        haproxy_upstream = HAPROXY_UPSTREAM,
        haproxy_upstream_ssl = HAPROXY_UPSTREAM_SSL,
        upstream_ssl = UPSTREAM_SSL == "true",
        haproxy_timeout = tonumber(HAPROXY_TIMEOUT) or 30,
    }

    -- Override with Redis values if present
    if type(config) == "table" and #config > 0 then
        for i = 1, #config, 2 do
            local key = config[i]
            local value = config[i + 1]
            if key and value then
                -- Handle boolean conversion for upstream_ssl
                if key == "upstream_ssl" then
                    routing[key] = value == "true"
                else
                    -- Try to convert to number if applicable
                    local num_value = tonumber(value)
                    routing[key] = num_value or value
                end
            end
        end
    end

    -- Store as JSON
    config_cache:set("routing", cjson.encode(routing), 120)
    ngx.log(ngx.DEBUG, "Synced routing config: haproxy_upstream=", routing.haproxy_upstream)
end

-- Sync IP allowlist (separates exact IPs from CIDR ranges)
local function sync_ip_whitelist(red)
    local ips, err = red:smembers(KEYS.ip_whitelist)
    if not ips then
        ngx.log(ngx.WARN, "Failed to get IP allowlist: ", err)
        return
    end

    -- Clear existing allowlist
    ip_whitelist:flush_all()

    -- Separate exact IPs from CIDR ranges
    local cidr_list = {}
    local exact_count = 0

    if type(ips) == "table" then
        for _, ip in ipairs(ips) do
            if ip:match("/%d+$") then
                -- CIDR notation -> store in CIDR list
                table.insert(cidr_list, ip)
            else
                -- Exact IP -> store in shared dict for fast O(1) lookup
                ip_whitelist:set(ip, true, 120)
                exact_count = exact_count + 1
            end
        end

        -- Store CIDR list as JSON in separate cache
        if ip_whitelist_cidr then
            ip_whitelist_cidr:set("cidrs", cjson.encode(cidr_list), 120)
        end

        ngx.log(ngx.DEBUG, "Synced IP allowlist: ", exact_count, " exact IPs, ", #cidr_list, " CIDR ranges")
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

-- ============================================================================
-- Vhost-specific Endpoint Sync Functions
-- ============================================================================

-- Sync vhost-specific endpoint index
local function sync_vhost_endpoint_index(red, vhost_id)
    local key = "waf:vhosts:endpoints:" .. vhost_id .. ":index"
    local endpoints, err = red:zrange(key, 0, -1)
    if not endpoints then
        ngx.log(ngx.DEBUG, "Failed to get vhost endpoint index for ", vhost_id, ": ", err)
        return {}
    end

    local cache_key = "vhost_endpoint_index:" .. vhost_id
    if type(endpoints) == "table" and #endpoints > 0 then
        local json_data = cjson.encode(endpoints)
        endpoint_matcher.update_cache(cache_key, json_data, 120)
        ngx.log(ngx.DEBUG, "Synced ", #endpoints, " vhost-specific endpoint IDs for ", vhost_id)
        return endpoints
    else
        endpoint_matcher.update_cache(cache_key, "[]", 120)
        return {}
    end
end

-- Sync vhost-specific exact path mappings
local function sync_vhost_exact_paths(red, vhost_id)
    local key = "waf:vhosts:endpoints:" .. vhost_id .. ":paths:exact"
    local paths, err = red:hgetall(key)
    if not paths then
        ngx.log(ngx.DEBUG, "Failed to get vhost exact paths for ", vhost_id, ": ", err)
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

    local cache_key = "vhost_exact_paths:" .. vhost_id
    local json_data = cjson.encode(path_map)
    endpoint_matcher.update_cache(cache_key, json_data, 120)
    ngx.log(ngx.DEBUG, "Synced vhost exact path mappings for ", vhost_id)
end

-- Sync vhost-specific prefix patterns
local function sync_vhost_prefix_patterns(red, vhost_id)
    local key = "waf:vhosts:endpoints:" .. vhost_id .. ":paths:prefix"
    local patterns, err = red:zrange(key, 0, -1, "WITHSCORES")
    if not patterns then
        ngx.log(ngx.DEBUG, "Failed to get vhost prefix patterns for ", vhost_id, ": ", err)
        return
    end

    local prefix_list = {}
    if type(patterns) == "table" then
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

    local cache_key = "vhost_prefix_patterns:" .. vhost_id
    local json_data = cjson.encode(prefix_list)
    endpoint_matcher.update_cache(cache_key, json_data, 120)
    ngx.log(ngx.DEBUG, "Synced ", #prefix_list, " vhost prefix patterns for ", vhost_id)
end

-- Sync vhost-specific regex patterns
local function sync_vhost_regex_patterns(red, vhost_id)
    local key = "waf:vhosts:endpoints:" .. vhost_id .. ":paths:regex"
    local patterns, err = red:lrange(key, 0, -1)
    if not patterns then
        ngx.log(ngx.DEBUG, "Failed to get vhost regex patterns for ", vhost_id, ": ", err)
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
                    ngx.log(ngx.WARN, "Invalid vhost regex pattern: ", pattern.pattern, " - ", err)
                end
            end
        end

        -- Sort by priority
        table.sort(regex_list, function(a, b)
            return a.priority < b.priority
        end)
    end

    local cache_key = "vhost_regex_patterns:" .. vhost_id
    local json_data = cjson.encode(regex_list)
    endpoint_matcher.update_cache(cache_key, json_data, 120)
    ngx.log(ngx.DEBUG, "Synced ", #regex_list, " vhost regex patterns for ", vhost_id)
end

-- Sync all vhost-specific endpoint data for a single vhost
local function sync_vhost_endpoints(red, vhost_id)
    sync_vhost_endpoint_index(red, vhost_id)
    sync_vhost_exact_paths(red, vhost_id)
    sync_vhost_prefix_patterns(red, vhost_id)
    sync_vhost_regex_patterns(red, vhost_id)
end

-- Sync all vhost-specific endpoints for all vhosts
local function sync_all_vhost_endpoints(red, vhost_ids)
    if not vhost_ids or #vhost_ids == 0 then
        return
    end

    for _, vhost_id in ipairs(vhost_ids) do
        sync_vhost_endpoints(red, vhost_id)
    end

    ngx.log(ngx.DEBUG, "Synced vhost-specific endpoints for ", #vhost_ids, " vhosts")
end

-- ============================================================================
-- Virtual Host Sync Functions
-- ============================================================================

-- Sync vhost index (list of all vhost IDs)
local function sync_vhost_index(red)
    -- Get all vhost IDs from sorted set (ordered by priority)
    local vhosts, err = red:zrange(KEYS.vhost_index, 0, -1)
    if not vhosts then
        ngx.log(ngx.WARN, "Failed to get vhost index: ", err)
        return {}
    end

    if type(vhosts) == "table" and #vhosts > 0 then
        local json_data = cjson.encode(vhosts)
        vhost_matcher.update_cache("vhost_index", json_data, 120)
        ngx.log(ngx.DEBUG, "Synced ", #vhosts, " vhost IDs")
        return vhosts
    else
        vhost_matcher.update_cache("vhost_index", "[]", 120)
        return {}
    end
end

-- Sync exact hostname mappings
local function sync_exact_hosts(red)
    local hosts, err = red:hgetall(KEYS.vhost_hosts_exact)
    if not hosts then
        ngx.log(ngx.WARN, "Failed to get exact hosts: ", err)
        return
    end

    local host_map = {}
    if type(hosts) == "table" then
        for i = 1, #hosts, 2 do
            local hostname = hosts[i]
            local vhost_id = hosts[i + 1]
            if hostname and vhost_id then
                host_map[hostname:lower()] = vhost_id
            end
        end
    end

    local json_data = cjson.encode(host_map)
    vhost_matcher.update_cache("exact_hosts", json_data, 120)
    ngx.log(ngx.DEBUG, "Synced exact host mappings")
end

-- Sync wildcard host patterns
local function sync_wildcard_patterns(red)
    -- Wildcard patterns stored as sorted set with format "pattern|vhost_id"
    local patterns, err = red:zrange(KEYS.vhost_hosts_wildcard, 0, -1, "WITHSCORES")
    if not patterns then
        ngx.log(ngx.WARN, "Failed to get wildcard patterns: ", err)
        return
    end

    local wildcard_list = {}
    if type(patterns) == "table" then
        -- Patterns come as [value, score, value, score, ...]
        for i = 1, #patterns, 2 do
            local pattern_str = patterns[i]
            local priority = tonumber(patterns[i + 1]) or 100

            -- Parse pattern: "*.example.com|vhost_id"
            local pattern, vhost_id = pattern_str:match("^(.+)|([^|]+)$")
            if pattern and vhost_id then
                table.insert(wildcard_list, {
                    pattern = pattern:lower(),
                    vhost_id = vhost_id,
                    priority = priority
                })
            end
        end

        -- Sort by pattern specificity (longer patterns first, then by priority)
        table.sort(wildcard_list, function(a, b)
            if #a.pattern == #b.pattern then
                return a.priority < b.priority
            end
            return #a.pattern > #b.pattern
        end)
    end

    local json_data = cjson.encode(wildcard_list)
    vhost_matcher.update_cache("wildcard_patterns", json_data, 120)
    ngx.log(ngx.DEBUG, "Synced ", #wildcard_list, " wildcard host patterns")
end

-- Sync individual vhost configuration
local function sync_vhost_config(red, vhost_id)
    local config_key = KEYS.vhost_config_prefix .. vhost_id
    local config_json, err = red:get(config_key)

    if not config_json or config_json == ngx.null then
        ngx.log(ngx.DEBUG, "No config found for vhost: ", vhost_id)
        return nil
    end

    local config = cjson.decode(config_json)
    if config then
        vhost_matcher.cache_config(vhost_id, config, 120)
        ngx.log(ngx.DEBUG, "Synced config for vhost: ", vhost_id)
        return config
    end

    return nil
end

-- Sync all vhost configurations
local function sync_vhosts(red)
    -- First sync the index to get all vhost IDs
    local vhost_ids = sync_vhost_index(red)

    -- Sync host mappings
    sync_exact_hosts(red)
    sync_wildcard_patterns(red)

    -- Sync individual vhost configs
    local synced_count = 0
    for _, vhost_id in ipairs(vhost_ids) do
        local config = sync_vhost_config(red, vhost_id)
        if config then
            synced_count = synced_count + 1
        end
    end

    -- Also sync the default vhost if it exists
    local default_config = sync_vhost_config(red, "_default")
    if default_config then
        synced_count = synced_count + 1
    end

    -- Sync vhost-specific endpoints for all vhosts
    sync_all_vhost_endpoints(red, vhost_ids)

    ngx.log(ngx.DEBUG, "Synced ", synced_count, " vhost configurations")
end

-- ============================================================================
-- CAPTCHA Configuration Sync Functions
-- ============================================================================

-- Sync CAPTCHA global configuration
local function sync_captcha_config(red)
    local config, err = red:hgetall(KEYS.captcha_config)
    if not config then
        ngx.log(ngx.DEBUG, "Failed to get CAPTCHA config: ", err)
        return
    end

    local captcha_config = {}
    if type(config) == "table" then
        for i = 1, #config, 2 do
            local key = config[i]
            local value = config[i + 1]
            if key and value then
                -- Parse JSON values
                if value:match("^[%[{]") then
                    captcha_config[key] = cjson.decode(value) or value
                elseif value == "true" then
                    captcha_config[key] = true
                elseif value == "false" then
                    captcha_config[key] = false
                elseif tonumber(value) then
                    captcha_config[key] = tonumber(value)
                else
                    captcha_config[key] = value
                end
            end
        end
    end

    -- Apply defaults if not set
    local defaults = {
        enabled = false,
        default_provider = nil,
        trust_duration = 86400,
        challenge_ttl = 600,
        fallback_action = "block",
        cookie_name = "waf_trust",
        cookie_secure = true,
        cookie_httponly = true,
        cookie_samesite = "Strict",
    }

    for key, default_value in pairs(defaults) do
        if captcha_config[key] == nil then
            captcha_config[key] = default_value
        end
    end

    -- Update captcha_handler's cached config
    get_captcha_handler().update_config(captcha_config)
    ngx.log(ngx.DEBUG, "Synced CAPTCHA global config")
end

-- Sync individual CAPTCHA provider configuration
local function sync_captcha_provider(red, provider_id)
    local config_key = KEYS.captcha_providers_config_prefix .. provider_id
    local config_json, err = red:get(config_key)

    if not config_json or config_json == ngx.null then
        ngx.log(ngx.DEBUG, "No config found for CAPTCHA provider: ", provider_id)
        return nil
    end

    local config = cjson.decode(config_json)
    if config then
        get_captcha_handler().cache_provider(provider_id, config)
        ngx.log(ngx.DEBUG, "Synced config for CAPTCHA provider: ", provider_id)
        return config
    end

    return nil
end

-- Sync all CAPTCHA providers
local function sync_captcha_providers(red)
    -- Get all provider IDs from sorted set (ordered by priority)
    local provider_ids, err = red:zrange(KEYS.captcha_providers_index, 0, -1)
    if not provider_ids then
        ngx.log(ngx.DEBUG, "Failed to get CAPTCHA providers index: ", err)
        return
    end

    -- Clear existing cached providers and rebuild
    get_captcha_handler().clear_providers_cache()

    local synced_count = 0
    if type(provider_ids) == "table" then
        for _, provider_id in ipairs(provider_ids) do
            local config = sync_captcha_provider(red, provider_id)
            if config then
                synced_count = synced_count + 1
            end
        end
    end

    -- Also cache the provider index for quick lookups
    get_captcha_handler().update_provider_index(provider_ids or {})

    ngx.log(ngx.DEBUG, "Synced ", synced_count, " CAPTCHA providers")
end

-- Sync all CAPTCHA configuration (global config + providers)
local function sync_captcha(red)
    sync_captcha_config(red)
    sync_captcha_providers(red)
end

-- ============================================================================
-- Fingerprint Profile Sync Functions
-- ============================================================================

-- Sync all fingerprint profiles from Redis
local function sync_fingerprint_profiles(red)
    -- Get all profile IDs from sorted set (ordered by priority)
    local profile_ids, err = red:zrange(KEYS.fingerprint_profiles_index, 0, -1)
    if not profile_ids then
        ngx.log(ngx.DEBUG, "Failed to get fingerprint profiles index: ", err)
        return
    end

    local profiles = {}
    local synced_count = 0

    if type(profile_ids) == "table" then
        for _, profile_id in ipairs(profile_ids) do
            local config_key = KEYS.fingerprint_profiles_config_prefix .. profile_id
            local config_json, get_err = red:get(config_key)

            if config_json and config_json ~= ngx.null then
                local config = cjson.decode(config_json)
                if config then
                    table.insert(profiles, config)
                    synced_count = synced_count + 1
                end
            end
        end
    end

    -- Cache all profiles via fingerprint_profiles module
    get_fingerprint_profiles().cache_all_profiles(profiles, 120)

    ngx.log(ngx.DEBUG, "Synced ", synced_count, " fingerprint profiles")
end

-- Sync webhook configuration
local function sync_webhooks(red)
    local config_str = red:get("waf:webhooks:config")

    if config_str and config_str ~= ngx.null then
        local ok, webhooks = pcall(require, "webhooks")
        if ok and webhooks then
            local config = cjson.decode(config_str)
            if config then
                webhooks.update_config(config)
                ngx.log(ngx.DEBUG, "Synced webhook configuration")
            end
        end
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
    sync_routing(red)
    sync_ip_whitelist(red)

    -- Sync endpoint configurations
    sync_endpoints(red)

    -- Sync vhost configurations
    sync_vhosts(red)

    -- Sync CAPTCHA configuration
    sync_captcha(red)

    -- Sync fingerprint profiles
    sync_fingerprint_profiles(red)

    -- Sync webhook configuration
    sync_webhooks(red)

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

    -- Start learning flush timer (only on worker 0)
    if ngx.worker.id() == 0 then
        local flush_interval = field_learner.get_flush_interval()
        local function learning_flush_handler(premature)
            if premature then
                return
            end

            -- Connect to Redis and flush learning data
            local red = redis:new()
            red:set_timeouts(1000, 1000, 1000)

            local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
            if ok then
                if REDIS_PASSWORD then
                    red:auth(REDIS_PASSWORD)
                end
                if REDIS_DB > 0 then
                    red:select(REDIS_DB)
                end

                local flushed, flush_err = field_learner.flush_to_redis(red)
                if flushed and flushed > 0 then
                    ngx.log(ngx.DEBUG, "Flushed ", flushed, " learning entries to Redis")
                end

                red:set_keepalive(10000, 100)
            else
                ngx.log(ngx.WARN, "Learning flush: failed to connect to Redis: ", err)
            end

            -- Reschedule
            ngx.timer.at(flush_interval, learning_flush_handler)
        end

        local ok, err = ngx.timer.at(flush_interval, learning_flush_handler)
        if ok then
            ngx.log(ngx.INFO, "Field learning flush timer started with interval: ", flush_interval, "s")
        else
            ngx.log(ngx.WARN, "Failed to start learning flush timer: ", err)
        end

        -- Start behavioral baseline calculation timer (hourly)
        -- This can optionally use leader election to avoid race conditions in multi-pod deployments
        local USE_LEADER_ELECTION = os.getenv("WAF_USE_LEADER_ELECTION") == "true"
        local baseline_interval = 3600  -- 1 hour
        local baseline_initial_delay = 300  -- 5 minutes

        -- Baseline calculation logic (reusable for both timer and leader task)
        local function do_baseline_calculation()
            ngx.log(ngx.DEBUG, "Starting behavioral baseline calculations")

            -- Connect to Redis
            local red = redis:new()
            red:set_timeouts(5000, 5000, 5000)  -- Longer timeout for calculations

            local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
            if ok then
                if REDIS_PASSWORD then
                    red:auth(REDIS_PASSWORD)
                end
                if REDIS_DB > 0 then
                    red:select(REDIS_DB)
                end

                -- Get all vhosts with behavioral tracking
                local vhost_ids = behavioral_tracker.get_tracked_vhosts()
                local calculated_count = 0

                for _, vhost_id in ipairs(vhost_ids or {}) do
                    -- Get vhost config for baselines settings
                    local vhost_config_json = red:get(KEYS.vhost_config_prefix .. vhost_id)
                    if vhost_config_json and vhost_config_json ~= ngx.null then
                        local vhost_config = cjson.decode(vhost_config_json)
                        if vhost_config and vhost_config.behavioral and vhost_config.behavioral.enabled then
                            local baselines_config = vhost_config.behavioral.baselines or {}

                            -- Get all flows for this vhost
                            local flows = behavioral_tracker.get_flows(vhost_id)
                            for _, flow_name in ipairs(flows or {}) do
                                local calc_ok, calc_err = behavioral_tracker.calculate_baselines(
                                    red, vhost_id, flow_name, baselines_config
                                )
                                if calc_ok then
                                    calculated_count = calculated_count + 1
                                elseif calc_err ~= "insufficient samples" then
                                    ngx.log(ngx.WARN, "Baseline calculation failed for ",
                                        vhost_id, ":", flow_name, " - ", calc_err)
                                end
                            end
                        end
                    end
                end

                if calculated_count > 0 then
                    ngx.log(ngx.INFO, "Calculated ", calculated_count, " behavioral baselines")
                end

                red:set_keepalive(10000, 100)
            else
                ngx.log(ngx.WARN, "Baseline calculation: failed to connect to Redis: ", err)
            end
        end

        if USE_LEADER_ELECTION then
            -- Use leader election: only the elected leader runs baseline calculations
            -- This is useful for multi-pod deployments to avoid race conditions
            ngx.log(ngx.INFO, "Using leader election for baseline calculations")
            local coordinator = get_instance_coordinator()
            coordinator.register_for_leader_task(
                "baseline_calculation",
                do_baseline_calculation,
                baseline_interval,
                baseline_initial_delay
            )
        else
            -- Fallback to worker-0 pattern (traditional approach for single-pod deployments)
            local function baseline_calculation_handler(premature)
                if premature then
                    return
                end

                do_baseline_calculation()

                -- Reschedule
                ngx.timer.at(baseline_interval, baseline_calculation_handler)
            end

            -- Start after initial delay (5 minutes) to allow data to accumulate
            local ok, err = ngx.timer.at(baseline_initial_delay, baseline_calculation_handler)
            if ok then
                ngx.log(ngx.INFO, "Behavioral baseline calculation timer started with interval: ", baseline_interval, "s (worker-0 mode)")
            else
                ngx.log(ngx.WARN, "Failed to start baseline calculation timer: ", err)
            end
        end
    end
end

-- Manual sync trigger
function _M.sync_now()
    do_sync()
end

-- Get sync status
function _M.get_status()
    local status = {
        redis_host = REDIS_HOST,
        redis_port = REDIS_PORT,
        sync_interval = SYNC_INTERVAL,
        filter_stats = keyword_filter.get_stats(),
        endpoint_stats = endpoint_matcher.get_stats(),
        vhost_stats = vhost_matcher.get_stats(),
        redis_connected = false,
        blocked_hashes_count = 0,
        whitelisted_ips_count = 0,
        endpoints_count = 0,
        vhosts_count = 0,
    }

    -- Try to get counts from Redis
    local red, err = get_redis_connection()
    if red then
        status.redis_connected = true

        -- Get counts
        local blocked_hashes = red:scard(KEYS.blocked_hashes)
        if blocked_hashes and blocked_hashes ~= ngx.null then
            status.blocked_hashes_count = blocked_hashes
        end

        local whitelisted_ips = red:scard(KEYS.ip_whitelist)
        if whitelisted_ips and whitelisted_ips ~= ngx.null then
            status.whitelisted_ips_count = whitelisted_ips
        end

        local endpoints = red:zcard(KEYS.endpoint_index)
        if endpoints and endpoints ~= ngx.null then
            status.endpoints_count = endpoints
        end

        local vhosts = red:zcard(KEYS.vhost_index)
        if vhosts and vhosts ~= ngx.null then
            status.vhosts_count = vhosts
        end

        close_redis(red)
    end

    return status
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

-- Sync single vhost (for admin API)
function _M.sync_vhost(vhost_id)
    local red, err = get_redis_connection()
    if not red then
        return nil, err
    end

    local config = sync_vhost_config(red, vhost_id)
    close_redis(red)

    return config
end

-- Sync all vhosts (for admin API)
function _M.sync_all_vhosts()
    local red, err = get_redis_connection()
    if not red then
        return nil, err
    end

    sync_vhosts(red)
    close_redis(red)

    return true
end

-- Get Redis connection (exposed for admin API direct operations)
function _M.get_connection()
    return get_redis_connection()
end

-- Return connection to pool (exposed for admin API)
function _M.return_connection(red)
    close_redis(red)
end

-- Alias for release_connection (used by behavioral_tracker)
function _M.release_connection(red)
    close_redis(red)
end

-- Default values for seeding Redis
local DEFAULT_THRESHOLDS = {
    spam_score_block = 80,
    spam_score_flag = 50,
    hash_count_block = 10,
    hash_unique_ips_block = 5,
    ip_rate_limit = 30,
    ip_daily_limit = 500,
    fingerprint_rate_limit = 20,     -- Max submissions per minute per fingerprint
    ip_spam_score_threshold = 500,   -- Cumulative spam score limit per IP (24h)
    expose_waf_headers = false,
}

local DEFAULT_ROUTING = {
    haproxy_upstream = HAPROXY_UPSTREAM,
    haproxy_upstream_ssl = HAPROXY_UPSTREAM_SSL,
    upstream_ssl = UPSTREAM_SSL == "true",
    haproxy_timeout = tonumber(HAPROXY_TIMEOUT) or 30,
}

local DEFAULT_VHOST = {
    id = "_default",
    name = "Default Virtual Host",
    enabled = true,
    hostnames = {"_"},  -- Nginx-style catch-all hostname
    waf = {
        enabled = true,
        default_mode = "monitoring",
    },
    routing = {
        use_haproxy = true,
    },
    priority = 1000,
}

-- Initialize Redis with default values if keys don't exist
-- This ensures sensible defaults are present without requiring external init scripts
function _M.initialize_defaults()
    local red, err = get_redis_connection()
    if not red then
        ngx.log(ngx.ERR, "Failed to connect to Redis for initialization: ", err)
        return false, err
    end

    local initialized = {}

    -- Initialize thresholds if empty
    local thresholds_count = red:hlen(KEYS.thresholds)
    if not thresholds_count or thresholds_count == 0 then
        ngx.log(ngx.INFO, "Initializing default thresholds in Redis")
        for key, value in pairs(DEFAULT_THRESHOLDS) do
            red:hset(KEYS.thresholds, key, serialize_threshold_value(value))
        end
        table.insert(initialized, "thresholds")
    end

    -- Initialize routing config if empty
    local routing_count = red:hlen(KEYS.routing)
    if not routing_count or routing_count == 0 then
        ngx.log(ngx.INFO, "Initializing default routing config in Redis")
        for key, value in pairs(DEFAULT_ROUTING) do
            red:hset(KEYS.routing, key, value)
        end
        table.insert(initialized, "routing")
    end

    -- Initialize default vhost if no vhosts exist
    local vhost_count = red:zcard(KEYS.vhost_index)
    if not vhost_count or vhost_count == 0 then
        ngx.log(ngx.INFO, "Initializing default virtual host in Redis")
        local config_json = cjson.encode(DEFAULT_VHOST)
        red:set(KEYS.vhost_config_prefix .. DEFAULT_VHOST.id, config_json)
        red:zadd(KEYS.vhost_index, DEFAULT_VHOST.priority, DEFAULT_VHOST.id)
        -- Create host mapping for the catch-all hostname
        for _, hostname in ipairs(DEFAULT_VHOST.hostnames) do
            red:hset(KEYS.vhost_hosts_exact, hostname, DEFAULT_VHOST.id)
        end
        table.insert(initialized, "default_vhost")
    end

    -- Initialize built-in fingerprint profiles if none exist
    local profile_count = red:zcard(KEYS.fingerprint_profiles_index)
    if not profile_count or profile_count == 0 then
        ngx.log(ngx.INFO, "Initializing built-in fingerprint profiles in Redis")
        local fp_module = get_fingerprint_profiles()
        for _, profile in ipairs(fp_module.BUILTIN_PROFILES) do
            local profile_json = cjson.encode(profile)
            red:set(KEYS.fingerprint_profiles_config_prefix .. profile.id, profile_json)
            red:zadd(KEYS.fingerprint_profiles_index, profile.priority, profile.id)
            red:sadd(KEYS.fingerprint_profiles_builtin, profile.id)
        end
        table.insert(initialized, "fingerprint_profiles")
    end

    close_redis(red)

    if #initialized > 0 then
        ngx.log(ngx.INFO, "Redis initialized with defaults: ", table.concat(initialized, ", "))
    else
        ngx.log(ngx.DEBUG, "Redis already initialized, no defaults needed")
    end

    return true, initialized
end

return _M
