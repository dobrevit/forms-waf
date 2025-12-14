-- admin_api.lua
-- Admin API for WAF management

local _M = {}

local cjson = require "cjson.safe"
local redis = require "resty.redis"
local redis_sync = require "redis_sync"
local waf_config = require "waf_config"
local keyword_filter = require "keyword_filter"
local endpoint_matcher = require "endpoint_matcher"
local config_resolver = require "config_resolver"
local vhost_matcher = require "vhost_matcher"
local vhost_resolver = require "vhost_resolver"
local admin_auth = require "admin_auth"
local field_learner = require "field_learner"
local metrics = require "metrics"

-- Configuration
local REQUIRE_AUTH = os.getenv("WAF_ADMIN_AUTH") ~= "false"  -- Default: require auth

-- Redis configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil

-- Get Redis connection
local function get_redis()
    local red = redis:new()
    red:set_timeout(2000)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        return nil, err
    end

    if REDIS_PASSWORD and REDIS_PASSWORD ~= "" then
        local res, err = red:auth(REDIS_PASSWORD)
        if not res then
            red:close()
            return nil, err
        end
    end

    return red
end

local function close_redis(red)
    if red then
        red:set_keepalive(10000, 100)
    end
end

-- Response helpers
local function json_response(data, status)
    ngx.status = status or 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode(data))
    return ngx.exit(ngx.status)
end

local function error_response(message, status)
    return json_response({error = message}, status or 400)
end

-- Route handlers
local handlers = {}

-- GET /waf-admin/status - Get WAF status
handlers["GET:/status"] = function()
    local status = redis_sync.get_status()
    status.config = waf_config.get_all()
    return json_response(status)
end

-- GET /waf-admin/metrics - Get WAF metrics summary
handlers["GET:/metrics"] = function()
    local summary = metrics.get_summary()
    return json_response(summary)
end

-- POST /waf-admin/metrics/reset - Reset all metrics (for testing)
handlers["POST:/metrics/reset"] = function()
    metrics.reset()
    return json_response({success = true, message = "Metrics reset"})
end

-- GET /waf-admin/keywords/blocked - List blocked keywords
handlers["GET:/keywords/blocked"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local keywords = red:smembers("waf:keywords:blocked")
    close_redis(red)

    return json_response({keywords = keywords or {}})
end

-- POST /waf-admin/keywords/blocked - Add blocked keyword
handlers["POST:/keywords/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return error_response("Missing 'keyword' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:keywords:blocked", data.keyword:lower())
    close_redis(red)

    -- Trigger immediate sync
    redis_sync.sync_now()

    return json_response({added = added == 1, keyword = data.keyword:lower()})
end

-- DELETE /waf-admin/keywords/blocked - Remove blocked keyword
handlers["DELETE:/keywords/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return error_response("Missing 'keyword' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local removed = red:srem("waf:keywords:blocked", data.keyword:lower())
    close_redis(red)

    redis_sync.sync_now()

    return json_response({removed = removed == 1, keyword = data.keyword:lower()})
end

-- PUT /waf-admin/keywords/blocked - Edit blocked keyword (atomic rename)
handlers["PUT:/keywords/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.old_keyword or not data.new_keyword then
        return error_response("Missing 'old_keyword' or 'new_keyword' field")
    end

    local old_kw = data.old_keyword:lower()
    local new_kw = data.new_keyword:lower()

    if old_kw == new_kw then
        return json_response({updated = false, reason = "keywords are identical"})
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if old keyword exists
    local exists = red:sismember("waf:keywords:blocked", old_kw)
    if exists ~= 1 then
        close_redis(red)
        return error_response("Keyword not found: " .. old_kw, 404)
    end

    -- Check if new keyword already exists
    local new_exists = red:sismember("waf:keywords:blocked", new_kw)
    if new_exists == 1 then
        close_redis(red)
        return error_response("Keyword already exists: " .. new_kw, 409)
    end

    -- Atomic transaction: add new first, then remove old
    -- If add fails, old keyword is preserved
    red:multi()
    red:sadd("waf:keywords:blocked", new_kw)
    red:srem("waf:keywords:blocked", old_kw)
    local results, err = red:exec()

    if not results then
        close_redis(red)
        return error_response("Transaction failed: " .. (err or "unknown"), 500)
    end

    close_redis(red)
    redis_sync.sync_now()

    return json_response({updated = true, old_keyword = old_kw, new_keyword = new_kw})
end

-- GET /waf-admin/keywords/flagged - List flagged keywords
handlers["GET:/keywords/flagged"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local keywords = red:smembers("waf:keywords:flagged")
    close_redis(red)

    return json_response({keywords = keywords or {}})
end

-- POST /waf-admin/keywords/flagged - Add flagged keyword
handlers["POST:/keywords/flagged"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return error_response("Missing 'keyword' field")
    end

    local keyword_entry = data.keyword:lower()
    if data.score then
        keyword_entry = keyword_entry .. ":" .. tostring(data.score)
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:keywords:flagged", keyword_entry)
    close_redis(red)

    redis_sync.sync_now()

    return json_response({added = added == 1, keyword = keyword_entry})
end

-- DELETE /waf-admin/keywords/flagged - Remove flagged keyword
handlers["DELETE:/keywords/flagged"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return error_response("Missing 'keyword' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Flagged keywords may have score suffix, so we need to find and remove the matching entry
    local keyword_lower = data.keyword:lower()
    local members = red:smembers("waf:keywords:flagged")
    local removed = 0

    if members and type(members) == "table" then
        for _, member in ipairs(members) do
            -- Match keyword with or without score suffix
            local kw = member:match("^([^:]+)")
            if kw == keyword_lower or member == keyword_lower then
                local result = red:srem("waf:keywords:flagged", member)
                if result == 1 then
                    removed = removed + 1
                end
            end
        end
    end

    close_redis(red)
    redis_sync.sync_now()

    return json_response({removed = removed > 0, keyword = keyword_lower, count = removed})
end

-- PUT /waf-admin/keywords/flagged - Edit flagged keyword (atomic rename)
handlers["PUT:/keywords/flagged"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.old_keyword then
        return error_response("Missing 'old_keyword' field")
    end

    -- new_keyword or new_score (or both) must be provided
    if not data.new_keyword and data.new_score == nil then
        return error_response("Missing 'new_keyword' or 'new_score' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Find the existing entry (keyword may have score suffix)
    local old_kw_lower = data.old_keyword:lower()
    local members = red:smembers("waf:keywords:flagged")
    local old_entry = nil
    local old_keyword_base = nil
    local old_score = nil

    if members and type(members) == "table" then
        for _, member in ipairs(members) do
            local kw, score = member:match("^([^:]+):?(%d*)$")
            if kw == old_kw_lower or member == old_kw_lower then
                old_entry = member
                old_keyword_base = kw
                old_score = score ~= "" and tonumber(score) or nil
                break
            end
        end
    end

    if not old_entry then
        close_redis(red)
        return error_response("Keyword not found: " .. old_kw_lower, 404)
    end

    -- Build new entry
    local new_keyword_base = data.new_keyword and data.new_keyword:lower() or old_keyword_base
    local new_score = data.new_score ~= nil and data.new_score or old_score

    local new_entry = new_keyword_base
    if new_score then
        new_entry = new_keyword_base .. ":" .. tostring(new_score)
    end

    -- If nothing changed, return early
    if old_entry == new_entry then
        close_redis(red)
        return json_response({updated = false, reason = "no changes detected"})
    end

    -- Check if new keyword already exists (only if keyword itself changed)
    if new_keyword_base ~= old_keyword_base then
        for _, member in ipairs(members) do
            local kw = member:match("^([^:]+)")
            if kw == new_keyword_base then
                close_redis(red)
                return error_response("Keyword already exists: " .. new_keyword_base, 409)
            end
        end
    end

    -- Atomic transaction: add new first, then remove old
    -- If add fails, old keyword is preserved
    red:multi()
    red:sadd("waf:keywords:flagged", new_entry)
    red:srem("waf:keywords:flagged", old_entry)
    local results, err = red:exec()

    if not results then
        close_redis(red)
        return error_response("Transaction failed: " .. (err or "unknown"), 500)
    end

    close_redis(red)
    redis_sync.sync_now()

    return json_response({
        updated = true,
        old_keyword = old_entry,
        new_keyword = new_entry
    })
end

-- GET /waf-admin/hashes/blocked - List blocked hashes
handlers["GET:/hashes/blocked"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local hashes = red:smembers("waf:hashes:blocked")
    close_redis(red)

    return json_response({hashes = hashes or {}})
end

-- POST /waf-admin/hashes/blocked - Add blocked hash
handlers["POST:/hashes/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.hash then
        return error_response("Missing 'hash' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:hashes:blocked", data.hash:lower())
    close_redis(red)

    redis_sync.sync_now()

    return json_response({added = added == 1, hash = data.hash:lower()})
end

-- GET /waf-admin/whitelist/ips - List whitelisted IPs
handlers["GET:/whitelist/ips"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local ips = red:smembers("waf:whitelist:ips")
    close_redis(red)

    return json_response({ips = ips or {}})
end

-- POST /waf-admin/whitelist/ips - Add whitelisted IP
handlers["POST:/whitelist/ips"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.ip then
        return error_response("Missing 'ip' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:whitelist:ips", data.ip)
    close_redis(red)

    redis_sync.sync_now()

    return json_response({added = added == 1, ip = data.ip})
end

-- POST /waf-admin/sync - Force sync from Redis
handlers["POST:/sync"] = function()
    redis_sync.sync_now()
    return json_response({synced = true})
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

-- Helper to serialize threshold value for Redis
local function serialize_threshold_value(value)
    if type(value) == "boolean" then
        return value and "true" or "false"
    else
        return tostring(value)
    end
end

-- GET /waf-admin/config/thresholds - Get thresholds
handlers["GET:/config/thresholds"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config = red:hgetall("waf:config:thresholds")
    close_redis(red)

    local thresholds = {}
    if type(config) == "table" then
        for i = 1, #config, 2 do
            thresholds[config[i]] = parse_threshold_value(config[i + 1])
        end
    end

    return json_response({
        thresholds = thresholds,
        defaults = waf_config.get_all().defaults
    })
end

-- POST /waf-admin/config/thresholds - Set threshold
handlers["POST:/config/thresholds"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.name or data.value == nil then
        return error_response("Missing 'name' or 'value' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local redis_value = serialize_threshold_value(data.value)
    red:hset("waf:config:thresholds", data.name, redis_value)
    close_redis(red)

    redis_sync.sync_now()

    return json_response({set = true, name = data.name, value = data.value})
end

-- GET /waf-admin/config/routing - Get global routing config
handlers["GET:/config/routing"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config = red:hgetall("waf:config:routing")
    close_redis(red)

    local routing = {}
    if type(config) == "table" then
        for i = 1, #config, 2 do
            local key = config[i]
            local value = config[i + 1]
            -- Try to convert to number if applicable
            local num_value = tonumber(value)
            routing[key] = num_value or value
        end
    end

    return json_response({
        routing = routing,
        defaults = waf_config.get_all().defaults.routing
    })
end

-- PUT /waf-admin/config/routing - Update global routing config
handlers["PUT:/config/routing"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return error_response("Invalid JSON body")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Update each provided field
    local updated = {}
    if data.haproxy_upstream then
        red:hset("waf:config:routing", "haproxy_upstream", data.haproxy_upstream)
        table.insert(updated, "haproxy_upstream")
    end
    if data.haproxy_timeout then
        red:hset("waf:config:routing", "haproxy_timeout", tonumber(data.haproxy_timeout))
        table.insert(updated, "haproxy_timeout")
    end

    close_redis(red)

    redis_sync.sync_now()

    return json_response({updated = true, fields = updated})
end

-- ============================================================================
-- Endpoint Configuration Management
-- ============================================================================

-- Redis keys for endpoints
local ENDPOINT_KEYS = {
    index = "waf:endpoints:index",
    config_prefix = "waf:endpoints:config:",
    paths_exact = "waf:endpoints:paths:exact",
    paths_prefix = "waf:endpoints:paths:prefix",
    paths_regex = "waf:endpoints:paths:regex",
}

-- Redis keys for vhosts (defined early for use in endpoint handlers)
local VHOST_KEYS = {
    index = "waf:vhosts:index",
    config_prefix = "waf:vhosts:config:",
    hosts_exact = "waf:vhosts:hosts:exact",
    hosts_wildcard = "waf:vhosts:hosts:wildcard",
}

-- Helper: Get endpoint keys based on vhost scope
-- Returns global keys if vhost_id is nil/empty/ngx.null, vhost-specific keys otherwise
local function get_endpoint_keys_for_vhost(vhost_id)
    if not vhost_id or vhost_id == "" or vhost_id == ngx.null then
        -- Global endpoint keys
        return {
            index = ENDPOINT_KEYS.index,
            paths_exact = ENDPOINT_KEYS.paths_exact,
            paths_prefix = ENDPOINT_KEYS.paths_prefix,
            paths_regex = ENDPOINT_KEYS.paths_regex,
        }
    else
        -- Vhost-specific endpoint keys
        local prefix = "waf:vhosts:endpoints:" .. vhost_id
        return {
            index = prefix .. ":index",
            paths_exact = prefix .. ":paths:exact",
            paths_prefix = prefix .. ":paths:prefix",
            paths_regex = prefix .. ":paths:regex",
        }
    end
end

-- Helper: Build path mappings from endpoint config
local function build_path_mappings(red, endpoint_id, config)
    if not config.matching then
        return
    end

    -- Get the appropriate keys based on vhost scope
    local keys = get_endpoint_keys_for_vhost(config.vhost_id)
    local methods = config.matching.methods or {"*"}

    -- Add to index with priority
    local priority = config.priority or 100
    red:zadd(keys.index, priority, endpoint_id)

    -- Add exact paths
    if config.matching.paths then
        for _, path in ipairs(config.matching.paths) do
            for _, method in ipairs(methods) do
                local key = path .. ":" .. method:upper()
                red:hset(keys.paths_exact, key, endpoint_id)
            end
        end
    end

    -- Add prefix pattern
    if config.matching.path_prefix then
        local prefix = config.matching.path_prefix
        for _, method in ipairs(methods) do
            local pattern = prefix .. "|" .. method:upper() .. "|" .. endpoint_id
            red:zadd(keys.paths_prefix, priority, pattern)
        end
    end

    -- Add regex pattern
    if config.matching.path_regex then
        for _, method in ipairs(methods) do
            local pattern_obj = {
                pattern = config.matching.path_regex,
                method = method:upper(),
                endpoint_id = endpoint_id,
                priority = priority
            }
            red:rpush(keys.paths_regex, cjson.encode(pattern_obj))
        end
    end
end

-- Helper: Remove path mappings for an endpoint
local function remove_path_mappings(red, endpoint_id, config)
    if not config or not config.matching then
        return
    end

    -- Get the appropriate keys based on vhost scope
    local keys = get_endpoint_keys_for_vhost(config.vhost_id)
    local methods = config.matching.methods or {"*"}

    -- Remove from index
    red:zrem(keys.index, endpoint_id)

    -- Remove exact paths
    if config.matching.paths then
        for _, path in ipairs(config.matching.paths) do
            for _, method in ipairs(methods) do
                local key = path .. ":" .. method:upper()
                red:hdel(keys.paths_exact, key)
            end
        end
    end

    -- Remove prefix patterns (need to find and remove matching entries)
    if config.matching.path_prefix then
        local prefix = config.matching.path_prefix
        for _, method in ipairs(methods) do
            local pattern = prefix .. "|" .. method:upper() .. "|" .. endpoint_id
            red:zrem(keys.paths_prefix, pattern)
        end
    end

    -- For regex patterns, we need to rebuild the list (Redis list doesn't support remove by value easily)
    -- This is handled by a full rebuild in update operations
end

-- GET /waf-admin/endpoints - List all endpoint configurations
-- Supports filtering by vhost_id:
--   ?vhost_id=_global  - only global endpoints
--   ?vhost_id={id}     - endpoints for specific vhost (vhost-specific + global)
--   (no param)         - all endpoints
handlers["GET:/endpoints"] = function()
    local args = ngx.req.get_uri_args()
    local filter_vhost = args.vhost_id

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local endpoints = {}
    local seen_ids = {}  -- Track seen endpoint IDs to avoid duplicates

    -- Helper to fetch endpoints from an index
    local function fetch_endpoints_from_index(index_key)
        local endpoint_ids = red:zrange(index_key, 0, -1, "WITHSCORES")
        if endpoint_ids and type(endpoint_ids) == "table" then
            for i = 1, #endpoint_ids, 2 do
                local endpoint_id = endpoint_ids[i]
                local priority = tonumber(endpoint_ids[i + 1]) or 100

                if not seen_ids[endpoint_id] then
                    seen_ids[endpoint_id] = true
                    local config_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
                    if config_json and config_json ~= ngx.null then
                        local config = cjson.decode(config_json)
                        if config then
                            config.priority = priority
                            table.insert(endpoints, config)
                        end
                    end
                end
            end
        end
    end

    if filter_vhost == "_global" then
        -- Only global endpoints (no vhost_id)
        fetch_endpoints_from_index(ENDPOINT_KEYS.index)
    elseif filter_vhost and filter_vhost ~= "" then
        -- Vhost-specific endpoints + global endpoints
        local vhost_keys = get_endpoint_keys_for_vhost(filter_vhost)
        fetch_endpoints_from_index(vhost_keys.index)  -- Vhost-specific first
        fetch_endpoints_from_index(ENDPOINT_KEYS.index)  -- Then global
    else
        -- All endpoints: get all vhost indexes + global
        -- First, get global endpoints
        fetch_endpoints_from_index(ENDPOINT_KEYS.index)

        -- Then get all vhost-specific endpoints
        local vhost_ids = red:zrange(VHOST_KEYS.index, 0, -1)
        if vhost_ids and type(vhost_ids) == "table" then
            for _, vhost_id in ipairs(vhost_ids) do
                local vhost_keys = get_endpoint_keys_for_vhost(vhost_id)
                fetch_endpoints_from_index(vhost_keys.index)
            end
        end
    end

    -- Get global endpoint count for response
    local global_count = red:zcard(ENDPOINT_KEYS.index) or 0

    close_redis(red)

    return json_response({
        endpoints = endpoints,
        total = #endpoints,
        global_count = global_count,
        filter_vhost = filter_vhost
    })
end

-- GET /waf-admin/endpoints/stats - Get endpoint statistics
handlers["GET:/endpoints/stats"] = function()
    local stats = endpoint_matcher.get_stats()
    return json_response(stats)
end

-- GET /waf-admin/endpoints/match - Test endpoint matching
handlers["GET:/endpoints/match"] = function()
    local args = ngx.req.get_uri_args()
    local path = args.path
    local method = args.method or "POST"

    if not path then
        return error_response("Missing 'path' query parameter")
    end

    local endpoint_id, match_type = endpoint_matcher.match(path, method)

    local result = {
        path = path,
        method = method,
        matched = endpoint_id ~= nil,
        endpoint_id = endpoint_id,
        match_type = match_type
    }

    if endpoint_id then
        local config = endpoint_matcher.get_config(endpoint_id)
        if config then
            result.endpoint_config = config
            result.resolved_config = config_resolver.resolve(config)
        end
    end

    return json_response(result)
end

-- ===============================
-- Field Learning API
-- ===============================

-- GET /waf-admin/endpoints/{id}/learned-fields - Get learned fields for endpoint
handlers["GET:/endpoints/learned-fields"] = function()
    local args = ngx.req.get_uri_args()
    local endpoint_id = args.endpoint_id

    if not endpoint_id then
        return error_response("Missing 'endpoint_id' query parameter")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local fields = field_learner.get_endpoint_fields(red, endpoint_id)
    close_redis(red)

    -- Convert to sorted array for consistent output
    local field_list = {}
    for name, data in pairs(fields) do
        table.insert(field_list, data)
    end

    -- Sort by count (most frequent first)
    table.sort(field_list, function(a, b)
        return (a.count or 0) > (b.count or 0)
    end)

    local field_count = #field_list

    -- Use cjson.empty_array to ensure empty tables encode as [] not {}
    if field_count == 0 then
        field_list = cjson.empty_array
    end

    return json_response({
        endpoint_id = endpoint_id,
        fields = field_list,
        count = field_count,
        learning_stats = field_learner.get_stats()
    })
end

-- DELETE /waf-admin/endpoints/{id}/learned-fields - Clear learned fields for endpoint
handlers["DELETE:/endpoints/learned-fields"] = function()
    local args = ngx.req.get_uri_args()
    local endpoint_id = args.endpoint_id

    if not endpoint_id then
        return error_response("Missing 'endpoint_id' query parameter")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local cleared = field_learner.clear_endpoint_fields(red, endpoint_id)
    close_redis(red)

    return json_response({
        cleared = cleared,
        endpoint_id = endpoint_id
    })
end

-- GET /waf-admin/vhosts/learned-fields - Get learned fields for vhost
handlers["GET:/vhosts/learned-fields"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id

    if not vhost_id then
        return error_response("Missing 'vhost_id' query parameter")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local fields = field_learner.get_vhost_fields(red, vhost_id)
    close_redis(red)

    -- Convert to sorted array for consistent output
    local field_list = {}
    for name, data in pairs(fields) do
        table.insert(field_list, data)
    end

    -- Sort by count (most frequent first)
    table.sort(field_list, function(a, b)
        return (a.count or 0) > (b.count or 0)
    end)

    local field_count = #field_list

    -- Use cjson.empty_array to ensure empty tables encode as [] not {}
    if field_count == 0 then
        field_list = cjson.empty_array
    end

    return json_response({
        vhost_id = vhost_id,
        fields = field_list,
        count = field_count,
        learning_stats = field_learner.get_stats()
    })
end

-- DELETE /waf-admin/vhosts/learned-fields - Clear learned fields for vhost
handlers["DELETE:/vhosts/learned-fields"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id

    if not vhost_id then
        return error_response("Missing 'vhost_id' query parameter")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local cleared = field_learner.clear_vhost_fields(red, vhost_id)
    close_redis(red)

    return json_response({
        cleared = cleared,
        vhost_id = vhost_id
    })
end

-- GET /waf-admin/learning/stats - Get learning statistics
handlers["GET:/learning/stats"] = function()
    return json_response({
        stats = field_learner.get_stats()
    })
end

-- Parameterized endpoint handlers (called from main handler)
local endpoint_handlers = {}

-- GET /waf-admin/endpoints/{id} - Get specific endpoint configuration
endpoint_handlers["GET"] = function(endpoint_id)
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    close_redis(red)

    if not config_json or config_json == ngx.null then
        return error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local config = cjson.decode(config_json)
    if not config then
        return error_response("Invalid endpoint configuration", 500)
    end

    -- Include resolved configuration
    local resolved = config_resolver.resolve(config)

    return json_response({
        endpoint = config,
        resolved = resolved
    })
end

-- POST /waf-admin/endpoints - Create new endpoint configuration
handlers["POST:/endpoints"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local config = cjson.decode(body or "{}")

    if not config then
        return error_response("Invalid JSON body")
    end

    -- Validate configuration
    local valid, errors = endpoint_matcher.validate_config(config)
    if not valid then
        return error_response("Validation failed: " .. table.concat(errors, ", "), 400)
    end

    local endpoint_id = config.id

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if endpoint already exists
    local existing = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if existing and existing ~= ngx.null then
        close_redis(red)
        return error_response("Endpoint already exists: " .. endpoint_id, 409)
    end

    -- Normalize vhost_id (JSON null becomes ngx.null, convert to nil)
    if config.vhost_id == ngx.null then
        config.vhost_id = nil
    end

    -- Validate vhost_id if provided
    if config.vhost_id and config.vhost_id ~= "" then
        local vhost_exists = red:get(VHOST_KEYS.config_prefix .. config.vhost_id)
        if not vhost_exists or vhost_exists == ngx.null then
            close_redis(red)
            return error_response("Vhost not found: " .. config.vhost_id, 400)
        end
    end

    -- Add timestamp
    config.metadata = config.metadata or {}
    config.metadata.created_at = ngx.utctime()
    config.metadata.updated_at = ngx.utctime()

    -- Store configuration (config key is always global, only path mappings are vhost-scoped)
    local config_json = cjson.encode(config)
    red:set(ENDPOINT_KEYS.config_prefix .. endpoint_id, config_json)

    -- Build path mappings (includes adding to the appropriate index)
    build_path_mappings(red, endpoint_id, config)

    close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return json_response({
        created = true,
        endpoint_id = endpoint_id,
        endpoint = config
    }, 201)
end

-- PUT /waf-admin/endpoints/{id} - Update endpoint configuration
endpoint_handlers["PUT"] = function(endpoint_id)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local new_config = cjson.decode(body or "{}")

    if not new_config then
        return error_response("Invalid JSON body")
    end

    -- Ensure ID matches
    new_config.id = endpoint_id

    -- Validate configuration
    local valid, errors = endpoint_matcher.validate_config(new_config)
    if not valid then
        return error_response("Validation failed: " .. table.concat(errors, ", "), 400)
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if not existing_json or existing_json == ngx.null then
        close_redis(red)
        return error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local existing_config = cjson.decode(existing_json)

    -- Normalize vhost_id (JSON null becomes ngx.null, convert to nil)
    if new_config.vhost_id == ngx.null then
        new_config.vhost_id = nil
    end

    -- Validate new vhost_id if provided
    if new_config.vhost_id and new_config.vhost_id ~= "" then
        local vhost_exists = red:get(VHOST_KEYS.config_prefix .. new_config.vhost_id)
        if not vhost_exists or vhost_exists == ngx.null then
            close_redis(red)
            return error_response("Vhost not found: " .. new_config.vhost_id, 400)
        end
    end

    -- Remove old path mappings (uses old config's vhost_id to find correct keys)
    remove_path_mappings(red, endpoint_id, existing_config)

    -- Preserve created_at, update updated_at
    new_config.metadata = new_config.metadata or {}
    if existing_config.metadata and existing_config.metadata.created_at then
        new_config.metadata.created_at = existing_config.metadata.created_at
    end
    new_config.metadata.updated_at = ngx.utctime()

    -- Store new configuration
    local config_json = cjson.encode(new_config)
    red:set(ENDPOINT_KEYS.config_prefix .. endpoint_id, config_json)

    -- Build new path mappings (uses new config's vhost_id for correct keys)
    build_path_mappings(red, endpoint_id, new_config)

    close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return json_response({
        updated = true,
        endpoint_id = endpoint_id,
        endpoint = new_config
    })
end

-- DELETE /waf-admin/endpoints/{id} - Delete endpoint configuration
endpoint_handlers["DELETE"] = function(endpoint_id)
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if not existing_json or existing_json == ngx.null then
        close_redis(red)
        return error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local existing_config = cjson.decode(existing_json)

    -- Remove path mappings
    remove_path_mappings(red, endpoint_id, existing_config)

    -- Delete configuration
    red:del(ENDPOINT_KEYS.config_prefix .. endpoint_id)

    -- Remove from index
    red:zrem(ENDPOINT_KEYS.index, endpoint_id)

    close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return json_response({
        deleted = true,
        endpoint_id = endpoint_id
    })
end

-- POST /waf-admin/endpoints/{id}/enable - Enable endpoint
endpoint_handlers["POST:enable"] = function(endpoint_id)
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = true
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(ENDPOINT_KEYS.config_prefix .. endpoint_id, cjson.encode(config))
    close_redis(red)

    redis_sync.sync_now()

    return json_response({
        enabled = true,
        endpoint_id = endpoint_id
    })
end

-- POST /waf-admin/endpoints/{id}/disable - Disable endpoint
endpoint_handlers["POST:disable"] = function(endpoint_id)
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = false
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(ENDPOINT_KEYS.config_prefix .. endpoint_id, cjson.encode(config))
    close_redis(red)

    redis_sync.sync_now()

    return json_response({
        disabled = true,
        endpoint_id = endpoint_id
    })
end

-- ============================================================================
-- Virtual Host Configuration Management
-- ============================================================================

-- Helper: Build host mappings from vhost config
local function build_host_mappings(red, vhost_id, config)
    if not config.hostnames then
        return
    end

    for _, host in ipairs(config.hostnames) do
        local host_lower = host:lower()

        if host_lower:match("^%*%.") then
            -- Wildcard pattern (e.g., *.example.com)
            local pattern = host_lower .. "|" .. vhost_id
            local priority = config.priority or 100
            red:zadd(VHOST_KEYS.hosts_wildcard, priority, pattern)
        else
            -- Exact hostname
            red:hset(VHOST_KEYS.hosts_exact, host_lower, vhost_id)
        end
    end
end

-- Helper: Remove host mappings for a vhost
local function remove_host_mappings(red, vhost_id, config)
    if not config or not config.hostnames then
        return
    end

    for _, host in ipairs(config.hostnames) do
        local host_lower = host:lower()

        if host_lower:match("^%*%.") then
            -- Wildcard pattern
            local pattern = host_lower .. "|" .. vhost_id
            red:zrem(VHOST_KEYS.hosts_wildcard, pattern)
        else
            -- Exact hostname
            red:hdel(VHOST_KEYS.hosts_exact, host_lower)
        end
    end
end

-- GET /waf-admin/vhosts - List all vhost configurations
handlers["GET:/vhosts"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get all vhost IDs from index
    local vhost_ids = red:zrange(VHOST_KEYS.index, 0, -1, "WITHSCORES")
    if not vhost_ids or type(vhost_ids) ~= "table" then
        close_redis(red)
        return json_response({vhosts = {}, total = 0, global_endpoint_count = 0})
    end

    local vhosts = {}
    for i = 1, #vhost_ids, 2 do
        local vhost_id = vhost_ids[i]
        local priority = tonumber(vhost_ids[i + 1]) or 100

        -- Get config for each vhost
        local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
        if config_json and config_json ~= ngx.null then
            local config = cjson.decode(config_json)
            if config then
                config.priority = priority

                -- Get endpoint count for this vhost
                local vhost_endpoint_key = "waf:vhosts:endpoints:" .. vhost_id .. ":index"
                local endpoint_count = red:zcard(vhost_endpoint_key)
                config.endpoint_count = endpoint_count and tonumber(endpoint_count) or 0

                table.insert(vhosts, config)
            end
        end
    end

    -- Get global endpoint count
    local global_endpoint_count = red:zcard(ENDPOINT_KEYS.index) or 0

    close_redis(red)

    return json_response({
        vhosts = vhosts,
        total = #vhosts,
        global_endpoint_count = tonumber(global_endpoint_count) or 0
    })
end

-- GET /waf-admin/vhosts/stats - Get vhost statistics
handlers["GET:/vhosts/stats"] = function()
    local stats = vhost_matcher.get_stats()
    return json_response(stats)
end

-- GET /waf-admin/vhosts/match - Test vhost matching
handlers["GET:/vhosts/match"] = function()
    local args = ngx.req.get_uri_args()
    local host = args.host

    if not host then
        return error_response("Missing 'host' query parameter")
    end

    local vhost_id, match_type = vhost_matcher.match(host)

    local result = {
        host = host,
        matched = vhost_id ~= vhost_matcher.DEFAULT_VHOST,
        vhost_id = vhost_id,
        match_type = match_type
    }

    if vhost_id then
        local config = vhost_matcher.get_config(vhost_id)
        if config then
            result.vhost_config = config
            result.resolved_config = vhost_resolver.resolve(vhost_id)
        end
    end

    return json_response(result)
end

-- GET /waf-admin/vhosts/context - Test full request context resolution
handlers["GET:/vhosts/context"] = function()
    local args = ngx.req.get_uri_args()
    local host = args.host
    local path = args.path or "/"
    local method = args.method or "POST"

    if not host then
        return error_response("Missing 'host' query parameter")
    end

    local context = vhost_resolver.resolve_request_context(host, path, method)
    local summary = vhost_resolver.get_context_summary(context)

    return json_response({
        request = {
            host = host,
            path = path,
            method = method
        },
        context = {
            vhost = context.vhost,
            vhost_match_type = context.vhost_match_type,
            endpoint = context.endpoint,
            endpoint_match_type = context.endpoint_match_type,
            skip_waf = context.skip_waf,
            reason = context.reason
        },
        summary = summary,
        routing = vhost_resolver.get_routing(context)
    })
end

-- Parameterized vhost handlers
local vhost_handlers = {}

-- GET /waf-admin/vhosts/{id} - Get specific vhost configuration
vhost_handlers["GET"] = function(vhost_id)
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    close_redis(red)

    if not config_json or config_json == ngx.null then
        return error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)
    if not config then
        return error_response("Invalid vhost configuration", 500)
    end

    -- Include resolved configuration
    local resolved = vhost_resolver.resolve(vhost_id)

    return json_response({
        vhost = config,
        resolved = resolved
    })
end

-- POST /waf-admin/vhosts - Create new vhost configuration
handlers["POST:/vhosts"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local config = cjson.decode(body or "{}")

    if not config then
        return error_response("Invalid JSON body")
    end

    -- Validate configuration
    local valid, errors = vhost_matcher.validate_config(config)
    if not valid then
        return error_response("Validation failed: " .. table.concat(errors, ", "), 400)
    end

    local vhost_id = config.id

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if vhost already exists
    local existing = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if existing and existing ~= ngx.null then
        close_redis(red)
        return error_response("Vhost already exists: " .. vhost_id, 409)
    end

    -- Check for conflicting hostnames
    for _, host in ipairs(config.hostnames) do
        local host_lower = host:lower()
        if not host_lower:match("^%*%.") then
            -- Check if exact host already mapped to another vhost
            local existing_vhost = red:hget(VHOST_KEYS.hosts_exact, host_lower)
            if existing_vhost and existing_vhost ~= ngx.null then
                close_redis(red)
                return error_response("Host '" .. host .. "' already mapped to vhost: " .. existing_vhost, 409)
            end
        end
    end

    -- Add timestamp
    config.metadata = config.metadata or {}
    config.metadata.created_at = ngx.utctime()
    config.metadata.updated_at = ngx.utctime()

    -- Store configuration
    local config_json = cjson.encode(config)
    red:set(VHOST_KEYS.config_prefix .. vhost_id, config_json)

    -- Add to index with priority
    local priority = config.priority or 100
    red:zadd(VHOST_KEYS.index, priority, vhost_id)

    -- Build host mappings
    build_host_mappings(red, vhost_id, config)

    close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return json_response({
        created = true,
        vhost_id = vhost_id,
        vhost = config
    }, 201)
end

-- PUT /waf-admin/vhosts/{id} - Update vhost configuration
vhost_handlers["PUT"] = function(vhost_id)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local new_config = cjson.decode(body or "{}")

    if not new_config then
        return error_response("Invalid JSON body")
    end

    -- Ensure ID matches
    new_config.id = vhost_id

    -- Validate configuration
    local valid, errors = vhost_matcher.validate_config(new_config)
    if not valid then
        return error_response("Validation failed: " .. table.concat(errors, ", "), 400)
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not existing_json or existing_json == ngx.null then
        close_redis(red)
        return error_response("Vhost not found: " .. vhost_id, 404)
    end

    local existing_config = cjson.decode(existing_json)

    -- Remove old host mappings
    remove_host_mappings(red, vhost_id, existing_config)

    -- Preserve created_at, update updated_at
    new_config.metadata = new_config.metadata or {}
    if existing_config.metadata and existing_config.metadata.created_at then
        new_config.metadata.created_at = existing_config.metadata.created_at
    end
    new_config.metadata.updated_at = ngx.utctime()

    -- Store new configuration
    local config_json = cjson.encode(new_config)
    red:set(VHOST_KEYS.config_prefix .. vhost_id, config_json)

    -- Update priority in index
    local priority = new_config.priority or 100
    red:zadd(VHOST_KEYS.index, priority, vhost_id)

    -- Build new host mappings
    build_host_mappings(red, vhost_id, new_config)

    close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return json_response({
        updated = true,
        vhost_id = vhost_id,
        vhost = new_config
    })
end

-- DELETE /waf-admin/vhosts/{id} - Delete vhost configuration
vhost_handlers["DELETE"] = function(vhost_id)
    -- Prevent deleting the default vhost
    if vhost_id == "_default" then
        return error_response("Cannot delete the default vhost", 400)
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not existing_json or existing_json == ngx.null then
        close_redis(red)
        return error_response("Vhost not found: " .. vhost_id, 404)
    end

    local existing_config = cjson.decode(existing_json)

    -- Remove host mappings
    remove_host_mappings(red, vhost_id, existing_config)

    -- Delete configuration
    red:del(VHOST_KEYS.config_prefix .. vhost_id)

    -- Remove from index
    red:zrem(VHOST_KEYS.index, vhost_id)

    close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return json_response({
        deleted = true,
        vhost_id = vhost_id
    })
end

-- POST /waf-admin/vhosts/{id}/enable - Enable vhost
vhost_handlers["POST:enable"] = function(vhost_id)
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = true
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(VHOST_KEYS.config_prefix .. vhost_id, cjson.encode(config))
    close_redis(red)

    redis_sync.sync_now()

    return json_response({
        enabled = true,
        vhost_id = vhost_id
    })
end

-- POST /waf-admin/vhosts/{id}/disable - Disable vhost
vhost_handlers["POST:disable"] = function(vhost_id)
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = false
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(VHOST_KEYS.config_prefix .. vhost_id, cjson.encode(config))
    close_redis(red)

    redis_sync.sync_now()

    return json_response({
        disabled = true,
        vhost_id = vhost_id
    })
end

-- Main request handler
function _M.handle_request()
    local method = ngx.req.get_method()
    local uri = ngx.var.uri

    -- Extract path - support both /api/ and /waf-admin/ prefixes
    local path = uri:match("/api(/.*)")
    if not path then
        path = uri:match("/waf%-admin(/.*)")
    end
    if not path then
        path = "/"
    end

    -- Check authentication (skip for auth endpoints themselves)
    if REQUIRE_AUTH then
        -- Auth endpoints are handled separately in admin_auth.lua via nginx routing
        -- All requests here should be authenticated
        admin_auth.check_auth()
    end

    -- Try exact handler first
    local handler_key = method .. ":" .. path
    local handler = handlers[handler_key]

    if handler then
        return handler()
    end

    -- Check for parameterized endpoint routes: /endpoints/{id} or /endpoints/{id}/action
    local endpoint_id, endpoint_action = path:match("^/endpoints/([a-zA-Z0-9_-]+)/?([a-z]*)$")

    if endpoint_id then
        -- Route to appropriate endpoint handler
        if endpoint_action and endpoint_action ~= "" then
            -- Action route: /endpoints/{id}/enable, /endpoints/{id}/disable
            local action_handler = endpoint_handlers[method .. ":" .. endpoint_action]
            if action_handler then
                return action_handler(endpoint_id)
            end
        else
            -- CRUD route: GET/PUT/DELETE /endpoints/{id}
            local crud_handler = endpoint_handlers[method]
            if crud_handler then
                return crud_handler(endpoint_id)
            end
        end
    end

    -- Check for parameterized vhost routes: /vhosts/{id} or /vhosts/{id}/action
    local vhost_id, vhost_action = path:match("^/vhosts/([a-zA-Z0-9_-]+)/?([a-z]*)$")

    if vhost_id then
        -- Route to appropriate vhost handler
        if vhost_action and vhost_action ~= "" then
            -- Action route: /vhosts/{id}/enable, /vhosts/{id}/disable
            local action_handler = vhost_handlers[method .. ":" .. vhost_action]
            if action_handler then
                return action_handler(vhost_id)
            end
        else
            -- CRUD route: GET/PUT/DELETE /vhosts/{id}
            local crud_handler = vhost_handlers[method]
            if crud_handler then
                return crud_handler(vhost_id)
            end
        end
    end

    return error_response("Not found", 404)
end

return _M
