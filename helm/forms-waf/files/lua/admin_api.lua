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
            thresholds[config[i]] = tonumber(config[i + 1])
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

    if not data or not data.name or not data.value then
        return error_response("Missing 'name' or 'value' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    red:hset("waf:config:thresholds", data.name, tonumber(data.value))
    close_redis(red)

    redis_sync.sync_now()

    return json_response({set = true, name = data.name, value = data.value})
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

-- Helper: Build path mappings from endpoint config
local function build_path_mappings(red, endpoint_id, config)
    if not config.matching then
        return
    end

    local methods = config.matching.methods or {"*"}

    -- Add exact paths
    if config.matching.paths then
        for _, path in ipairs(config.matching.paths) do
            for _, method in ipairs(methods) do
                local key = path .. ":" .. method:upper()
                red:hset(ENDPOINT_KEYS.paths_exact, key, endpoint_id)
            end
        end
    end

    -- Add prefix pattern
    if config.matching.path_prefix then
        local prefix = config.matching.path_prefix
        for _, method in ipairs(methods) do
            local pattern = prefix .. "|" .. method:upper() .. "|" .. endpoint_id
            local priority = config.priority or 100
            red:zadd(ENDPOINT_KEYS.paths_prefix, priority, pattern)
        end
    end

    -- Add regex pattern
    if config.matching.path_regex then
        for _, method in ipairs(methods) do
            local pattern_obj = {
                pattern = config.matching.path_regex,
                method = method:upper(),
                endpoint_id = endpoint_id,
                priority = config.priority or 100
            }
            red:rpush(ENDPOINT_KEYS.paths_regex, cjson.encode(pattern_obj))
        end
    end
end

-- Helper: Remove path mappings for an endpoint
local function remove_path_mappings(red, endpoint_id, config)
    if not config or not config.matching then
        return
    end

    local methods = config.matching.methods or {"*"}

    -- Remove exact paths
    if config.matching.paths then
        for _, path in ipairs(config.matching.paths) do
            for _, method in ipairs(methods) do
                local key = path .. ":" .. method:upper()
                red:hdel(ENDPOINT_KEYS.paths_exact, key)
            end
        end
    end

    -- Remove prefix patterns (need to find and remove matching entries)
    if config.matching.path_prefix then
        local prefix = config.matching.path_prefix
        for _, method in ipairs(methods) do
            local pattern = prefix .. "|" .. method:upper() .. "|" .. endpoint_id
            red:zrem(ENDPOINT_KEYS.paths_prefix, pattern)
        end
    end

    -- For regex patterns, we need to rebuild the list (Redis list doesn't support remove by value easily)
    -- This is handled by a full rebuild in update operations
end

-- GET /waf-admin/endpoints - List all endpoint configurations
handlers["GET:/endpoints"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get all endpoint IDs from index
    local endpoint_ids = red:zrange(ENDPOINT_KEYS.index, 0, -1, "WITHSCORES")
    if not endpoint_ids or type(endpoint_ids) ~= "table" then
        close_redis(red)
        return json_response({endpoints = {}, total = 0})
    end

    local endpoints = {}
    for i = 1, #endpoint_ids, 2 do
        local endpoint_id = endpoint_ids[i]
        local priority = tonumber(endpoint_ids[i + 1]) or 100

        -- Get config for each endpoint
        local config_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
        if config_json and config_json ~= ngx.null then
            local config = cjson.decode(config_json)
            if config then
                config.priority = priority
                table.insert(endpoints, config)
            end
        end
    end

    close_redis(red)

    return json_response({
        endpoints = endpoints,
        total = #endpoints
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

    -- Add timestamp
    config.metadata = config.metadata or {}
    config.metadata.created_at = ngx.utctime()
    config.metadata.updated_at = ngx.utctime()

    -- Store configuration
    local config_json = cjson.encode(config)
    red:set(ENDPOINT_KEYS.config_prefix .. endpoint_id, config_json)

    -- Add to index with priority
    local priority = config.priority or 100
    red:zadd(ENDPOINT_KEYS.index, priority, endpoint_id)

    -- Build path mappings
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

    -- Remove old path mappings
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

    -- Update priority in index
    local priority = new_config.priority or 100
    red:zadd(ENDPOINT_KEYS.index, priority, endpoint_id)

    -- Build new path mappings
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

-- Main request handler
function _M.handle_request()
    local method = ngx.req.get_method()
    local uri = ngx.var.uri

    -- Extract path after /waf-admin
    local path = uri:match("/waf%-admin(/.*)")
    if not path then
        path = "/"
    end

    -- Try exact handler first
    local handler_key = method .. ":" .. path
    local handler = handlers[handler_key]

    if handler then
        return handler()
    end

    -- Check for parameterized endpoint routes: /endpoints/{id} or /endpoints/{id}/action
    local endpoint_id, action = path:match("^/endpoints/([a-zA-Z0-9_-]+)/?([a-z]*)$")

    if endpoint_id then
        -- Route to appropriate endpoint handler
        if action and action ~= "" then
            -- Action route: /endpoints/{id}/enable, /endpoints/{id}/disable
            local action_handler = endpoint_handlers[method .. ":" .. action]
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

    return error_response("Not found", 404)
end

return _M
