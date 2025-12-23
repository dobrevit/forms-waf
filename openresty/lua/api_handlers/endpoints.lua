-- api_handlers/endpoints.lua
-- Endpoint configuration management handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"
local endpoint_matcher = require "endpoint_matcher"
local config_resolver = require "config_resolver"
local field_learner = require "field_learner"

-- Redis keys for endpoints
local ENDPOINT_KEYS = {
    index = "waf:endpoints:index",
    config_prefix = "waf:endpoints:config:",
    paths_exact = "waf:endpoints:paths:exact",
    paths_prefix = "waf:endpoints:paths:prefix",
    paths_regex = "waf:endpoints:paths:regex",
}

-- Redis keys for vhosts (needed for vhost validation)
local VHOST_KEYS = {
    index = "waf:vhosts:index",
    config_prefix = "waf:vhosts:config:",
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

-- Handlers table (simple routes)
_M.handlers = {}

-- Resource handlers table (parameterized routes: /endpoints/{id})
_M.resource_handlers = {}

-- ==================== Simple Handlers ====================

-- GET /endpoints - List all endpoint configurations
-- Supports filtering by vhost_id:
--   ?vhost_id=_global  - only global endpoints
--   ?vhost_id={id}     - endpoints for specific vhost (vhost-specific + global)
--   (no param)         - all endpoints
_M.handlers["GET:/endpoints"] = function()
    local args = ngx.req.get_uri_args()
    local filter_vhost = args.vhost_id

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
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

    utils.close_redis(red)

    return utils.json_response({
        endpoints = endpoints,
        total = #endpoints,
        global_count = global_count,
        filter_vhost = filter_vhost
    })
end

-- POST /endpoints - Create new endpoint configuration
_M.handlers["POST:/endpoints"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local config = cjson.decode(body or "{}")

    if not config then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate configuration
    local valid, errors = endpoint_matcher.validate_config(config)
    if not valid then
        return utils.error_response("Validation failed: " .. table.concat(errors, ", "), 400)
    end

    local endpoint_id = config.id

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if endpoint already exists
    local existing = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if existing and existing ~= ngx.null then
        utils.close_redis(red)
        return utils.error_response("Endpoint already exists: " .. endpoint_id, 409)
    end

    -- Normalize vhost_id (JSON null becomes ngx.null, convert to nil)
    if config.vhost_id == ngx.null then
        config.vhost_id = nil
    end

    -- Validate vhost_id if provided
    if config.vhost_id and config.vhost_id ~= "" then
        local vhost_exists = red:get(VHOST_KEYS.config_prefix .. config.vhost_id)
        if not vhost_exists or vhost_exists == ngx.null then
            utils.close_redis(red)
            return utils.error_response("Vhost not found: " .. config.vhost_id, 400)
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

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        created = true,
        endpoint_id = endpoint_id,
        endpoint = config
    }, 201)
end

-- GET /endpoints/stats - Get endpoint statistics
_M.handlers["GET:/endpoints/stats"] = function()
    local stats = endpoint_matcher.get_stats()
    return utils.json_response(stats)
end

-- GET /endpoints/match - Test endpoint matching
_M.handlers["GET:/endpoints/match"] = function()
    local args = ngx.req.get_uri_args()
    local path = args.path
    local method = args.method or "POST"

    if not path then
        return utils.error_response("Missing 'path' query parameter")
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

    return utils.json_response(result)
end

-- GET /endpoints/learned-fields - Get learned fields for endpoint
_M.handlers["GET:/endpoints/learned-fields"] = function()
    local args = ngx.req.get_uri_args()
    local endpoint_id = args.endpoint_id

    if not endpoint_id then
        return utils.error_response("Missing 'endpoint_id' query parameter")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local fields = field_learner.get_endpoint_fields(red, endpoint_id)
    utils.close_redis(red)

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

    return utils.json_response({
        endpoint_id = endpoint_id,
        fields = field_list,
        count = field_count,
        learning_stats = field_learner.get_stats()
    })
end

-- DELETE /endpoints/learned-fields - Clear learned fields for endpoint
_M.handlers["DELETE:/endpoints/learned-fields"] = function()
    local args = ngx.req.get_uri_args()
    local endpoint_id = args.endpoint_id

    if not endpoint_id then
        return utils.error_response("Missing 'endpoint_id' query parameter")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local cleared = field_learner.clear_endpoint_fields(red, endpoint_id)
    utils.close_redis(red)

    return utils.json_response({
        cleared = cleared,
        endpoint_id = endpoint_id
    })
end

-- ==================== Resource Handlers (parameterized) ====================

-- GET /endpoints/{id} - Get specific endpoint configuration
_M.resource_handlers["GET"] = function(endpoint_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    utils.close_redis(red)

    if not config_json or config_json == ngx.null then
        return utils.error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local config = cjson.decode(config_json)
    if not config then
        return utils.error_response("Invalid endpoint configuration", 500)
    end

    -- Include resolved configuration
    local resolved = config_resolver.resolve(config)

    return utils.json_response({
        endpoint = config,
        resolved = resolved
    })
end

-- PUT /endpoints/{id} - Update endpoint configuration
_M.resource_handlers["PUT"] = function(endpoint_id)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local new_config = cjson.decode(body or "{}")

    if not new_config then
        return utils.error_response("Invalid JSON body")
    end

    -- Ensure ID matches
    new_config.id = endpoint_id

    -- Validate configuration
    local valid, errors = endpoint_matcher.validate_config(new_config)
    if not valid then
        return utils.error_response("Validation failed: " .. table.concat(errors, ", "), 400)
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if not existing_json or existing_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Endpoint not found: " .. endpoint_id, 404)
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
            utils.close_redis(red)
            return utils.error_response("Vhost not found: " .. new_config.vhost_id, 400)
        end
    end

    -- Detect scope change (global <-> vhost-specific)
    local old_vhost_id = existing_config.vhost_id
    local new_vhost_id = new_config.vhost_id
    local scope_changed = (old_vhost_id or "") ~= (new_vhost_id or "")

    if scope_changed then
        ngx.log(ngx.INFO, "Endpoint ", endpoint_id, " scope changing: ",
                old_vhost_id or "global", " -> ", new_vhost_id or "global")
    end

    -- Remove old path mappings (uses old config's vhost_id to find correct keys)
    remove_path_mappings(red, endpoint_id, existing_config)

    -- If scope changed FROM global, explicitly clean up any remaining global mappings
    -- This handles edge cases where remove_path_mappings may not fully clean up
    if scope_changed and (not old_vhost_id or old_vhost_id == "" or old_vhost_id == ngx.null) then
        ngx.log(ngx.DEBUG, "Cleaning up global mappings for endpoint: ", endpoint_id)
        -- Force cleanup of global index
        red:zrem(ENDPOINT_KEYS.index, endpoint_id)
        -- Clean up global path entries
        if existing_config.matching then
            local methods = existing_config.matching.methods or {"*"}
            if existing_config.matching.paths then
                for _, path in ipairs(existing_config.matching.paths) do
                    for _, method in ipairs(methods) do
                        local key = path .. ":" .. method:upper()
                        red:hdel(ENDPOINT_KEYS.paths_exact, key)
                    end
                end
            end
            if existing_config.matching.path_prefix then
                local prefix = existing_config.matching.path_prefix
                for _, method in ipairs(methods) do
                    local pattern = prefix .. "|" .. method:upper() .. "|" .. endpoint_id
                    red:zrem(ENDPOINT_KEYS.paths_prefix, pattern)
                end
            end
        end
    end

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

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        updated = true,
        endpoint_id = endpoint_id,
        endpoint = new_config
    })
end

-- DELETE /endpoints/{id} - Delete endpoint configuration
_M.resource_handlers["DELETE"] = function(endpoint_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if not existing_json or existing_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local existing_config = cjson.decode(existing_json)

    -- Remove path mappings (this also removes from the correct scoped index)
    remove_path_mappings(red, endpoint_id, existing_config)

    -- Delete configuration
    red:del(ENDPOINT_KEYS.config_prefix .. endpoint_id)

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        deleted = true,
        endpoint_id = endpoint_id
    })
end

-- POST /endpoints/{id}/enable - Enable endpoint
_M.resource_handlers["POST:enable"] = function(endpoint_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = true
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(ENDPOINT_KEYS.config_prefix .. endpoint_id, cjson.encode(config))
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({
        enabled = true,
        endpoint_id = endpoint_id
    })
end

-- POST /endpoints/{id}/disable - Disable endpoint
_M.resource_handlers["POST:disable"] = function(endpoint_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(ENDPOINT_KEYS.config_prefix .. endpoint_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Endpoint not found: " .. endpoint_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = false
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(ENDPOINT_KEYS.config_prefix .. endpoint_id, cjson.encode(config))
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({
        disabled = true,
        endpoint_id = endpoint_id
    })
end

return _M
