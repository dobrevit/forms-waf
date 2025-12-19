-- api_handlers/vhosts.lua
-- Virtual host configuration management handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"
local vhost_matcher = require "vhost_matcher"
local vhost_resolver = require "vhost_resolver"
local field_learner = require "field_learner"

-- Redis keys for vhosts
local VHOST_KEYS = {
    index = "waf:vhosts:index",
    config_prefix = "waf:vhosts:config:",
    hosts_exact = "waf:vhosts:hosts:exact",
    hosts_wildcard = "waf:vhosts:hosts:wildcard",
}

-- Redis keys for endpoints (needed for stats)
local ENDPOINT_KEYS = {
    index = "waf:endpoints:index",
}

-- Helper: Build host mappings from vhost config
local function build_host_mappings(red, vhost_id, config)
    if not config.hostnames then
        return
    end

    for _, host in ipairs(config.hostnames) do
        local host_lower = host:lower()

        if host_lower == "_" or host_lower == "*" then
            -- Catch-all patterns are stored as exact matches (handled specially in vhost_matcher)
            red:hset(VHOST_KEYS.hosts_exact, host_lower, vhost_id)
        elseif host_lower:find("%*") then
            -- Wildcard pattern (e.g., *.example.com, www.*.example.com)
            local pattern = host_lower .. "|" .. vhost_id
            local priority = config.priority or 100
            red:zadd(VHOST_KEYS.hosts_wildcard, priority, pattern)
        else
            -- Exact hostname
            red:hset(VHOST_KEYS.hosts_exact, host_lower, vhost_id)
        end
    end
end

-- Helper: Check if hostname is a catch-all pattern
local function is_catchall_hostname(hostname)
    return hostname == "_" or hostname == "*"
end

-- Helper: Remove host mappings for a vhost
local function remove_host_mappings(red, vhost_id, config)
    if not config or not config.hostnames then
        return
    end

    for _, host in ipairs(config.hostnames) do
        local host_lower = host:lower()

        if host_lower == "_" or host_lower == "*" then
            -- Catch-all patterns are stored as exact matches
            red:hdel(VHOST_KEYS.hosts_exact, host_lower)
        elseif host_lower:find("%*") then
            -- Wildcard pattern
            local pattern = host_lower .. "|" .. vhost_id
            red:zrem(VHOST_KEYS.hosts_wildcard, pattern)
        else
            -- Exact hostname
            red:hdel(VHOST_KEYS.hosts_exact, host_lower)
        end
    end
end

-- Handlers table (simple routes)
_M.handlers = {}

-- Resource handlers table (parameterized routes: /vhosts/{id})
_M.resource_handlers = {}

-- ==================== Simple Handlers ====================

-- GET /vhosts - List all vhost configurations
_M.handlers["GET:/vhosts"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get all vhost IDs from index
    local vhost_ids = red:zrange(VHOST_KEYS.index, 0, -1, "WITHSCORES")
    if not vhost_ids or type(vhost_ids) ~= "table" then
        utils.close_redis(red)
        return utils.json_response({vhosts = {}, total = 0, global_endpoint_count = 0})
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

    utils.close_redis(red)

    return utils.json_response({
        vhosts = vhosts,
        total = #vhosts,
        global_endpoint_count = tonumber(global_endpoint_count) or 0
    })
end

-- POST /vhosts - Create new vhost configuration
_M.handlers["POST:/vhosts"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local config = cjson.decode(body or "{}")

    if not config then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate configuration
    local valid, errors = vhost_matcher.validate_config(config)
    if not valid then
        return utils.error_response("Validation failed: " .. table.concat(errors, ", "), 400)
    end

    local vhost_id = config.id

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if vhost already exists
    local existing = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if existing and existing ~= ngx.null then
        utils.close_redis(red)
        return utils.error_response("Vhost already exists: " .. vhost_id, 409)
    end

    -- Check for conflicting hostnames
    if config.hostnames and type(config.hostnames) == "table" then
        for _, host in ipairs(config.hostnames) do
            local host_lower = host:lower()
            if is_catchall_hostname(host_lower) then
                -- Check if catch-all hostname is already used by another vhost
                local existing_vhost = red:hget(VHOST_KEYS.hosts_exact, host_lower)
                if existing_vhost and existing_vhost ~= ngx.null then
                    utils.close_redis(red)
                    return utils.error_response("Catch-all hostname '" .. host .. "' already used by vhost: " .. existing_vhost, 409)
                end
            elseif not host_lower:match("^%*%.") then
                -- Check if exact host already mapped to another vhost
                local existing_vhost = red:hget(VHOST_KEYS.hosts_exact, host_lower)
                if existing_vhost and existing_vhost ~= ngx.null then
                    utils.close_redis(red)
                    return utils.error_response("Host '" .. host .. "' already mapped to vhost: " .. existing_vhost, 409)
                end
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

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        created = true,
        vhost_id = vhost_id,
        vhost = config
    }, 201)
end

-- GET /vhosts/stats - Get vhost statistics
_M.handlers["GET:/vhosts/stats"] = function()
    local stats = vhost_matcher.get_stats()
    return utils.json_response(stats)
end

-- GET /vhosts/match - Test vhost matching
_M.handlers["GET:/vhosts/match"] = function()
    local args = ngx.req.get_uri_args()
    local host = args.host

    if not host then
        return utils.error_response("Missing 'host' query parameter")
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

    return utils.json_response(result)
end

-- GET /vhosts/context - Test full request context resolution
_M.handlers["GET:/vhosts/context"] = function()
    local args = ngx.req.get_uri_args()
    local host = args.host
    local path = args.path or "/"
    local method = args.method or "POST"

    if not host then
        return utils.error_response("Missing 'host' query parameter")
    end

    local context = vhost_resolver.resolve_request_context(host, path, method)
    local summary = vhost_resolver.get_context_summary(context)

    return utils.json_response({
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

-- GET /vhosts/learned-fields - Get learned fields for vhost
_M.handlers["GET:/vhosts/learned-fields"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id

    if not vhost_id then
        return utils.error_response("Missing 'vhost_id' query parameter")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local fields = field_learner.get_vhost_fields(red, vhost_id)
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
        vhost_id = vhost_id,
        fields = field_list,
        count = field_count,
        learning_stats = field_learner.get_stats()
    })
end

-- DELETE /vhosts/learned-fields - Clear learned fields for vhost
_M.handlers["DELETE:/vhosts/learned-fields"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id

    if not vhost_id then
        return utils.error_response("Missing 'vhost_id' query parameter")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local cleared = field_learner.clear_vhost_fields(red, vhost_id)
    utils.close_redis(red)

    return utils.json_response({
        cleared = cleared,
        vhost_id = vhost_id
    })
end

-- ==================== Resource Handlers (parameterized) ====================

-- GET /vhosts/{id} - Get specific vhost configuration
_M.resource_handlers["GET"] = function(vhost_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    utils.close_redis(red)

    if not config_json or config_json == ngx.null then
        return utils.error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)
    if not config then
        return utils.error_response("Invalid vhost configuration", 500)
    end

    -- Include resolved configuration
    local resolved = vhost_resolver.resolve(vhost_id)

    return utils.json_response({
        vhost = config,
        resolved = resolved
    })
end

-- PUT /vhosts/{id} - Update vhost configuration
_M.resource_handlers["PUT"] = function(vhost_id)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local new_config = cjson.decode(body or "{}")

    if not new_config then
        return utils.error_response("Invalid JSON body")
    end

    -- Ensure ID matches
    new_config.id = vhost_id

    -- Validate configuration
    local valid, errors = vhost_matcher.validate_config(new_config)
    if not valid then
        return utils.error_response("Validation failed: " .. table.concat(errors, ", "), 400)
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not existing_json or existing_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Vhost not found: " .. vhost_id, 404)
    end

    local existing_config = cjson.decode(existing_json)

    -- Remove old host mappings first (so we can check for conflicts without hitting ourselves)
    remove_host_mappings(red, vhost_id, existing_config)

    -- Check for conflicting hostnames (including catch-all)
    if new_config.hostnames and type(new_config.hostnames) == "table" then
        for _, host in ipairs(new_config.hostnames) do
            local host_lower = host:lower()
            if is_catchall_hostname(host_lower) then
                -- Check if catch-all hostname is already used by another vhost
                local existing_vhost = red:hget(VHOST_KEYS.hosts_exact, host_lower)
                if existing_vhost and existing_vhost ~= ngx.null and existing_vhost ~= vhost_id then
                    -- Restore old mappings before returning error
                    build_host_mappings(red, vhost_id, existing_config)
                    utils.close_redis(red)
                    return utils.error_response("Catch-all hostname '" .. host .. "' already used by vhost: " .. existing_vhost, 409)
                end
            elseif not host_lower:match("^%*%.") then
                -- Check if exact host already mapped to another vhost
                local existing_vhost = red:hget(VHOST_KEYS.hosts_exact, host_lower)
                if existing_vhost and existing_vhost ~= ngx.null and existing_vhost ~= vhost_id then
                    -- Restore old mappings before returning error
                    build_host_mappings(red, vhost_id, existing_config)
                    utils.close_redis(red)
                    return utils.error_response("Host '" .. host .. "' already mapped to vhost: " .. existing_vhost, 409)
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
    red:set(VHOST_KEYS.config_prefix .. vhost_id, config_json)

    -- Update priority in index
    local priority = new_config.priority or 100
    red:zadd(VHOST_KEYS.index, priority, vhost_id)

    -- Build new host mappings
    build_host_mappings(red, vhost_id, new_config)

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        updated = true,
        vhost_id = vhost_id,
        vhost = new_config
    })
end

-- DELETE /vhosts/{id} - Delete vhost configuration
_M.resource_handlers["DELETE"] = function(vhost_id)
    -- Prevent deleting the default vhost
    if vhost_id == "_default" then
        return utils.error_response("Cannot delete the default vhost", 400)
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not existing_json or existing_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Vhost not found: " .. vhost_id, 404)
    end

    local existing_config = cjson.decode(existing_json)

    -- Remove host mappings
    remove_host_mappings(red, vhost_id, existing_config)

    -- Delete configuration
    red:del(VHOST_KEYS.config_prefix .. vhost_id)

    -- Remove from index
    red:zrem(VHOST_KEYS.index, vhost_id)

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        deleted = true,
        vhost_id = vhost_id
    })
end

-- POST /vhosts/{id}/enable - Enable vhost
_M.resource_handlers["POST:enable"] = function(vhost_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = true
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(VHOST_KEYS.config_prefix .. vhost_id, cjson.encode(config))
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({
        enabled = true,
        vhost_id = vhost_id
    })
end

-- POST /vhosts/{id}/disable - Disable vhost
_M.resource_handlers["POST:disable"] = function(vhost_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = false
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(VHOST_KEYS.config_prefix .. vhost_id, cjson.encode(config))
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({
        disabled = true,
        vhost_id = vhost_id
    })
end

-- ==================== Timing Configuration Handlers ====================

-- GET /vhosts/{id}/timing - Get vhost timing configuration
_M.resource_handlers["GET:timing"] = function(vhost_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get global timing config to read the cookie_name setting
    local global_config_json = red:get("waf:config:timing_token")
    local global_cookie_name = "_waf_timing"  -- Default
    if global_config_json and global_config_json ~= ngx.null then
        local global_config = cjson.decode(global_config_json)
        if global_config and global_config.cookie_name then
            global_cookie_name = global_config.cookie_name
        end
    end

    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    utils.close_redis(red)

    if not config_json or config_json == ngx.null then
        return utils.error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)
    if not config then
        return utils.error_response("Invalid vhost configuration", 500)
    end

    -- Get resolved timing config
    local resolved = vhost_resolver.resolve(vhost_id)

    -- Determine cookie name for this vhost using global cookie_name as base
    local cookie_name = global_cookie_name
    if vhost_id and vhost_id ~= "_default" then
        local safe_id = vhost_id:gsub("[^%w_-]", "")
        cookie_name = global_cookie_name .. "_" .. safe_id
    end

    return utils.json_response({
        vhost_id = vhost_id,
        timing = config.timing or {},
        resolved_timing = resolved.timing,
        cookie_name = resolved.timing and resolved.timing.enabled and cookie_name or nil
    })
end

-- PUT /vhosts/{id}/timing - Update vhost timing configuration
_M.resource_handlers["PUT:timing"] = function(vhost_id)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local timing_config = cjson.decode(body or "{}")

    if not timing_config then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate timing config by wrapping it in a vhost config
    local temp_config = { id = vhost_id, hostnames = {"_"}, timing = timing_config }
    local valid, errors = vhost_matcher.validate_config(temp_config)
    if not valid then
        -- Filter to only timing errors
        local timing_errors = {}
        for _, err in ipairs(errors) do
            if err:match("^timing%.") then
                table.insert(timing_errors, err)
            end
        end
        if #timing_errors > 0 then
            return utils.error_response("Validation failed: " .. table.concat(timing_errors, ", "), 400)
        end
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing vhost config
    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)

    -- Update timing section
    config.timing = timing_config
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    -- Save
    red:set(VHOST_KEYS.config_prefix .. vhost_id, cjson.encode(config))
    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        updated = true,
        vhost_id = vhost_id,
        timing = config.timing
    })
end

-- DELETE /vhosts/{id}/timing - Remove/disable vhost timing configuration
_M.resource_handlers["DELETE:timing"] = function(vhost_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(VHOST_KEYS.config_prefix .. vhost_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Vhost not found: " .. vhost_id, 404)
    end

    local config = cjson.decode(config_json)

    -- Remove timing section
    config.timing = nil
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(VHOST_KEYS.config_prefix .. vhost_id, cjson.encode(config))
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({
        deleted = true,
        vhost_id = vhost_id
    })
end

return _M
