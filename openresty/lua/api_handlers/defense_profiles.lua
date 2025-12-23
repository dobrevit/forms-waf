-- api_handlers/defense_profiles.lua
-- Defense profile management API handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local defense_profiles_store = require "defense_profiles_store"
local defense_profile_executor = require "defense_profile_executor"
local redis_sync = require "redis_sync"

-- Handlers table
_M.handlers = {}

-- GET /defense-profiles - List all profiles
_M.handlers["GET:/defense-profiles"] = function()
    local profiles, err = defense_profiles_store.list()
    if not profiles then
        return utils.error_response("Failed to list profiles: " .. (err or "unknown"), 500)
    end

    return utils.json_response({profiles = profiles})
end

-- POST /defense-profiles - Create a new profile
_M.handlers["POST:/defense-profiles"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate ID format
    if data.id then
        if not data.id:match("^[a-zA-Z0-9_-]+$") then
            return utils.error_response("Profile ID must contain only alphanumeric characters, hyphens, and underscores")
        end
    else
        return utils.error_response("Missing 'id' field")
    end

    if not data.name or data.name == "" then
        return utils.error_response("Missing 'name' field")
    end

    -- Create profile
    local profile, err = defense_profiles_store.create(data)
    if not profile then
        local status = 400
        if err and err:find("already exists") then
            status = 409
        end
        return utils.error_response(err or "Failed to create profile", status)
    end

    redis_sync.sync_now()
    return utils.json_response({created = true, profile = profile})
end

-- GET /defense-profiles/:id - Get a specific profile
_M.handlers["GET:/defense-profiles/:id"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing profile ID")
    end

    local profile, err = defense_profiles_store.get(id)
    if not profile then
        local status = 404
        if err and err:find("not found") then
            status = 404
        else
            status = 500
        end
        return utils.error_response(err or "Failed to get profile", status)
    end

    return utils.json_response({profile = profile})
end

-- PUT /defense-profiles/:id - Update a profile
_M.handlers["PUT:/defense-profiles/:id"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing profile ID")
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local profile, err = defense_profiles_store.update(id, data)
    if not profile then
        local status = 400
        if err and err:find("not found") then
            status = 404
        end
        return utils.error_response(err or "Failed to update profile", status)
    end

    redis_sync.sync_now()
    return utils.json_response({updated = true, profile = profile})
end

-- DELETE /defense-profiles/:id - Delete a profile
_M.handlers["DELETE:/defense-profiles/:id"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing profile ID")
    end

    local ok, err = defense_profiles_store.delete(id)
    if not ok then
        local status = 400
        if err and err:find("not found") then
            status = 404
        elseif err and err:find("Cannot delete builtin") then
            status = 403
        end
        return utils.error_response(err or "Failed to delete profile", status)
    end

    redis_sync.sync_now()
    return utils.json_response({deleted = true, id = id})
end

-- POST /defense-profiles/:id/clone - Clone a profile
_M.handlers["POST:/defense-profiles/:id/clone"] = function(params)
    local source_id = params.id
    if not source_id or source_id == "" then
        return utils.error_response("Missing source profile ID")
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    local new_id = data.id
    local new_name = data.name

    if not new_id or new_id == "" then
        return utils.error_response("Missing 'id' for new profile")
    end

    if not new_id:match("^[a-zA-Z0-9_-]+$") then
        return utils.error_response("Profile ID must contain only alphanumeric characters, hyphens, and underscores")
    end

    local profile, err = defense_profiles_store.clone(source_id, new_id, new_name)
    if not profile then
        local status = 400
        if err and err:find("not found") then
            status = 404
        elseif err and err:find("already exists") then
            status = 409
        end
        return utils.error_response(err or "Failed to clone profile", status)
    end

    redis_sync.sync_now()
    return utils.json_response({cloned = true, profile = profile})
end

-- POST /defense-profiles/:id/enable - Enable a profile
_M.handlers["POST:/defense-profiles/:id/enable"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing profile ID")
    end

    local profile, err = defense_profiles_store.enable(id)
    if not profile then
        local status = 400
        if err and err:find("not found") then
            status = 404
        end
        return utils.error_response(err or "Failed to enable profile", status)
    end

    redis_sync.sync_now()
    return utils.json_response({enabled = true, profile = profile})
end

-- POST /defense-profiles/:id/disable - Disable a profile
_M.handlers["POST:/defense-profiles/:id/disable"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing profile ID")
    end

    local profile, err = defense_profiles_store.disable(id)
    if not profile then
        local status = 400
        if err and err:find("not found") then
            status = 404
        end
        return utils.error_response(err or "Failed to disable profile", status)
    end

    redis_sync.sync_now()
    return utils.json_response({disabled = true, profile = profile})
end

-- GET /defense-profiles/builtins - List builtin profiles
_M.handlers["GET:/defense-profiles/builtins"] = function()
    local ids, err = defense_profiles_store.get_builtin_ids()
    if not ids then
        return utils.error_response("Failed to get builtin IDs: " .. (err or "unknown"), 500)
    end

    return utils.json_response({builtin_ids = ids})
end

-- POST /defense-profiles/validate - Validate a profile graph
_M.handlers["POST:/defense-profiles/validate"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local valid, errors = defense_profile_executor.validate_profile(data)

    return utils.json_response({
        valid = valid,
        errors = errors or {}
    })
end

-- POST /defense-profiles/simulate - Simulate request through a profile
_M.handlers["POST:/defense-profiles/simulate"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Get profile
    local profile
    if data.profile_id then
        local err
        profile, err = defense_profiles_store.get_resolved(data.profile_id)
        if not profile then
            return utils.error_response("Profile not found: " .. data.profile_id, 404)
        end
    elseif data.profile then
        profile = data.profile
    else
        return utils.error_response("Must provide either 'profile_id' or 'profile'")
    end

    -- Validate profile first
    local valid, errors = defense_profile_executor.validate_profile(profile)
    if not valid then
        return utils.json_response({
            valid = false,
            errors = errors,
            simulation_skipped = true
        })
    end

    -- Build mock request context
    local request_context = {
        form_data = data.form_data or {},
        client_ip = data.client_ip or "127.0.0.1",
        host = data.host or "localhost",
        path = data.path or "/",
        method = data.method or "POST",
        headers = data.headers or {},
        content_type = data.content_type or "application/x-www-form-urlencoded",
        -- Mock ngx.var for fingerprint profiles
        ngx_vars = {}
    }

    -- Convert headers to ngx.var format
    for name, value in pairs(request_context.headers) do
        local var_name = "http_" .. name:lower():gsub("-", "_")
        request_context.ngx_vars[var_name] = value
    end

    -- Execute profile
    local result = defense_profile_executor.execute(profile, request_context)

    return utils.json_response({
        valid = true,
        simulation = {
            action = result.action,
            score = result.score,
            flags = result.flags,
            details = result.details,
            block_reason = result.block_reason,
            allow_reason = result.allow_reason,
            tarpit_delay = result.tarpit_delay,
            execution_time_ms = result.execution_time_ms,
            nodes_executed = result.nodes_executed
        }
    })
end

-- GET /defense-profiles/metadata - Get defense/operator/action metadata for UI
_M.handlers["GET:/defense-profiles/metadata"] = function()
    return utils.json_response({
        defenses = defense_profile_executor.get_defense_metadata(),
        operators = defense_profile_executor.get_operator_metadata(),
        actions = defense_profile_executor.get_action_metadata()
    })
end

-- POST /defense-profiles/reset-builtins - Reset builtin profiles to defaults
_M.handlers["POST:/defense-profiles/reset-builtins"] = function()
    local builtins = require "defense_profiles_builtins"
    local count, err = defense_profiles_store.reset_builtins(builtins.PROFILES)
    if not count then
        return utils.error_response("Failed to reset builtins: " .. (err or "unknown"), 500)
    end

    redis_sync.sync_now()
    return utils.json_response({reset = true, count = count})
end

-- GET /defense-profiles/:id/resolved - Get profile with inheritance resolved
_M.handlers["GET:/defense-profiles/:id/resolved"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing profile ID")
    end

    local profile, err = defense_profiles_store.get_resolved(id)
    if not profile then
        local status = 404
        if err and err:find("not found") then
            status = 404
        elseif err and err:find("inheritance") then
            status = 400
        else
            status = 500
        end
        return utils.error_response(err or "Failed to resolve profile", status)
    end

    return utils.json_response({profile = profile})
end

return _M
