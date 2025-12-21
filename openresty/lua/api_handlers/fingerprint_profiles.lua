-- api_handlers/fingerprint_profiles.lua
-- Fingerprint profile management handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"
local fingerprint_profiles = require "fingerprint_profiles"

-- Redis keys (must match redis_sync.lua)
local KEYS = {
    profiles_index = "waf:fingerprint:profiles:index",
    profiles_config_prefix = "waf:fingerprint:profiles:config:",
    profiles_builtin = "waf:fingerprint:profiles:builtin"
}

-- Handlers table
_M.handlers = {}

-- Validate profile data
local function validate_profile(data, is_update)
    local errors = {}

    -- Required fields for create
    if not is_update then
        if not data.id or data.id == "" then
            table.insert(errors, "Missing 'id' field")
        elseif not data.id:match("^[a-zA-Z0-9_-]+$") then
            table.insert(errors, "Profile ID must contain only alphanumeric characters, hyphens, and underscores")
        end
        if not data.name or data.name == "" then
            table.insert(errors, "Missing 'name' field")
        end
    end

    -- Validate action if provided
    if data.action then
        local valid_actions = {allow = true, block = true, flag = true, ignore = true}
        if not valid_actions[data.action] then
            table.insert(errors, "Invalid 'action': must be allow, block, flag, or ignore")
        end
    end

    -- Validate priority if provided
    if data.priority ~= nil then
        if type(data.priority) ~= "number" or data.priority < 0 then
            table.insert(errors, "Priority must be a non-negative number")
        end
    end

    -- Validate matching conditions
    if data.matching then
        if data.matching.match_mode then
            if data.matching.match_mode ~= "all" and data.matching.match_mode ~= "any" then
                table.insert(errors, "Invalid 'match_mode': must be 'all' or 'any'")
            end
        end

        if data.matching.conditions then
            if type(data.matching.conditions) ~= "table" then
                table.insert(errors, "Matching conditions must be an array")
            else
                for i, condition in ipairs(data.matching.conditions) do
                    if not condition.header or condition.header == "" then
                        table.insert(errors, string.format("Condition %d: missing 'header' field", i))
                    end
                    if not condition.condition then
                        table.insert(errors, string.format("Condition %d: missing 'condition' field", i))
                    else
                        local valid_conditions = {present = true, absent = true, matches = true, not_matches = true}
                        if not valid_conditions[condition.condition] then
                            table.insert(errors, string.format("Condition %d: invalid condition type", i))
                        end
                        -- Pattern required for matches/not_matches
                        if (condition.condition == "matches" or condition.condition == "not_matches") then
                            if not condition.pattern or condition.pattern == "" then
                                table.insert(errors, string.format("Condition %d: 'pattern' required for matches/not_matches", i))
                            end
                        end
                    end
                end
            end
        end
    end

    -- Validate fingerprint_headers
    if data.fingerprint_headers then
        if data.fingerprint_headers.headers and type(data.fingerprint_headers.headers) ~= "table" then
            table.insert(errors, "fingerprint_headers.headers must be an array")
        end
        if data.fingerprint_headers.max_length ~= nil then
            if type(data.fingerprint_headers.max_length) ~= "number" or data.fingerprint_headers.max_length < 1 then
                table.insert(errors, "fingerprint_headers.max_length must be a positive number")
            end
        end
    end

    -- Validate rate_limiting
    if data.rate_limiting then
        if data.rate_limiting.fingerprint_rate_limit ~= nil then
            if type(data.rate_limiting.fingerprint_rate_limit) ~= "number" or data.rate_limiting.fingerprint_rate_limit < 1 then
                table.insert(errors, "rate_limiting.fingerprint_rate_limit must be a positive number")
            end
        end
    end

    return #errors == 0, errors
end

-- GET /fingerprint-profiles - List all profiles
_M.handlers["GET:/fingerprint-profiles"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get all profile IDs from the sorted set (sorted by priority)
    local profile_ids = red:zrange(KEYS.profiles_index, 0, -1)
    if not profile_ids or type(profile_ids) ~= "table" then
        utils.close_redis(red)
        return utils.json_response({profiles = {}})
    end

    -- Get built-in profile IDs
    local builtin_ids = red:smembers(KEYS.profiles_builtin)
    local builtin_set = {}
    if builtin_ids and type(builtin_ids) == "table" then
        for _, id in ipairs(builtin_ids) do
            builtin_set[id] = true
        end
    end

    -- Fetch each profile config
    local profiles = {}
    for _, profile_id in ipairs(profile_ids) do
        local config_json = red:get(KEYS.profiles_config_prefix .. profile_id)
        if config_json and config_json ~= ngx.null then
            local profile = cjson.decode(config_json)
            if profile then
                -- Ensure builtin flag is set correctly
                profile.builtin = builtin_set[profile_id] or false
                table.insert(profiles, profile)
            end
        end
    end

    utils.close_redis(red)
    return utils.json_response({profiles = profiles})
end

-- POST /fingerprint-profiles - Create a custom profile
_M.handlers["POST:/fingerprint-profiles"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate profile data
    local valid, errors = validate_profile(data, false)
    if not valid then
        return utils.error_response("Validation failed: " .. table.concat(errors, "; "))
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if profile ID already exists
    local existing = red:get(KEYS.profiles_config_prefix .. data.id)
    if existing and existing ~= ngx.null then
        utils.close_redis(red)
        return utils.error_response("Profile already exists: " .. data.id, 409)
    end

    -- Set defaults
    data.enabled = data.enabled ~= false
    data.builtin = false  -- Custom profiles are never built-in
    data.priority = data.priority or 500  -- Default priority for custom profiles
    data.action = data.action or "allow"
    data.score = data.score or 0

    if not data.matching then
        data.matching = {
            conditions = {},
            match_mode = "all"
        }
    end

    if not data.fingerprint_headers then
        data.fingerprint_headers = {
            headers = {"User-Agent", "Accept-Language", "Accept-Encoding"},
            normalize = true,
            max_length = 100
        }
    end

    if not data.rate_limiting then
        data.rate_limiting = {
            enabled = true
        }
    end

    -- Store profile
    local profile_json = cjson.encode(data)
    red:set(KEYS.profiles_config_prefix .. data.id, profile_json)
    red:zadd(KEYS.profiles_index, data.priority, data.id)

    utils.close_redis(red)
    redis_sync.sync_now()

    return utils.json_response({created = true, profile = data})
end

-- GET /fingerprint-profiles/:id - Get a specific profile
_M.handlers["GET:/fingerprint-profiles/:id"] = function(params)
    local profile_id = params.id
    if not profile_id or profile_id == "" then
        return utils.error_response("Missing profile ID")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(KEYS.profiles_config_prefix .. profile_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Profile not found: " .. profile_id, 404)
    end

    local profile = cjson.decode(config_json)
    if not profile then
        utils.close_redis(red)
        return utils.error_response("Invalid profile data", 500)
    end

    -- Check if built-in
    local is_builtin = red:sismember(KEYS.profiles_builtin, profile_id)
    profile.builtin = is_builtin == 1

    utils.close_redis(red)
    return utils.json_response({profile = profile})
end

-- PUT /fingerprint-profiles/:id - Update a profile
_M.handlers["PUT:/fingerprint-profiles/:id"] = function(params)
    local profile_id = params.id
    if not profile_id or profile_id == "" then
        return utils.error_response("Missing profile ID")
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate profile data
    local valid, errors = validate_profile(data, true)
    if not valid then
        return utils.error_response("Validation failed: " .. table.concat(errors, "; "))
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing profile
    local config_json = red:get(KEYS.profiles_config_prefix .. profile_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Profile not found: " .. profile_id, 404)
    end

    local existing = cjson.decode(config_json)
    if not existing then
        utils.close_redis(red)
        return utils.error_response("Invalid existing profile data", 500)
    end

    -- Check if built-in
    local is_builtin = red:sismember(KEYS.profiles_builtin, profile_id) == 1

    -- Merge updates (deep merge for nested objects)
    local function deep_merge(base, updates)
        for k, v in pairs(updates) do
            if type(v) == "table" and type(base[k]) == "table" then
                deep_merge(base[k], v)
            else
                base[k] = v
            end
        end
    end

    deep_merge(existing, data)

    -- Preserve immutable fields
    existing.id = profile_id  -- ID cannot change
    existing.builtin = is_builtin  -- Builtin status cannot change

    -- Update priority in sorted set if changed
    if data.priority then
        red:zadd(KEYS.profiles_index, existing.priority, profile_id)
    end

    -- Store updated profile
    local updated_json = cjson.encode(existing)
    red:set(KEYS.profiles_config_prefix .. profile_id, updated_json)

    utils.close_redis(red)
    redis_sync.sync_now()

    return utils.json_response({updated = true, profile = existing})
end

-- DELETE /fingerprint-profiles/:id - Delete a custom profile
_M.handlers["DELETE:/fingerprint-profiles/:id"] = function(params)
    local profile_id = params.id
    if not profile_id or profile_id == "" then
        return utils.error_response("Missing profile ID")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if profile exists
    local exists = red:exists(KEYS.profiles_config_prefix .. profile_id)
    if exists ~= 1 then
        utils.close_redis(red)
        return utils.error_response("Profile not found: " .. profile_id, 404)
    end

    -- Check if built-in (cannot delete built-in profiles)
    local is_builtin = red:sismember(KEYS.profiles_builtin, profile_id)
    if is_builtin == 1 then
        utils.close_redis(red)
        return utils.error_response("Cannot delete built-in profile: " .. profile_id, 403)
    end

    -- Delete profile
    red:del(KEYS.profiles_config_prefix .. profile_id)
    red:zrem(KEYS.profiles_index, profile_id)

    utils.close_redis(red)
    redis_sync.sync_now()

    return utils.json_response({deleted = true, id = profile_id})
end

-- POST /fingerprint-profiles/test - Test profile matching against headers
_M.handlers["POST:/fingerprint-profiles/test"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.headers then
        return utils.error_response("Missing 'headers' field (object with header name/value pairs)")
    end

    -- Build mock ngx.var-like table from headers
    local mock_vars = {}
    for header_name, value in pairs(data.headers) do
        -- Convert header name to nginx variable format
        local var_name = "http_" .. header_name:lower():gsub("-", "_")
        mock_vars[var_name] = value
    end

    -- Get optional profile filter
    local profile_ids = data.profiles  -- nil = all profiles

    -- Match profiles
    local matched = fingerprint_profiles.match_profiles(mock_vars, profile_ids)

    -- Get action result
    local no_match_config = data.no_match_config or {
        no_match_action = "use_default",
        no_match_score = 15
    }
    local action_result = fingerprint_profiles.aggregate_actions(matched, no_match_config)

    -- Generate fingerprint if any profile matched
    local fingerprint = nil
    if action_result.fingerprint_profile then
        fingerprint = fingerprint_profiles.generate_fingerprint(
            data.form_fields or {},
            mock_vars,
            action_result.fingerprint_profile
        )
    end

    -- Build response
    local matched_summary = {}
    for _, profile in ipairs(matched) do
        table.insert(matched_summary, {
            id = profile.id,
            name = profile.name,
            priority = profile.priority,
            action = profile.action,
            score = profile.score
        })
    end

    return utils.json_response({
        matched_profiles = matched_summary,
        result = {
            blocked = action_result.blocked,
            ignored = action_result.ignored,
            total_score = action_result.total_score,
            flags = action_result.flags,
            fingerprint_profile_id = action_result.fingerprint_profile and action_result.fingerprint_profile.id,
            fingerprint_rate_limit = action_result.fingerprint_rate_limit,
            fingerprint = fingerprint
        }
    })
end

-- POST /fingerprint-profiles/reset-builtin - Reset built-in profiles to defaults
_M.handlers["POST:/fingerprint-profiles/reset-builtin"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get built-in profile IDs
    local builtin_ids = red:smembers(KEYS.profiles_builtin)
    if not builtin_ids or type(builtin_ids) ~= "table" or #builtin_ids == 0 then
        utils.close_redis(red)
        return utils.error_response("No built-in profiles found", 404)
    end

    -- Get default built-in profiles from module
    local default_profiles = fingerprint_profiles.BUILTIN_PROFILES

    -- Build lookup by ID
    local default_by_id = {}
    for _, profile in ipairs(default_profiles) do
        default_by_id[profile.id] = profile
    end

    -- Reset each built-in profile
    local reset_count = 0
    for _, profile_id in ipairs(builtin_ids) do
        local default_profile = default_by_id[profile_id]
        if default_profile then
            local profile_json = cjson.encode(default_profile)
            red:set(KEYS.profiles_config_prefix .. profile_id, profile_json)
            red:zadd(KEYS.profiles_index, default_profile.priority, profile_id)
            reset_count = reset_count + 1
        end
    end

    utils.close_redis(red)
    redis_sync.sync_now()

    return utils.json_response({reset = true, count = reset_count})
end

return _M
