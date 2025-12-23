-- defense_profiles_store.lua
-- Redis storage layer for defense profiles

local _M = {}

local cjson = require "cjson.safe"
local defense_profile_executor = require "defense_profile_executor"

-- Redis keys
local KEYS = {
    index = "waf:defense_profiles:index",              -- Sorted set of profile IDs (by priority)
    config_prefix = "waf:defense_profiles:config:",    -- JSON profile config
    builtin = "waf:defense_profiles:builtin",          -- Set of builtin profile IDs
    cache_version = "waf:defense_profiles:version"     -- Cache invalidation version
}

-- Local cache
local profile_cache = {}
local cache_version = 0
local cache_ttl = 60  -- seconds

-- Export keys for redis_sync
_M.KEYS = KEYS

-- Get Redis connection (uses shared dict for connection pooling)
local function get_redis()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(1000)

    local ok, err = red:connect(os.getenv("REDIS_HOST") or "redis", tonumber(os.getenv("REDIS_PORT") or 6379))
    if not ok then
        return nil, err
    end

    -- Authentication if required
    local redis_password = os.getenv("REDIS_PASSWORD")
    if redis_password and redis_password ~= "" then
        local res, auth_err = red:auth(redis_password)
        if not res then
            return nil, auth_err
        end
    end

    return red
end

-- Close Redis connection (return to pool)
local function close_redis(red)
    if red then
        local ok, err = red:set_keepalive(10000, 100)
        if not ok then
            ngx.log(ngx.WARN, "Failed to set redis keepalive: ", err)
        end
    end
end

-- Check if cache is valid
local function is_cache_valid()
    local red, err = get_redis()
    if not red then
        return true  -- Assume valid if can't check
    end

    local version = red:get(KEYS.cache_version)
    close_redis(red)

    if version and version ~= ngx.null then
        return tonumber(version) == cache_version
    end

    return cache_version == 0
end

-- Invalidate cache
local function invalidate_cache()
    local red, err = get_redis()
    if not red then
        ngx.log(ngx.WARN, "Failed to get redis for cache invalidation: ", err)
        return
    end

    red:incr(KEYS.cache_version)
    close_redis(red)
    profile_cache = {}
end

-- List all profile IDs
function _M.list_ids()
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local ids = red:zrange(KEYS.index, 0, -1)
    close_redis(red)

    if not ids or type(ids) ~= "table" then
        return {}
    end

    return ids
end

-- Get all profiles
function _M.list()
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Get all profile IDs sorted by priority
    local ids = red:zrange(KEYS.index, 0, -1)
    if not ids or type(ids) ~= "table" then
        close_redis(red)
        return {}
    end

    -- Get builtin set
    local builtin_ids = red:smembers(KEYS.builtin)
    local builtin_set = {}
    if builtin_ids and type(builtin_ids) == "table" then
        for _, id in ipairs(builtin_ids) do
            builtin_set[id] = true
        end
    end

    -- Fetch each profile
    local profiles = {}
    for _, id in ipairs(ids) do
        local config_json = red:get(KEYS.config_prefix .. id)
        if config_json and config_json ~= ngx.null then
            local profile = cjson.decode(config_json)
            if profile then
                profile.builtin = builtin_set[id] or false
                table.insert(profiles, profile)
            end
        end
    end

    close_redis(red)
    return profiles
end

-- Get a single profile by ID
function _M.get(id)
    if not id or id == "" then
        return nil, "Missing profile ID"
    end

    -- Check cache first
    if profile_cache[id] and is_cache_valid() then
        return profile_cache[id]
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local config_json = red:get(KEYS.config_prefix .. id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return nil, "Profile not found: " .. id
    end

    local profile = cjson.decode(config_json)
    if not profile then
        close_redis(red)
        return nil, "Invalid profile data"
    end

    -- Check builtin status
    local is_builtin = red:sismember(KEYS.builtin, id)
    profile.builtin = is_builtin == 1

    close_redis(red)

    -- Update cache
    profile_cache[id] = profile

    return profile
end

-- Create a new profile
function _M.create(profile)
    if not profile then
        return nil, "Missing profile data"
    end

    if not profile.id or profile.id == "" then
        return nil, "Missing profile ID"
    end

    -- Validate profile structure
    local valid, errors = defense_profile_executor.validate_profile(profile)
    if not valid then
        return nil, "Validation failed: " .. table.concat(errors, "; ")
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Check if ID already exists
    local exists = red:exists(KEYS.config_prefix .. profile.id)
    if exists == 1 then
        close_redis(red)
        return nil, "Profile already exists: " .. profile.id
    end

    -- Set defaults
    profile.enabled = profile.enabled ~= false
    profile.builtin = false
    profile.priority = profile.priority or 500

    if not profile.settings then
        profile.settings = {
            default_action = "allow",
            max_execution_time_ms = 100
        }
    end

    -- Store profile
    local profile_json = cjson.encode(profile)
    red:set(KEYS.config_prefix .. profile.id, profile_json)
    red:zadd(KEYS.index, profile.priority, profile.id)

    close_redis(red)
    invalidate_cache()

    return profile
end

-- Update an existing profile
function _M.update(id, updates)
    if not id or id == "" then
        return nil, "Missing profile ID"
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Get existing profile
    local config_json = red:get(KEYS.config_prefix .. id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return nil, "Profile not found: " .. id
    end

    local profile = cjson.decode(config_json)
    if not profile then
        close_redis(red)
        return nil, "Invalid profile data"
    end

    -- Check builtin status
    local is_builtin = red:sismember(KEYS.builtin, id) == 1

    -- Deep merge updates
    local function deep_merge(base, updates_tbl)
        for k, v in pairs(updates_tbl) do
            if type(v) == "table" and type(base[k]) == "table" then
                deep_merge(base[k], v)
            else
                base[k] = v
            end
        end
    end

    deep_merge(profile, updates)

    -- Preserve immutable fields
    profile.id = id
    profile.builtin = is_builtin

    -- Validate updated profile
    local valid, errors = defense_profile_executor.validate_profile(profile)
    if not valid then
        close_redis(red)
        return nil, "Validation failed: " .. table.concat(errors, "; ")
    end

    -- Update priority in sorted set if changed
    if updates.priority then
        red:zadd(KEYS.index, profile.priority, id)
    end

    -- Store updated profile
    local updated_json = cjson.encode(profile)
    red:set(KEYS.config_prefix .. id, updated_json)

    close_redis(red)
    invalidate_cache()

    return profile
end

-- Delete a profile
function _M.delete(id)
    if not id or id == "" then
        return nil, "Missing profile ID"
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Check if exists
    local exists = red:exists(KEYS.config_prefix .. id)
    if exists ~= 1 then
        close_redis(red)
        return nil, "Profile not found: " .. id
    end

    -- Check if builtin (cannot delete builtin profiles)
    local is_builtin = red:sismember(KEYS.builtin, id)
    if is_builtin == 1 then
        close_redis(red)
        return nil, "Cannot delete builtin profile: " .. id
    end

    -- Delete profile
    red:del(KEYS.config_prefix .. id)
    red:zrem(KEYS.index, id)

    close_redis(red)
    invalidate_cache()

    return true
end

-- Clone a profile
function _M.clone(source_id, new_id, new_name)
    if not source_id or source_id == "" then
        return nil, "Missing source profile ID"
    end

    if not new_id or new_id == "" then
        return nil, "Missing new profile ID"
    end

    -- Get source profile
    local source, err = _M.get(source_id)
    if not source then
        return nil, err
    end

    -- Create clone
    local clone = cjson.decode(cjson.encode(source))  -- Deep copy
    clone.id = new_id
    clone.name = new_name or (source.name .. " (Copy)")
    clone.builtin = false

    return _M.create(clone)
end

-- Enable a profile
function _M.enable(id)
    return _M.update(id, {enabled = true})
end

-- Disable a profile
function _M.disable(id)
    return _M.update(id, {enabled = false})
end

-- Get builtin profile IDs
function _M.get_builtin_ids()
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local ids = red:smembers(KEYS.builtin)
    close_redis(red)

    if not ids or type(ids) ~= "table" then
        return {}
    end

    return ids
end

-- Check if profile is builtin
function _M.is_builtin(id)
    local red, err = get_redis()
    if not red then
        return false
    end

    local is_builtin = red:sismember(KEYS.builtin, id)
    close_redis(red)

    return is_builtin == 1
end

-- Initialize builtin profiles
function _M.init_builtins(profiles)
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local initialized = 0
    for _, profile in ipairs(profiles) do
        -- Only create if doesn't exist
        local exists = red:exists(KEYS.config_prefix .. profile.id)
        if exists ~= 1 then
            profile.builtin = true
            local profile_json = cjson.encode(profile)
            red:set(KEYS.config_prefix .. profile.id, profile_json)
            red:zadd(KEYS.index, profile.priority or 100, profile.id)
            red:sadd(KEYS.builtin, profile.id)
            initialized = initialized + 1
        end
    end

    close_redis(red)
    invalidate_cache()

    return initialized
end

-- Reset builtin profiles to defaults
function _M.reset_builtins(default_profiles)
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Get current builtin IDs
    local builtin_ids = red:smembers(KEYS.builtin)
    if not builtin_ids or type(builtin_ids) ~= "table" then
        close_redis(red)
        return 0
    end

    -- Build lookup by ID
    local default_by_id = {}
    for _, profile in ipairs(default_profiles) do
        default_by_id[profile.id] = profile
    end

    -- Reset each builtin
    local reset_count = 0
    for _, id in ipairs(builtin_ids) do
        local default_profile = default_by_id[id]
        if default_profile then
            default_profile.builtin = true
            local profile_json = cjson.encode(default_profile)
            red:set(KEYS.config_prefix .. id, profile_json)
            red:zadd(KEYS.index, default_profile.priority or 100, id)
            reset_count = reset_count + 1
        end
    end

    close_redis(red)
    invalidate_cache()

    return reset_count
end

-- Get profile for request context (with inheritance resolution)
function _M.get_resolved(id)
    local profile, err = _M.get(id)
    if not profile then
        return nil, err
    end

    -- Resolve inheritance
    return defense_profile_executor.resolve_inheritance(profile, _M.get)
end

-- Get enabled profiles sorted by priority
function _M.get_enabled()
    local profiles, err = _M.list()
    if not profiles then
        return nil, err
    end

    local enabled = {}
    for _, profile in ipairs(profiles) do
        if profile.enabled then
            table.insert(enabled, profile)
        end
    end

    return enabled
end

-- Sync profiles from shared memory (called by redis_sync)
function _M.sync_to_shared(shared_dict_name)
    local shared = ngx.shared[shared_dict_name]
    if not shared then
        return nil, "Shared dict not found: " .. shared_dict_name
    end

    local profiles, err = _M.list()
    if not profiles then
        return nil, err
    end

    -- Store profiles in shared dict
    for _, profile in ipairs(profiles) do
        local key = "defense_profile:" .. profile.id
        local json = cjson.encode(profile)
        shared:set(key, json, cache_ttl)
    end

    -- Store index
    local ids = {}
    for _, profile in ipairs(profiles) do
        if profile.enabled then
            table.insert(ids, profile.id)
        end
    end
    shared:set("defense_profiles:enabled", cjson.encode(ids), cache_ttl)

    return #profiles
end

-- Load profile from shared memory (fast path)
function _M.get_from_shared(id, shared_dict_name)
    shared_dict_name = shared_dict_name or "waf_profiles"
    local shared = ngx.shared[shared_dict_name]
    if not shared then
        -- Fall back to Redis
        return _M.get(id)
    end

    local json = shared:get("defense_profile:" .. id)
    if not json then
        -- Not in shared, load from Redis and cache
        local profile, err = _M.get(id)
        if profile then
            shared:set("defense_profile:" .. id, cjson.encode(profile), cache_ttl)
        end
        return profile, err
    end

    return cjson.decode(json)
end

return _M
