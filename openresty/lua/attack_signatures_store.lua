-- attack_signatures_store.lua
-- Redis storage layer for attack signatures

local _M = {}

local cjson = require "cjson.safe"

-- Redis keys
local KEYS = {
    index = "waf:attack_signatures:index",              -- Sorted set of signature IDs (by priority)
    config_prefix = "waf:attack_signatures:config:",    -- JSON signature config
    builtin = "waf:attack_signatures:builtin",          -- Set of builtin signature IDs
    active = "waf:attack_signatures:active",            -- Set of enabled signature IDs
    by_tag_prefix = "waf:attack_signatures:by_tag:",    -- Set of signature IDs with tag
    stats_prefix = "waf:attack_signatures:stats:global:", -- Global aggregated stats
    cache_version = "waf:attack_signatures:version"     -- Cache invalidation version
}

-- Local cache
local signature_cache = {}
local cache_version = 0
local cache_ttl = 60  -- seconds

-- Export keys for redis_sync
_M.KEYS = KEYS

-- Get Redis connection
local function get_redis()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(1000)

    local ok, err = red:connect(os.getenv("REDIS_HOST") or "redis", tonumber(os.getenv("REDIS_PORT") or 6379))
    if not ok then
        return nil, err
    end

    local redis_password = os.getenv("REDIS_PASSWORD")
    if redis_password and redis_password ~= "" then
        local res, auth_err = red:auth(redis_password)
        if not res then
            return nil, auth_err
        end
    end

    return red
end

-- Close Redis connection
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
        return true
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
    signature_cache = {}
end

-- Update tag index
local function update_tag_index(red, id, old_tags, new_tags)
    old_tags = old_tags or {}
    new_tags = new_tags or {}

    -- Remove from old tags
    for _, tag in ipairs(old_tags) do
        red:srem(KEYS.by_tag_prefix .. tag, id)
    end

    -- Add to new tags
    for _, tag in ipairs(new_tags) do
        red:sadd(KEYS.by_tag_prefix .. tag, id)
    end
end

-- Update active set
local function update_active_set(red, id, enabled)
    if enabled then
        red:sadd(KEYS.active, id)
    else
        red:srem(KEYS.active, id)
    end
end

-- Validate signature structure
function _M.validate(signature)
    local errors = {}

    if not signature.id or signature.id == "" then
        table.insert(errors, "Missing signature ID")
    elseif not signature.id:match("^[a-zA-Z0-9_-]+$") then
        table.insert(errors, "Signature ID must contain only alphanumeric characters, hyphens, and underscores")
    end

    if not signature.name or signature.name == "" then
        table.insert(errors, "Missing signature name")
    end

    if signature.signatures then
        -- Validate signature sections (basic validation)
        local valid_sections = {
            "ip_allowlist", "geoip", "ip_reputation", "timing_token",
            "behavioral", "honeypot", "keyword_filter", "content_hash",
            "expected_fields", "pattern_scan", "disposable_email",
            "field_anomalies", "fingerprint", "header_consistency", "rate_limiter"
        }
        local valid_section_set = {}
        for _, s in ipairs(valid_sections) do
            valid_section_set[s] = true
        end

        for section, _ in pairs(signature.signatures) do
            if not valid_section_set[section] then
                table.insert(errors, "Unknown signature section: " .. section)
            end
        end
    end

    if signature.expires_at then
        -- Basic ISO8601 date validation
        if not signature.expires_at:match("^%d%d%d%d%-%d%d%-%d%d") then
            table.insert(errors, "Invalid expires_at format (expected ISO8601)")
        end
    end

    return #errors == 0, errors
end

-- List all signature IDs
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

-- Get all signatures
function _M.list(opts)
    opts = opts or {}
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Get IDs, optionally filtered
    local ids
    if opts.tag then
        ids = red:smembers(KEYS.by_tag_prefix .. opts.tag)
    elseif opts.active_only then
        ids = red:smembers(KEYS.active)
    else
        ids = red:zrange(KEYS.index, 0, -1)
    end

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

    -- Fetch each signature
    local signatures = {}
    for _, id in ipairs(ids) do
        local config_json = red:get(KEYS.config_prefix .. id)
        if config_json and config_json ~= ngx.null then
            local signature = cjson.decode(config_json)
            if signature then
                signature.builtin = builtin_set[id] or false

                -- Get stats if requested
                if opts.include_stats then
                    local stats = red:hgetall(KEYS.stats_prefix .. id)
                    if stats and type(stats) == "table" and #stats > 0 then
                        signature.stats = {}
                        for i = 1, #stats, 2 do
                            signature.stats[stats[i]] = tonumber(stats[i + 1]) or stats[i + 1]
                        end
                    end
                end

                -- Filter by enabled status if specified
                if opts.enabled ~= nil then
                    if (opts.enabled and signature.enabled) or (not opts.enabled and not signature.enabled) then
                        table.insert(signatures, signature)
                    end
                else
                    table.insert(signatures, signature)
                end
            end
        end
    end

    close_redis(red)

    -- Sort by priority
    table.sort(signatures, function(a, b)
        return (a.priority or 100) < (b.priority or 100)
    end)

    return signatures
end

-- Get a single signature by ID
function _M.get(id)
    if not id or id == "" then
        return nil, "Missing signature ID"
    end

    -- Check cache first
    if signature_cache[id] and is_cache_valid() then
        return signature_cache[id]
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local config_json = red:get(KEYS.config_prefix .. id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return nil, "Signature not found: " .. id
    end

    local signature = cjson.decode(config_json)
    if not signature then
        close_redis(red)
        return nil, "Invalid signature data"
    end

    -- Check builtin status
    local is_builtin = red:sismember(KEYS.builtin, id)
    signature.builtin = is_builtin == 1

    close_redis(red)

    -- Update cache
    signature_cache[id] = signature

    return signature
end

-- Create a new signature
function _M.create(signature)
    if not signature then
        return nil, "Missing signature data"
    end

    -- Validate
    local valid, errors = _M.validate(signature)
    if not valid then
        return nil, "Validation failed: " .. table.concat(errors, "; ")
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Check if ID already exists
    local exists = red:exists(KEYS.config_prefix .. signature.id)
    if exists == 1 then
        close_redis(red)
        return nil, "Signature already exists: " .. signature.id
    end

    -- Set defaults
    signature.enabled = signature.enabled ~= false
    signature.builtin = false
    signature.priority = signature.priority or 100
    signature.created_at = ngx.utctime()
    signature.updated_at = signature.created_at

    -- Store signature
    local signature_json = cjson.encode(signature)
    red:set(KEYS.config_prefix .. signature.id, signature_json)
    red:zadd(KEYS.index, signature.priority, signature.id)

    -- Update indices
    update_active_set(red, signature.id, signature.enabled)
    update_tag_index(red, signature.id, {}, signature.tags)

    close_redis(red)
    invalidate_cache()

    return signature
end

-- Update an existing signature
function _M.update(id, updates)
    if not id or id == "" then
        return nil, "Missing signature ID"
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Get existing signature
    local config_json = red:get(KEYS.config_prefix .. id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return nil, "Signature not found: " .. id
    end

    local signature = cjson.decode(config_json)
    if not signature then
        close_redis(red)
        return nil, "Invalid signature data"
    end

    local old_tags = signature.tags

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

    deep_merge(signature, updates)

    -- Preserve immutable fields
    signature.id = id
    signature.builtin = is_builtin
    signature.created_at = signature.created_at or ngx.utctime()
    signature.updated_at = ngx.utctime()

    -- Validate updated signature
    local valid, errors = _M.validate(signature)
    if not valid then
        close_redis(red)
        return nil, "Validation failed: " .. table.concat(errors, "; ")
    end

    -- Update priority in sorted set if changed
    if updates.priority then
        red:zadd(KEYS.index, signature.priority, id)
    end

    -- Update indices
    update_active_set(red, id, signature.enabled)
    update_tag_index(red, id, old_tags, signature.tags)

    -- Store updated signature
    local updated_json = cjson.encode(signature)
    red:set(KEYS.config_prefix .. id, updated_json)

    close_redis(red)
    invalidate_cache()

    return signature
end

-- Delete a signature
function _M.delete(id)
    if not id or id == "" then
        return nil, "Missing signature ID"
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Check if exists
    local config_json = red:get(KEYS.config_prefix .. id)
    if not config_json or config_json == ngx.null then
        close_redis(red)
        return nil, "Signature not found: " .. id
    end

    -- Check if builtin (cannot delete builtin)
    local is_builtin = red:sismember(KEYS.builtin, id)
    if is_builtin == 1 then
        close_redis(red)
        return nil, "Cannot delete builtin signature: " .. id
    end

    -- Get tags for cleanup
    local signature = cjson.decode(config_json)
    local tags = signature and signature.tags or {}

    -- Delete signature
    red:del(KEYS.config_prefix .. id)
    red:zrem(KEYS.index, id)
    red:srem(KEYS.active, id)

    -- Remove from tag indices
    for _, tag in ipairs(tags) do
        red:srem(KEYS.by_tag_prefix .. tag, id)
    end

    -- Delete stats
    red:del(KEYS.stats_prefix .. id)

    close_redis(red)
    invalidate_cache()

    return true
end

-- Clone a signature
function _M.clone(source_id, new_id, new_name)
    if not source_id or source_id == "" then
        return nil, "Missing source signature ID"
    end

    if not new_id or new_id == "" then
        return nil, "Missing new signature ID"
    end

    -- Get source signature
    local source, err = _M.get(source_id)
    if not source then
        return nil, err
    end

    -- Create clone
    local clone = cjson.decode(cjson.encode(source))  -- Deep copy
    clone.id = new_id
    clone.name = new_name or (source.name .. " (Copy)")
    clone.builtin = false
    clone.stats = nil  -- Reset stats

    return _M.create(clone)
end

-- Enable a signature
function _M.enable(id)
    return _M.update(id, {enabled = true})
end

-- Disable a signature
function _M.disable(id)
    return _M.update(id, {enabled = false})
end

-- Get builtin signature IDs
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

-- Check if signature is builtin
function _M.is_builtin(id)
    local red, err = get_redis()
    if not red then
        return false
    end

    local is_builtin = red:sismember(KEYS.builtin, id)
    close_redis(red)

    return is_builtin == 1
end

-- Initialize builtin signatures
function _M.init_builtins(signatures)
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local initialized = 0
    for _, signature in ipairs(signatures) do
        -- Only create if doesn't exist
        local exists = red:exists(KEYS.config_prefix .. signature.id)
        if exists ~= 1 then
            signature.builtin = true
            signature.created_at = ngx.utctime()
            signature.updated_at = signature.created_at
            local signature_json = cjson.encode(signature)
            red:set(KEYS.config_prefix .. signature.id, signature_json)
            red:zadd(KEYS.index, signature.priority or 100, signature.id)
            red:sadd(KEYS.builtin, signature.id)
            if signature.enabled ~= false then
                red:sadd(KEYS.active, signature.id)
            end
            -- Update tag index
            if signature.tags then
                for _, tag in ipairs(signature.tags) do
                    red:sadd(KEYS.by_tag_prefix .. tag, signature.id)
                end
            end
            initialized = initialized + 1
        end
    end

    close_redis(red)
    invalidate_cache()

    return initialized
end

-- Reset builtin signatures to defaults
function _M.reset_builtins(default_signatures)
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
    for _, signature in ipairs(default_signatures) do
        default_by_id[signature.id] = signature
    end

    -- Reset each builtin
    local reset_count = 0
    for _, id in ipairs(builtin_ids) do
        local default_sig = default_by_id[id]
        if default_sig then
            -- Get old tags for cleanup
            local old_json = red:get(KEYS.config_prefix .. id)
            local old_tags = {}
            if old_json and old_json ~= ngx.null then
                local old_sig = cjson.decode(old_json)
                old_tags = old_sig and old_sig.tags or {}
            end

            default_sig.builtin = true
            default_sig.updated_at = ngx.utctime()
            local signature_json = cjson.encode(default_sig)
            red:set(KEYS.config_prefix .. id, signature_json)
            red:zadd(KEYS.index, default_sig.priority or 100, id)

            -- Update indices
            update_active_set(red, id, default_sig.enabled ~= false)
            update_tag_index(red, id, old_tags, default_sig.tags)

            reset_count = reset_count + 1
        end
    end

    close_redis(red)
    invalidate_cache()

    return reset_count
end

-- Get enabled signatures
function _M.get_enabled()
    return _M.list({active_only = true, include_stats = false})
end

-- Get signatures by tag
function _M.get_by_tag(tag)
    return _M.list({tag = tag, include_stats = false})
end

-- Get signature stats
function _M.get_stats(id)
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local stats_data = red:hgetall(KEYS.stats_prefix .. id)
    close_redis(red)

    if not stats_data or type(stats_data) ~= "table" or #stats_data == 0 then
        return {
            signature_id = id,
            total_matches = 0,
            last_match_at = nil,
            matches_by_type = {}
        }
    end

    -- Convert array to hash
    local stats = {}
    for i = 1, #stats_data, 2 do
        stats[stats_data[i]] = stats_data[i + 1]
    end

    -- Build response
    local matches_by_type = {}
    for k, v in pairs(stats) do
        if k:match("^matches_") then
            local type_name = k:gsub("^matches_", "")
            matches_by_type[type_name] = tonumber(v) or 0
        end
    end

    return {
        signature_id = id,
        total_matches = tonumber(stats.total_matches) or 0,
        last_match_at = stats.last_match_at,
        matches_by_type = matches_by_type
    }
end

-- Get all tags
function _M.get_all_tags()
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    -- Scan for tag keys
    local cursor = "0"
    local tags = {}

    repeat
        local result = red:scan(cursor, "MATCH", KEYS.by_tag_prefix .. "*", "COUNT", 100)
        cursor = result[1]
        local keys = result[2]

        for _, key in ipairs(keys) do
            local tag = key:gsub(KEYS.by_tag_prefix, "")
            -- Check if tag has any members
            local count = red:scard(key)
            if count and count > 0 then
                table.insert(tags, {tag = tag, count = count})
            end
        end
    until cursor == "0"

    close_redis(red)

    -- Sort by count descending
    table.sort(tags, function(a, b) return a.count > b.count end)

    return tags
end

-- Export signatures to JSON
function _M.export(ids)
    local signatures, err = _M.list({include_stats = false})
    if not signatures then
        return nil, err
    end

    -- Filter by IDs if provided
    if ids and #ids > 0 then
        local id_set = {}
        for _, id in ipairs(ids) do
            id_set[id] = true
        end

        local filtered = {}
        for _, sig in ipairs(signatures) do
            if id_set[sig.id] then
                -- Remove internal fields for export
                sig.builtin = nil
                sig.stats = nil
                table.insert(filtered, sig)
            end
        end
        signatures = filtered
    else
        -- Remove internal fields for all
        for _, sig in ipairs(signatures) do
            sig.builtin = nil
            sig.stats = nil
        end
    end

    return signatures
end

-- Import signatures from JSON
function _M.import(signatures, opts)
    opts = opts or {}
    local imported = 0
    local errors = {}

    for _, signature in ipairs(signatures) do
        -- Check if exists
        local existing = _M.get(signature.id)

        if existing then
            if opts.overwrite then
                -- Update existing
                local _, err = _M.update(signature.id, signature)
                if err then
                    table.insert(errors, {id = signature.id, error = err})
                else
                    imported = imported + 1
                end
            elseif opts.skip_existing then
                -- Skip
            else
                table.insert(errors, {id = signature.id, error = "Already exists"})
            end
        else
            -- Create new
            local _, err = _M.create(signature)
            if err then
                table.insert(errors, {id = signature.id, error = err})
            else
                imported = imported + 1
            end
        end
    end

    return imported, errors
end

return _M
