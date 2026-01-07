-- api_handlers/backup.lua
-- Backup and restore API handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local resty_sha256 = require "resty.sha256"
local resty_string = require "resty.string"

-- Handlers table
_M.handlers = {}

-- Redis key patterns for configuration entities
local ENTITY_KEYS = {
    -- Core configuration entities
    vhosts = {
        config_prefix = "waf:vhosts:config:",
        index = "waf:vhosts:index",
        name = "Virtual Hosts"
    },
    endpoints = {
        config_prefix = "waf:endpoints:config:",
        index = "waf:endpoints:index",
        name = "Endpoints"
    },
    defense_profiles = {
        config_prefix = "waf:defense_profiles:config:",
        index = "waf:defense_profiles:index",
        builtin = "waf:defense_profiles:builtin",
        name = "Defense Profiles"
    },
    attack_signatures = {
        config_prefix = "waf:attack_signatures:config:",
        index = "waf:attack_signatures:index",
        builtin = "waf:attack_signatures:builtin",
        name = "Attack Signatures"
    },
    fingerprint_profiles = {
        config_prefix = "waf:fingerprint:profiles:config:",
        index = "waf:fingerprint:profiles:index",
        builtin = "waf:fingerprint:profiles:builtin",
        name = "Fingerprint Profiles"
    },
    captcha_providers = {
        config_prefix = "waf:captcha:providers:config:",
        index = "waf:captcha:providers:index",
        name = "CAPTCHA Providers"
    },
    auth_providers = {
        config_prefix = "waf:auth:providers:config:",
        index = "waf:auth:providers:index",
        name = "Auth Providers"
    },
    -- Users (handled specially - exclude sensitive data)
    users = {
        config_prefix = "waf:admin:users:",
        index = "waf:admin:users:index",
        name = "Users",
        sensitive = true
    },
    -- Roles
    roles = {
        config_prefix = "waf:auth:roles:config:",
        index = "waf:auth:roles:index",
        name = "Roles"
    },
    -- Keywords and hashes
    keywords = {
        name = "Keywords",
        keys = {
            blocked = "waf:keywords:blocked",
            flagged = "waf:keywords:flagged"
        }
    },
    hashes = {
        name = "Hashes",
        keys = {
            blocked = "waf:hashes:blocked"
        }
    },
    whitelist = {
        name = "IP Whitelist",
        keys = {
            ips = "waf:whitelist:ips"
        }
    },
    -- Global config
    config = {
        name = "Global Config",
        keys = {
            geoip = "waf:config:geoip",
            timing_token = "waf:config:timing_token",
            routing = "waf:config:routing",
            thresholds = "waf:config:thresholds",
            webhooks = "waf:config:webhooks",
            captcha = "waf:captcha:config",
            reputation = "waf:config:reputation"
        }
    }
}

-- Backup format version
local BACKUP_VERSION = "1.0"

-- Calculate SHA256 checksum
local function calculate_checksum(data)
    local sha256 = resty_sha256:new()
    sha256:update(data)
    local digest = sha256:final()
    return resty_string.to_hex(digest)
end

-- Export entity with config prefix
local function export_entity_with_prefix(red, entity_key, builtin_ids, include_builtins)
    local entities = {}
    local pattern = entity_key.config_prefix .. "*"

    local cursor = "0"
    repeat
        local res, err = red:scan(cursor, "MATCH", pattern, "COUNT", 100)
        if not res then
            return nil, err
        end

        cursor = res[1]
        local keys = res[2]

        for _, key in ipairs(keys) do
            local entity_json = red:get(key)
            if entity_json and entity_json ~= ngx.null then
                local entity = cjson.decode(entity_json)
                if entity then
                    -- Check if it's a builtin
                    local is_builtin = false
                    if builtin_ids and entity.id then
                        is_builtin = builtin_ids[entity.id]
                    end

                    -- Include based on builtin filter
                    if include_builtins or not is_builtin then
                        table.insert(entities, entity)
                    end
                end
            end
        end
    until cursor == "0"

    return entities
end

-- Export set/list data
local function export_set_data(red, key)
    local data = red:smembers(key)
    if not data or data == ngx.null then
        return nil
    end
    return data
end

-- Export single key data
local function export_key_data(red, key)
    local data = red:get(key)
    if not data or data == ngx.null then
        return nil
    end
    local decoded = cjson.decode(data)
    return decoded
end

-- Get builtin IDs as a lookup table
local function get_builtin_ids(red, builtin_key)
    if not builtin_key then
        return {}
    end

    local ids = red:smembers(builtin_key)
    if not ids or ids == ngx.null then
        return {}
    end

    local lookup = {}
    for _, id in ipairs(ids) do
        lookup[id] = true
    end
    return lookup
end

-- GET /backup/export - Export all configuration
_M.handlers["GET:/backup/export"] = function()
    local args = ngx.req.get_uri_args()

    -- Parse options
    local include_users = args.include_users ~= "false"
    local include_builtins = args.include_builtins ~= "false"
    local entities_filter = args.entities  -- comma-separated list

    -- Parse entity filter
    local entity_filter = nil
    if entities_filter and entities_filter ~= "" then
        entity_filter = {}
        for entity in entities_filter:gmatch("[^,]+") do
            entity_filter[entity:match("^%s*(.-)%s*$")] = true  -- trim whitespace
        end
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"), 500)
    end

    local backup_data = {}
    local entity_counts = {}

    -- Export entities with config prefixes
    for entity_type, entity_key in pairs(ENTITY_KEYS) do
        -- Skip if filtered out
        if entity_filter and not entity_filter[entity_type] then
            goto continue
        end

        -- Skip users if not included
        if entity_type == "users" and not include_users then
            goto continue
        end

        if entity_key.config_prefix then
            -- Get builtin IDs
            local builtin_ids = get_builtin_ids(red, entity_key.builtin)

            -- Export entities
            local entities, err = export_entity_with_prefix(red, entity_key, builtin_ids, include_builtins)
            if entities then
                -- For users, strip sensitive data
                if entity_key.sensitive then
                    for _, entity in ipairs(entities) do
                        entity.password_hash = nil
                        entity.salt = nil
                    end
                end

                backup_data[entity_type] = entities
                entity_counts[entity_type] = #entities
            end
        elseif entity_key.keys then
            -- Export set/key data
            backup_data[entity_type] = {}
            for key_name, redis_key in pairs(entity_key.keys) do
                local key_type = red:type(redis_key)
                if key_type == "set" then
                    backup_data[entity_type][key_name] = export_set_data(red, redis_key)
                elseif key_type == "string" then
                    backup_data[entity_type][key_name] = export_key_data(red, redis_key)
                end
            end
            entity_counts[entity_type] = 1
        end

        ::continue::
    end

    utils.close_redis(red)

    -- Build final backup structure
    local backup = {
        metadata = {
            version = BACKUP_VERSION,
            created_at = ngx.utctime(),
            entity_counts = entity_counts,
            include_builtins = include_builtins,
            include_users = include_users
        },
        data = backup_data
    }

    -- Calculate checksum
    local backup_json = cjson.encode(backup)
    backup.checksum = "sha256:" .. calculate_checksum(backup_json)

    -- Set download headers
    ngx.header["Content-Disposition"] = string.format(
        'attachment; filename="waf-backup-%s.json"',
        os.date("!%Y%m%d-%H%M%S")
    )

    return utils.json_response(backup)
end

-- POST /backup/validate - Validate backup file without importing
_M.handlers["POST:/backup/validate"] = function()
    local data, err = utils.get_json_body()
    if not data then
        return utils.error_response(err or "Invalid JSON body")
    end

    local validation = {
        valid = true,
        errors = {},
        warnings = {},
        summary = {}
    }

    -- Check version
    if not data.metadata then
        table.insert(validation.errors, "Missing metadata section")
        validation.valid = false
    elseif not data.metadata.version then
        table.insert(validation.errors, "Missing version in metadata")
        validation.valid = false
    elseif data.metadata.version ~= BACKUP_VERSION then
        table.insert(validation.warnings, string.format(
            "Version mismatch: backup is v%s, current is v%s",
            data.metadata.version, BACKUP_VERSION
        ))
    end

    -- Check data section
    if not data.data then
        table.insert(validation.errors, "Missing data section")
        validation.valid = false
    end

    -- Verify checksum if present
    if data.checksum then
        local checksum_data = {
            metadata = data.metadata,
            data = data.data
        }
        local expected = calculate_checksum(cjson.encode(checksum_data))
        local provided = data.checksum:gsub("^sha256:", "")

        if expected ~= provided then
            table.insert(validation.warnings, "Checksum mismatch - backup may have been modified")
        end
    end

    -- Count entities
    if data.data then
        for entity_type, entities in pairs(data.data) do
            if type(entities) == "table" then
                if entities[1] then
                    -- Array of entities
                    validation.summary[entity_type] = #entities
                else
                    -- Object with subkeys
                    validation.summary[entity_type] = "config"
                end
            end
        end
    end

    -- Check for entity references
    local red, err = utils.get_redis()
    if red then
        -- Check for conflicts
        validation.conflicts = {}

        for entity_type, entities in pairs(data.data or {}) do
            local entity_key = ENTITY_KEYS[entity_type]
            if entity_key and entity_key.config_prefix and type(entities) == "table" and entities[1] then
                for _, entity in ipairs(entities) do
                    if entity.id then
                        local exists = red:exists(entity_key.config_prefix .. entity.id)
                        if exists == 1 then
                            validation.conflicts[entity_type] = validation.conflicts[entity_type] or {}
                            table.insert(validation.conflicts[entity_type], entity.id)
                        end
                    end
                end
            end
        end

        utils.close_redis(red)
    end

    return utils.json_response(validation)
end

-- POST /backup/import - Import configuration
_M.handlers["POST:/backup/import"] = function()
    local data, err = utils.get_json_body()
    if not data then
        return utils.error_response(err or "Invalid JSON body")
    end

    -- Parse options from request body
    local mode = data.mode or "merge"  -- merge, replace, update
    local include_users = data.include_users ~= false
    local backup = data.backup

    if not backup then
        return utils.error_response("Missing 'backup' field with backup data")
    end

    if not backup.data then
        return utils.error_response("Invalid backup: missing data section")
    end

    -- Validate mode
    if mode ~= "merge" and mode ~= "replace" and mode ~= "update" then
        return utils.error_response("Invalid mode: must be 'merge', 'replace', or 'update'")
    end

    local red, redis_err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (redis_err or "unknown"), 500)
    end

    local results = {
        imported = {},
        skipped = {},
        updated = {},
        errors = {}
    }

    -- Helper to import entities with config prefix
    local function import_entities(entity_type, entities, entity_key)
        if not entities or type(entities) ~= "table" or not entities[1] then
            return
        end

        results.imported[entity_type] = 0
        results.skipped[entity_type] = 0
        results.updated[entity_type] = 0
        results.errors[entity_type] = {}

        for i, entity in ipairs(entities) do
            if type(entity) ~= "table" then
                table.insert(results.errors[entity_type], string.format(
                    "Invalid entity at index %d: expected object, got %s",
                    i, type(entity)
                ))
                goto next_entity
            end

            if not entity.id then
                -- Try to provide context about which entity failed
                local name_hint = entity.name or entity.hostname or entity.pattern or "(unknown)"
                table.insert(results.errors[entity_type], string.format(
                    "Entity at index %d missing 'id' field (name hint: %s)",
                    i, name_hint
                ))
                goto next_entity
            end

            local key = entity_key.config_prefix .. entity.id
            local exists = red:exists(key)

            if mode == "merge" then
                -- Skip existing
                if exists == 1 then
                    results.skipped[entity_type] = results.skipped[entity_type] + 1
                    goto next_entity
                end
            elseif mode == "replace" then
                -- Always overwrite
            elseif mode == "update" then
                -- Only update if exists, create if not
            end

            -- Store entity
            local entity_json = cjson.encode(entity)
            if not entity_json then
                table.insert(results.errors[entity_type], "Failed to encode entity: " .. entity.id)
                goto next_entity
            end

            local ok, err = red:set(key, entity_json)
            if not ok then
                table.insert(results.errors[entity_type], string.format("Failed to save %s: %s", entity.id, err or "unknown"))
                goto next_entity
            end

            -- Add to index if exists
            if entity_key.index then
                local priority = entity.priority or 0
                red:zadd(entity_key.index, priority, entity.id)
            end

            if exists == 1 then
                results.updated[entity_type] = results.updated[entity_type] + 1
            else
                results.imported[entity_type] = results.imported[entity_type] + 1
            end

            ::next_entity::
        end
    end

    -- Helper to import set data
    local function import_set_data(entity_type, data_obj)
        if not data_obj or type(data_obj) ~= "table" then
            return
        end

        local entity_key = ENTITY_KEYS[entity_type]
        if not entity_key or not entity_key.keys then
            return
        end

        results.imported[entity_type] = 0

        for key_name, values in pairs(data_obj) do
            local redis_key = entity_key.keys[key_name]
            if redis_key and values then
                if type(values) == "table" and values[1] then
                    -- It's an array - use sadd for set
                    if mode == "replace" then
                        red:del(redis_key)
                    end
                    for _, value in ipairs(values) do
                        red:sadd(redis_key, value)
                    end
                    results.imported[entity_type] = results.imported[entity_type] + #values
                elseif type(values) == "table" then
                    -- It's an object - store as JSON string
                    local json = cjson.encode(values)
                    if json then
                        red:set(redis_key, json)
                        results.imported[entity_type] = results.imported[entity_type] + 1
                    end
                end
            end
        end
    end

    -- Import each entity type
    for entity_type, entity_key in pairs(ENTITY_KEYS) do
        local entities = backup.data[entity_type]

        if not entities then
            goto next_type
        end

        -- Skip users if not included
        if entity_type == "users" and not include_users then
            goto next_type
        end

        if entity_key.config_prefix then
            import_entities(entity_type, entities, entity_key)
        elseif entity_key.keys then
            import_set_data(entity_type, entities)
        end

        ::next_type::
    end

    utils.close_redis(red)

    -- Trigger sync
    local redis_sync = require "redis_sync"
    redis_sync.sync_now()

    return utils.json_response({
        success = true,
        mode = mode,
        results = results
    })
end

-- GET /backup/entities - List available entity types
_M.handlers["GET:/backup/entities"] = function()
    local entities = {}

    for entity_type, entity_key in pairs(ENTITY_KEYS) do
        table.insert(entities, {
            id = entity_type,
            name = entity_key.name,
            has_builtins = entity_key.builtin ~= nil,
            sensitive = entity_key.sensitive or false
        })
    end

    return utils.json_response({entities = entities})
end

return _M
