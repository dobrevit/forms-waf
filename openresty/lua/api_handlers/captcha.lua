-- api_handlers/captcha.lua
-- CAPTCHA provider management handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"
local captcha_providers = require "captcha_providers"

-- Redis keys
local CAPTCHA_KEYS = {
    providers_index = "waf:captcha:providers:index",
    providers_config_prefix = "waf:captcha:providers:config:",
    config = "waf:captcha:config",
}

-- Helper: Generate unique provider ID
local function generate_provider_id()
    local id = ngx.now() * 1000 + math.random(1000)
    return string.format("cp_%x", id)
end

-- Helper: Validate provider type
local function validate_provider_type(provider_type)
    local valid_types = {
        turnstile = true,
        recaptcha_v2 = true,
        recaptcha_v3 = true,
        hcaptcha = true,
    }
    return valid_types[provider_type] == true
end

-- Helper function for merging options
local function merge_tables(base, override)
    local result = {}
    for k, v in pairs(base or {}) do
        result[k] = v
    end
    for k, v in pairs(override or {}) do
        result[k] = v
    end
    return result
end

-- Handlers table (simple routes)
_M.handlers = {}

-- Resource handlers table (parameterized routes: /captcha/providers/{id})
_M.resource_handlers = {}

-- ==================== Simple Handlers ====================

-- GET /captcha/providers - List all CAPTCHA providers
_M.handlers["GET:/captcha/providers"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get all provider IDs sorted by priority
    local provider_ids = red:zrange(CAPTCHA_KEYS.providers_index, 0, -1)

    local providers = {}
    if provider_ids and type(provider_ids) == "table" then
        for _, provider_id in ipairs(provider_ids) do
            local config_json = red:get(CAPTCHA_KEYS.providers_config_prefix .. provider_id)
            if config_json and config_json ~= ngx.null then
                local config = cjson.decode(config_json)
                if config then
                    -- Don't expose secret_key in list view
                    config.secret_key = config.secret_key and "***" or nil
                    table.insert(providers, config)
                end
            end
        end
    end

    utils.close_redis(red)

    -- Ensure empty array encodes as [] not {}
    if #providers == 0 then
        providers = cjson.empty_array
    end

    return utils.json_response({providers = providers})
end

-- POST /captcha/providers - Create new CAPTCHA provider
_M.handlers["POST:/captcha/providers"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate required fields
    if not data.name or data.name == "" then
        return utils.error_response("Missing 'name' field")
    end
    if not data.type or not validate_provider_type(data.type) then
        return utils.error_response("Invalid or missing 'type' field. Must be one of: turnstile, recaptcha_v2, recaptcha_v3, hcaptcha")
    end
    if not data.site_key or data.site_key == "" then
        return utils.error_response("Missing 'site_key' field")
    end
    if not data.secret_key or data.secret_key == "" then
        return utils.error_response("Missing 'secret_key' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Generate ID
    local provider_id = data.id or generate_provider_id()

    -- Check if ID already exists
    local existing = red:get(CAPTCHA_KEYS.providers_config_prefix .. provider_id)
    if existing and existing ~= ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider ID already exists: " .. provider_id, 409)
    end

    -- Build configuration
    local config = {
        id = provider_id,
        name = data.name,
        type = data.type,
        enabled = data.enabled ~= false,  -- Default true
        priority = data.priority or 100,
        site_key = data.site_key,
        secret_key = data.secret_key,
        options = data.options or {
            theme = "auto",
            size = "normal",
        },
        metadata = {
            created_at = ngx.utctime(),
            updated_at = ngx.utctime(),
        }
    }

    -- For reCAPTCHA v3, set default min_score
    if data.type == "recaptcha_v3" then
        config.options.min_score = config.options.min_score or 0.5
        config.options.action = config.options.action or "submit"
    end

    -- Store configuration
    red:set(CAPTCHA_KEYS.providers_config_prefix .. provider_id, cjson.encode(config))

    -- Add to index with priority
    red:zadd(CAPTCHA_KEYS.providers_index, config.priority, provider_id)

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    -- Return config without exposing full secret
    local response_config = cjson.decode(cjson.encode(config))
    response_config.secret_key = "***"

    return utils.json_response({
        created = true,
        provider = response_config
    })
end

-- GET /captcha/config - Get global CAPTCHA configuration
_M.handlers["GET:/captcha/config"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config = red:hgetall(CAPTCHA_KEYS.config)
    utils.close_redis(red)

    local captcha_config = {}
    if type(config) == "table" then
        for i = 1, #config, 2 do
            local key = config[i]
            local value = config[i + 1]
            -- Parse JSON values
            if value and value:match("^[%[{]") then
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

    -- Apply defaults
    local defaults = {
        enabled = false,
        default_provider = nil,
        trust_duration = 86400,  -- 24 hours
        challenge_ttl = 600,     -- 10 minutes
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

    return utils.json_response({config = captcha_config, defaults = defaults})
end

-- PUT /captcha/config - Update global CAPTCHA configuration
_M.handlers["PUT:/captcha/config"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Validate fallback_action if provided
    if data.fallback_action then
        local valid_actions = {block = true, allow = true, monitor = true}
        if not valid_actions[data.fallback_action] then
            utils.close_redis(red)
            return utils.error_response("Invalid 'fallback_action'. Must be one of: block, allow, monitor")
        end
    end

    -- Validate cookie_samesite if provided
    if data.cookie_samesite then
        local valid_samesite = {Strict = true, Lax = true, None = true}
        if not valid_samesite[data.cookie_samesite] then
            utils.close_redis(red)
            return utils.error_response("Invalid 'cookie_samesite'. Must be one of: Strict, Lax, None")
        end
    end

    -- Update each provided field
    local updated = {}
    local fields = {
        "enabled", "default_provider", "trust_duration", "challenge_ttl",
        "fallback_action", "cookie_name", "cookie_secure", "cookie_httponly", "cookie_samesite"
    }

    for _, field in ipairs(fields) do
        if data[field] ~= nil then
            local value = data[field]
            if type(value) == "boolean" then
                value = value and "true" or "false"
            elseif type(value) == "table" then
                value = cjson.encode(value)
            else
                value = tostring(value)
            end
            red:hset(CAPTCHA_KEYS.config, field, value)
            table.insert(updated, field)
        end
    end

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({updated = true, fields = updated})
end

-- ==================== Resource Handlers (parameterized) ====================

-- GET /captcha/providers/{id} - Get specific provider
_M.resource_handlers["GET"] = function(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(CAPTCHA_KEYS.providers_config_prefix .. provider_id)
    utils.close_redis(red)

    if not config_json or config_json == ngx.null then
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local config = cjson.decode(config_json)
    -- Don't expose secret_key in response
    config.secret_key = "***"

    return utils.json_response({provider = config})
end

-- PUT /captcha/providers/{id} - Update provider
_M.resource_handlers["PUT"] = function(provider_id)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get existing configuration
    local existing_json = red:get(CAPTCHA_KEYS.providers_config_prefix .. provider_id)
    if not existing_json or existing_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local existing_config = cjson.decode(existing_json)

    -- Validate provider type if being changed
    if data.type and not validate_provider_type(data.type) then
        utils.close_redis(red)
        return utils.error_response("Invalid 'type' field. Must be one of: turnstile, recaptcha_v2, recaptcha_v3, hcaptcha")
    end

    -- Build updated configuration
    local new_config = {
        id = provider_id,  -- ID cannot be changed
        name = data.name or existing_config.name,
        type = data.type or existing_config.type,
        enabled = data.enabled ~= nil and data.enabled or existing_config.enabled,
        priority = data.priority or existing_config.priority,
        site_key = data.site_key or existing_config.site_key,
        -- Only update secret if new one provided and not "***"
        secret_key = (data.secret_key and data.secret_key ~= "***") and data.secret_key or existing_config.secret_key,
        options = data.options and merge_tables(existing_config.options or {}, data.options) or existing_config.options,
        metadata = existing_config.metadata or {}
    }
    new_config.metadata.updated_at = ngx.utctime()

    -- Update priority in index if changed
    if new_config.priority ~= existing_config.priority then
        red:zadd(CAPTCHA_KEYS.providers_index, new_config.priority, provider_id)
    end

    -- Store updated configuration
    red:set(CAPTCHA_KEYS.providers_config_prefix .. provider_id, cjson.encode(new_config))

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    -- Return config without exposing full secret
    local response_config = cjson.decode(cjson.encode(new_config))
    response_config.secret_key = "***"

    return utils.json_response({
        updated = true,
        provider = response_config
    })
end

-- DELETE /captcha/providers/{id} - Delete provider
_M.resource_handlers["DELETE"] = function(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if provider exists
    local existing_json = red:get(CAPTCHA_KEYS.providers_config_prefix .. provider_id)
    if not existing_json or existing_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    -- Remove from index
    red:zrem(CAPTCHA_KEYS.providers_index, provider_id)

    -- Delete configuration
    red:del(CAPTCHA_KEYS.providers_config_prefix .. provider_id)

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        deleted = true,
        provider_id = provider_id
    })
end

-- POST /captcha/providers/{id}/test - Test provider connectivity
_M.resource_handlers["POST:test"] = function(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(CAPTCHA_KEYS.providers_config_prefix .. provider_id)
    utils.close_redis(red)

    if not config_json or config_json == ngx.null then
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local config = cjson.decode(config_json)

    -- Test provider connectivity
    local success, message = captcha_providers.test_provider(config)

    return utils.json_response({
        provider_id = provider_id,
        success = success,
        message = message
    })
end

-- POST /captcha/providers/{id}/enable - Enable provider
_M.resource_handlers["POST:enable"] = function(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(CAPTCHA_KEYS.providers_config_prefix .. provider_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = true
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(CAPTCHA_KEYS.providers_config_prefix .. provider_id, cjson.encode(config))
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({
        enabled = true,
        provider_id = provider_id
    })
end

-- POST /captcha/providers/{id}/disable - Disable provider
_M.resource_handlers["POST:disable"] = function(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config_json = red:get(CAPTCHA_KEYS.providers_config_prefix .. provider_id)
    if not config_json or config_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local config = cjson.decode(config_json)
    config.enabled = false
    config.metadata = config.metadata or {}
    config.metadata.updated_at = ngx.utctime()

    red:set(CAPTCHA_KEYS.providers_config_prefix .. provider_id, cjson.encode(config))
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({
        disabled = true,
        provider_id = provider_id
    })
end

return _M
