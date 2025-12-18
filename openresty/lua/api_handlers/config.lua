-- api_handlers/config.lua
-- Configuration handlers for thresholds and routing

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"
local waf_config = require "waf_config"

-- Handlers table
_M.handlers = {}

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

-- ==================== Thresholds ====================

-- GET /config/thresholds - Get thresholds
_M.handlers["GET:/config/thresholds"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config = red:hgetall("waf:config:thresholds")
    utils.close_redis(red)

    local thresholds = {}
    if type(config) == "table" then
        for i = 1, #config, 2 do
            thresholds[config[i]] = parse_threshold_value(config[i + 1])
        end
    end

    return utils.json_response({
        thresholds = thresholds,
        defaults = waf_config.get_all().defaults
    })
end

-- POST /config/thresholds - Set threshold
_M.handlers["POST:/config/thresholds"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.name or data.value == nil then
        return utils.error_response("Missing 'name' or 'value' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local redis_value = serialize_threshold_value(data.value)
    red:hset("waf:config:thresholds", data.name, redis_value)
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({set = true, name = data.name, value = data.value})
end

-- ==================== Routing ====================

-- GET /config/routing - Get global routing config
_M.handlers["GET:/config/routing"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config = red:hgetall("waf:config:routing")
    utils.close_redis(red)

    local routing = {}
    if type(config) == "table" then
        for i = 1, #config, 2 do
            local key = config[i]
            local value = config[i + 1]
            -- Handle boolean for upstream_ssl
            if key == "upstream_ssl" then
                routing[key] = value == "true"
            else
                -- Try to convert to number if applicable
                local num_value = tonumber(value)
                routing[key] = num_value or value
            end
        end
    end

    return utils.json_response({
        routing = routing,
        defaults = waf_config.get_all().defaults.routing
    })
end

-- PUT /config/routing - Update global routing config
-- Fields:
--   haproxy_upstream: HTTP endpoint address (FQDN:port)
--   haproxy_upstream_ssl: HTTPS endpoint address (FQDN:port)
--   upstream_ssl: boolean toggle - when true, use haproxy_upstream_ssl
--   haproxy_timeout: connection timeout in seconds
_M.handlers["PUT:/config/routing"] = function()
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

    -- Update each provided field
    local updated = {}
    if data.haproxy_upstream then
        red:hset("waf:config:routing", "haproxy_upstream", data.haproxy_upstream)
        table.insert(updated, "haproxy_upstream")
    end
    if data.haproxy_upstream_ssl then
        red:hset("waf:config:routing", "haproxy_upstream_ssl", data.haproxy_upstream_ssl)
        table.insert(updated, "haproxy_upstream_ssl")
    end
    if data.upstream_ssl ~= nil then
        red:hset("waf:config:routing", "upstream_ssl", data.upstream_ssl and "true" or "false")
        table.insert(updated, "upstream_ssl")
    end
    if data.haproxy_timeout then
        red:hset("waf:config:routing", "haproxy_timeout", tonumber(data.haproxy_timeout))
        table.insert(updated, "haproxy_timeout")
    end

    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({updated = true, fields = updated})
end

return _M
