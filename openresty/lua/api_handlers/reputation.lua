-- api_handlers/reputation.lua
-- IP reputation management handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"

-- Handlers table
_M.handlers = {}

-- GET /reputation/status - Get IP reputation feature status
_M.handlers["GET:/reputation/status"] = function()
    local ip_reputation = require "ip_reputation"
    return utils.json_response(ip_reputation.get_status())
end

-- GET /reputation/config - Get IP reputation configuration
_M.handlers["GET:/reputation/config"] = function()
    local ip_reputation = require "ip_reputation"
    return utils.json_response(ip_reputation.get_config())
end

-- PUT /reputation/config - Update IP reputation configuration
_M.handlers["PUT:/reputation/config"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    -- Get existing config and merge
    local existing_json = red:get("waf:config:ip_reputation")
    local existing = {}
    if existing_json and existing_json ~= ngx.null then
        existing = cjson.decode(existing_json) or {}
    end

    -- Merge new config into existing
    for k, v in pairs(data) do
        existing[k] = v
    end

    -- Save updated config
    red:set("waf:config:ip_reputation", cjson.encode(existing))
    utils.close_redis(red)

    return utils.json_response({
        success = true,
        config = existing
    })
end

-- GET /reputation/check - Check IP reputation
_M.handlers["GET:/reputation/check"] = function()
    local args = ngx.req.get_uri_args()
    local ip = args.ip

    if not ip or ip == "" then
        return utils.error_response("Missing 'ip' parameter")
    end

    local ip_reputation = require "ip_reputation"
    if not ip_reputation.is_available() then
        return utils.json_response({
            available = false,
            message = "IP reputation feature not available (disabled or no providers configured)"
        })
    end

    local result = ip_reputation.check_ip(ip)
    return utils.json_response({
        ip = ip,
        result = result
    })
end

-- GET /reputation/blocklist - Get IP blocklist
_M.handlers["GET:/reputation/blocklist"] = function()
    local ip_reputation = require "ip_reputation"
    local blocklist = ip_reputation.get_blocklist()
    return utils.json_response({
        blocked_ips = blocklist or {}
    })
end

-- POST /reputation/blocklist - Add IP to blocklist
_M.handlers["POST:/reputation/blocklist"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.ip then
        return utils.error_response("Missing 'ip' field")
    end

    local ip_reputation = require "ip_reputation"
    local success, err = ip_reputation.add_to_blocklist(data.ip, data.reason)

    if not success then
        return utils.error_response(err or "Failed to add IP to blocklist", 500)
    end

    return utils.json_response({
        success = true,
        ip = data.ip,
        reason = data.reason
    })
end

-- DELETE /reputation/blocklist - Remove IP from blocklist
_M.handlers["DELETE:/reputation/blocklist"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.ip then
        return utils.error_response("Missing 'ip' field")
    end

    local ip_reputation = require "ip_reputation"
    local success, err = ip_reputation.remove_from_blocklist(data.ip)

    if not success then
        return utils.error_response(err or "Failed to remove IP from blocklist", 500)
    end

    return utils.json_response({
        success = true,
        ip = data.ip
    })
end

-- DELETE /reputation/cache - Clear reputation cache for an IP
_M.handlers["DELETE:/reputation/cache"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.ip then
        return utils.error_response("Missing 'ip' field")
    end

    local ip_reputation = require "ip_reputation"
    ip_reputation.clear_cache(data.ip)

    return utils.json_response({
        success = true,
        ip = data.ip,
        message = "Cache cleared"
    })
end

return _M
