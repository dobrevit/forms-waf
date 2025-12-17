-- api_handlers/whitelist.lua
-- IP allowlist handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"

-- Handlers table
_M.handlers = {}

-- GET /whitelist/ips - List allowlisted IPs
_M.handlers["GET:/whitelist/ips"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local ips = red:smembers("waf:whitelist:ips")
    utils.close_redis(red)

    return utils.json_response({ips = ips or {}})
end

-- POST /whitelist/ips - Add IP to allowlist
_M.handlers["POST:/whitelist/ips"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.ip then
        return utils.error_response("Missing 'ip' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:whitelist:ips", data.ip)
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({added = added == 1, ip = data.ip})
end

-- DELETE /whitelist/ips - Remove IP from allowlist
_M.handlers["DELETE:/whitelist/ips"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.ip then
        return utils.error_response("Missing 'ip' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local removed = red:srem("waf:whitelist:ips", data.ip)
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({removed = removed == 1, ip = data.ip})
end

return _M
