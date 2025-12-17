-- api_handlers/hashes.lua
-- Blocked content hashes handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"

-- Handlers table
_M.handlers = {}

-- GET /hashes/blocked - List blocked hashes
_M.handlers["GET:/hashes/blocked"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local hashes = red:smembers("waf:hashes:blocked")
    utils.close_redis(red)

    return utils.json_response({hashes = hashes or {}})
end

-- POST /hashes/blocked - Add blocked hash
_M.handlers["POST:/hashes/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.hash then
        return utils.error_response("Missing 'hash' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:hashes:blocked", data.hash:lower())
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({added = added == 1, hash = data.hash:lower()})
end

return _M
