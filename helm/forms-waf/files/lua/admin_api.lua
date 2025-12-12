-- admin_api.lua
-- Admin API for WAF management

local _M = {}

local cjson = require "cjson.safe"
local redis = require "resty.redis"
local redis_sync = require "redis_sync"
local waf_config = require "waf_config"
local keyword_filter = require "keyword_filter"

-- Redis configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil

-- Get Redis connection
local function get_redis()
    local red = redis:new()
    red:set_timeout(2000)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        return nil, err
    end

    if REDIS_PASSWORD and REDIS_PASSWORD ~= "" then
        local res, err = red:auth(REDIS_PASSWORD)
        if not res then
            red:close()
            return nil, err
        end
    end

    return red
end

local function close_redis(red)
    if red then
        red:set_keepalive(10000, 100)
    end
end

-- Response helpers
local function json_response(data, status)
    ngx.status = status or 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode(data))
    return ngx.exit(ngx.status)
end

local function error_response(message, status)
    return json_response({error = message}, status or 400)
end

-- Route handlers
local handlers = {}

-- GET /waf-admin/status - Get WAF status
handlers["GET:/status"] = function()
    local status = redis_sync.get_status()
    status.config = waf_config.get_all()
    return json_response(status)
end

-- GET /waf-admin/keywords/blocked - List blocked keywords
handlers["GET:/keywords/blocked"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local keywords = red:smembers("waf:keywords:blocked")
    close_redis(red)

    return json_response({keywords = keywords or {}})
end

-- POST /waf-admin/keywords/blocked - Add blocked keyword
handlers["POST:/keywords/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return error_response("Missing 'keyword' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:keywords:blocked", data.keyword:lower())
    close_redis(red)

    -- Trigger immediate sync
    redis_sync.sync_now()

    return json_response({added = added == 1, keyword = data.keyword:lower()})
end

-- DELETE /waf-admin/keywords/blocked - Remove blocked keyword
handlers["DELETE:/keywords/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return error_response("Missing 'keyword' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local removed = red:srem("waf:keywords:blocked", data.keyword:lower())
    close_redis(red)

    redis_sync.sync_now()

    return json_response({removed = removed == 1, keyword = data.keyword:lower()})
end

-- GET /waf-admin/keywords/flagged - List flagged keywords
handlers["GET:/keywords/flagged"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local keywords = red:smembers("waf:keywords:flagged")
    close_redis(red)

    return json_response({keywords = keywords or {}})
end

-- POST /waf-admin/keywords/flagged - Add flagged keyword
handlers["POST:/keywords/flagged"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return error_response("Missing 'keyword' field")
    end

    local keyword_entry = data.keyword:lower()
    if data.score then
        keyword_entry = keyword_entry .. ":" .. tostring(data.score)
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:keywords:flagged", keyword_entry)
    close_redis(red)

    redis_sync.sync_now()

    return json_response({added = added == 1, keyword = keyword_entry})
end

-- GET /waf-admin/hashes/blocked - List blocked hashes
handlers["GET:/hashes/blocked"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local hashes = red:smembers("waf:hashes:blocked")
    close_redis(red)

    return json_response({hashes = hashes or {}})
end

-- POST /waf-admin/hashes/blocked - Add blocked hash
handlers["POST:/hashes/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.hash then
        return error_response("Missing 'hash' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:hashes:blocked", data.hash:lower())
    close_redis(red)

    redis_sync.sync_now()

    return json_response({added = added == 1, hash = data.hash:lower()})
end

-- GET /waf-admin/whitelist/ips - List whitelisted IPs
handlers["GET:/whitelist/ips"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local ips = red:smembers("waf:whitelist:ips")
    close_redis(red)

    return json_response({ips = ips or {}})
end

-- POST /waf-admin/whitelist/ips - Add whitelisted IP
handlers["POST:/whitelist/ips"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.ip then
        return error_response("Missing 'ip' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:whitelist:ips", data.ip)
    close_redis(red)

    redis_sync.sync_now()

    return json_response({added = added == 1, ip = data.ip})
end

-- POST /waf-admin/sync - Force sync from Redis
handlers["POST:/sync"] = function()
    redis_sync.sync_now()
    return json_response({synced = true})
end

-- GET /waf-admin/config/thresholds - Get thresholds
handlers["GET:/config/thresholds"] = function()
    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local config = red:hgetall("waf:config:thresholds")
    close_redis(red)

    local thresholds = {}
    if type(config) == "table" then
        for i = 1, #config, 2 do
            thresholds[config[i]] = tonumber(config[i + 1])
        end
    end

    return json_response({
        thresholds = thresholds,
        defaults = waf_config.get_all().defaults
    })
end

-- POST /waf-admin/config/thresholds - Set threshold
handlers["POST:/config/thresholds"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.name or not data.value then
        return error_response("Missing 'name' or 'value' field")
    end

    local red, err = get_redis()
    if not red then
        return error_response("Redis error: " .. (err or "unknown"), 500)
    end

    red:hset("waf:config:thresholds", data.name, tonumber(data.value))
    close_redis(red)

    redis_sync.sync_now()

    return json_response({set = true, name = data.name, value = data.value})
end

-- Main request handler
function _M.handle_request()
    local method = ngx.req.get_method()
    local uri = ngx.var.uri

    -- Extract path after /waf-admin
    local path = uri:match("/waf%-admin(/.*)")
    if not path then
        path = "/"
    end

    -- Find handler
    local handler_key = method .. ":" .. path
    local handler = handlers[handler_key]

    if not handler then
        return error_response("Not found", 404)
    end

    return handler()
end

return _M
