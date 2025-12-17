-- api_handlers/utils.lua
-- Shared utilities for API handlers

local _M = {}

local cjson = require "cjson.safe"
local redis = require "resty.redis"

-- Redis configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil

-- Get Redis connection
function _M.get_redis()
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

function _M.close_redis(red)
    if red then
        red:set_keepalive(10000, 100)
    end
end

-- Response helpers
function _M.json_response(data, status)
    ngx.status = status or 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode(data))
    return ngx.exit(ngx.status)
end

function _M.error_response(message, status)
    return _M.json_response({error = message}, status or 400)
end

-- Get request body as JSON
function _M.get_json_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        return nil, "No request body"
    end
    local data, err = cjson.decode(body)
    if not data then
        return nil, "Invalid JSON: " .. (err or "unknown error")
    end
    return data
end

-- Validate required fields
function _M.validate_required(data, fields)
    for _, field in ipairs(fields) do
        if data[field] == nil or data[field] == "" then
            return false, "Missing required field: " .. field
        end
    end
    return true
end

return _M
