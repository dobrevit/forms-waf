-- api_handlers/timing.lua
-- Timing token configuration handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"

-- Handlers table
_M.handlers = {}

-- GET /timing/status - Get timing token feature status
_M.handlers["GET:/timing/status"] = function()
    local timing_token = require "timing_token"
    return utils.json_response({
        enabled = timing_token.is_enabled(),
        config = timing_token.get_config()
    })
end

-- GET /timing/config - Get timing token configuration
_M.handlers["GET:/timing/config"] = function()
    local timing_token = require "timing_token"
    return utils.json_response(timing_token.get_config())
end

-- PUT /timing/config - Update timing token configuration
_M.handlers["PUT:/timing/config"] = function()
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
    local existing_json = red:get("waf:config:timing_token")
    local existing = {}
    if existing_json and existing_json ~= ngx.null then
        existing = cjson.decode(existing_json) or {}
    end

    -- Merge new config into existing
    for k, v in pairs(data) do
        existing[k] = v
    end

    -- Save updated config
    red:set("waf:config:timing_token", cjson.encode(existing))
    utils.close_redis(red)

    return utils.json_response({
        success = true,
        config = existing
    })
end

return _M
