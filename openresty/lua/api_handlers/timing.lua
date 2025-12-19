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

-- GET /timing/vhosts - List all vhosts with timing enabled
_M.handlers["GET:/timing/vhosts"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    -- Get global timing config to read the cookie_name setting
    local global_config_json = red:get("waf:config:timing_token")
    local global_cookie_name = "_waf_timing"  -- Default
    if global_config_json and global_config_json ~= ngx.null then
        local global_config = cjson.decode(global_config_json)
        if global_config and global_config.cookie_name then
            global_cookie_name = global_config.cookie_name
        end
    end

    -- Get all vhost IDs from index
    local vhost_ids = red:zrange("waf:vhosts:index", 0, -1)
    local timing_vhosts = {}

    if type(vhost_ids) == "table" then
        for _, vhost_id in ipairs(vhost_ids) do
            local config_json = red:get("waf:vhosts:config:" .. vhost_id)
            if config_json and config_json ~= ngx.null then
                local config = cjson.decode(config_json)
                if config and config.timing and config.timing.enabled then
                    -- Determine cookie name for this vhost using global cookie_name as base
                    local cookie_name = global_cookie_name
                    if vhost_id and vhost_id ~= "_default" then
                        local safe_id = vhost_id:gsub("[^%w_-]", "")
                        cookie_name = global_cookie_name .. "_" .. safe_id
                    end

                    table.insert(timing_vhosts, {
                        vhost_id = vhost_id,
                        name = config.name,
                        hostnames = config.hostnames,
                        timing = config.timing,
                        cookie_name = cookie_name
                    })
                end
            end
        end
    end

    utils.close_redis(red)

    return utils.json_response({
        vhosts = timing_vhosts,
        total = #timing_vhosts
    })
end

return _M
