-- api_handlers/webhooks.lua
-- Webhook configuration handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"

-- Redis keys
local WEBHOOK_KEYS = {
    config = "waf:webhooks:config",
}

-- Handlers table
_M.handlers = {}

-- GET /webhooks/config - Get webhook configuration
_M.handlers["GET:/webhooks/config"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local config_str = red:get(WEBHOOK_KEYS.config)
    utils.close_redis(red)

    local config = {}
    if config_str and config_str ~= ngx.null then
        config = cjson.decode(config_str) or {}
    end

    -- Set defaults
    config.enabled = config.enabled or false
    config.url = config.url or ""
    config.urls = config.urls or {}
    config.events = config.events or {}
    config.batch_size = config.batch_size or 10
    config.batch_interval = config.batch_interval or 60
    config.headers = config.headers or {}
    config.ssl_verify = config.ssl_verify ~= false

    return utils.json_response(config)
end

-- PUT /webhooks/config - Update webhook configuration
_M.handlers["PUT:/webhooks/config"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data, decode_err = cjson.decode(body)

    if not data then
        return utils.error_response("Invalid JSON: " .. (decode_err or "unknown error"))
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    -- Validate URL if provided
    if data.url and data.url ~= "" then
        if not data.url:match("^https?://") then
            utils.close_redis(red)
            return utils.error_response("Invalid URL format - must start with http:// or https://")
        end
    end

    -- Validate URLs array if provided
    if data.urls and type(data.urls) == "table" then
        for i, url in ipairs(data.urls) do
            if not url:match("^https?://") then
                utils.close_redis(red)
                return utils.error_response("Invalid URL at index " .. i .. " - must start with http:// or https://")
            end
        end
    end

    -- Validate events if provided
    local valid_events = {
        request_blocked = true,
        rate_limit_triggered = true,
        high_spam_score = true,
        captcha_triggered = true,
        honeypot_triggered = true,
        disposable_email = true,
        fingerprint_flood = true,
    }

    if data.events and type(data.events) == "table" then
        for _, event in ipairs(data.events) do
            if not valid_events[event] then
                utils.close_redis(red)
                return utils.error_response("Invalid event type: " .. event)
            end
        end
    end

    -- Build config object
    local config = {
        enabled = data.enabled == true,
        url = data.url or "",
        urls = data.urls or {},
        events = data.events or {},
        batch_size = tonumber(data.batch_size) or 10,
        batch_interval = tonumber(data.batch_interval) or 60,
        headers = data.headers or {},
        ssl_verify = data.ssl_verify ~= false,
    }

    -- Save to Redis
    local ok, save_err = red:set(WEBHOOK_KEYS.config, cjson.encode(config))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to save config: " .. (save_err or "unknown"))
    end

    -- Update local webhook module cache
    local webhooks = require "webhooks"
    webhooks.update_config(config)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({updated = true, config = config})
end

-- POST /webhooks/test - Test webhook endpoint
_M.handlers["POST:/webhooks/test"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data, decode_err = cjson.decode(body)

    if not data then
        return utils.error_response("Invalid JSON: " .. (decode_err or "unknown error"))
    end

    local url = data.url
    if not url or url == "" then
        return utils.error_response("URL is required")
    end

    if not url:match("^https?://") then
        return utils.error_response("Invalid URL format - must start with http:// or https://")
    end

    -- Send test webhook
    local httpc = require("resty.http").new()
    httpc:set_timeout(5000)

    local test_payload = {
        source = "forms-waf",
        type = "test",
        timestamp = ngx.time(),
        message = "This is a test webhook from Forms WAF",
    }

    local headers = {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "FormsWAF-Webhook/1.0",
    }

    -- Add custom headers from request
    if data.headers and type(data.headers) == "table" then
        for k, v in pairs(data.headers) do
            headers[k] = v
        end
    end

    local res, req_err = httpc:request_uri(url, {
        method = "POST",
        body = cjson.encode(test_payload),
        headers = headers,
        ssl_verify = data.ssl_verify ~= false,
    })

    if not res then
        return utils.json_response({
            success = false,
            error = "Request failed: " .. (req_err or "unknown"),
        })
    end

    return utils.json_response({
        success = res.status >= 200 and res.status < 300,
        status = res.status,
        status_text = res.reason,
        response_body = res.body and res.body:sub(1, 500) or nil,
    })
end

-- GET /webhooks/stats - Get webhook queue statistics
_M.handlers["GET:/webhooks/stats"] = function()
    local webhooks = require "webhooks"
    return utils.json_response(webhooks.get_stats())
end

return _M
