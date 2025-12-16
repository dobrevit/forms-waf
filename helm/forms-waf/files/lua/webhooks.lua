--[[
    Webhooks Module
    Sends notifications to external systems for security events
    Uses async processing via ngx.timer.at to avoid blocking requests
]]

local _M = {}

local http = require "resty.http"
local cjson = require "cjson.safe"

-- Shared dictionary for webhook queue and config
local webhook_cache = ngx.shared.keyword_cache  -- Reuse existing cache

-- Configuration defaults
local DEFAULT_BATCH_SIZE = 10
local DEFAULT_BATCH_INTERVAL = 60  -- seconds
local MAX_QUEUE_SIZE = 1000

-- Redis key patterns
local KEYS = {
    config = "waf:webhooks:config",
    queue = "waf:webhooks:queue",
    stats = "waf:webhooks:stats",
}

-- Event types
_M.EVENT_TYPES = {
    REQUEST_BLOCKED = "request_blocked",
    RATE_LIMIT_TRIGGERED = "rate_limit_triggered",
    HIGH_SPAM_SCORE = "high_spam_score",
    CAPTCHA_TRIGGERED = "captcha_triggered",
    HONEYPOT_TRIGGERED = "honeypot_triggered",
    DISPOSABLE_EMAIL = "disposable_email",
    FINGERPRINT_FLOOD = "fingerprint_flood",
}

-- Local event queue (batched before sending)
local event_queue = {}
local last_flush_time = ngx.now()

-- Get webhook configuration from cache
local function get_webhook_config()
    local cached = webhook_cache:get("webhooks:config")
    if cached then
        return cjson.decode(cached)
    end
    return nil
end

-- Queue an event for webhook notification
-- Events are batched and sent periodically to reduce overhead
function _M.queue_event(event_type, event_data)
    local config = get_webhook_config()
    if not config or not config.enabled then
        return false, "Webhooks not enabled"
    end

    -- Check if this event type is enabled
    local type_enabled = false
    if config.events then
        for _, evt in ipairs(config.events) do
            if evt == event_type or evt == "*" then
                type_enabled = true
                break
            end
        end
    end

    if not type_enabled then
        return false, "Event type not enabled"
    end

    -- Build event payload
    local event = {
        event = event_type,
        timestamp = ngx.time(),
        timestamp_ms = ngx.now() * 1000,
        data = event_data or {},
    }

    -- Add to local queue
    if #event_queue < MAX_QUEUE_SIZE then
        table.insert(event_queue, event)
    else
        ngx.log(ngx.WARN, "Webhook queue full, dropping event: ", event_type)
        return false, "Queue full"
    end

    -- Check if we should flush immediately (batch size reached)
    local batch_size = config.batch_size or DEFAULT_BATCH_SIZE
    if #event_queue >= batch_size then
        -- Schedule async flush
        local ok, err = ngx.timer.at(0, _M.flush_queue)
        if not ok then
            ngx.log(ngx.ERR, "Failed to schedule webhook flush: ", err)
        end
    end

    return true
end

-- Send events to webhook endpoint
local function send_webhook(config, events)
    if not config.url or config.url == "" then
        return false, "No webhook URL configured"
    end

    local httpc = http.new()
    httpc:set_timeout(5000)  -- 5 second timeout

    -- Build payload
    local payload = {
        source = "forms-waf",
        batch_id = ngx.now() .. "-" .. math.random(1000, 9999),
        event_count = #events,
        events = events,
    }

    -- Build headers
    local headers = {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "FormsWAF-Webhook/1.0",
    }

    -- Add custom headers from config
    if config.headers then
        for k, v in pairs(config.headers) do
            headers[k] = v
        end
    end

    -- Send request
    local body = cjson.encode(payload)
    local res, err = httpc:request_uri(config.url, {
        method = "POST",
        body = body,
        headers = headers,
        ssl_verify = config.ssl_verify ~= false,
    })

    if not res then
        ngx.log(ngx.ERR, "Webhook request failed: ", err)
        return false, err
    end

    if res.status >= 200 and res.status < 300 then
        ngx.log(ngx.DEBUG, "Webhook sent successfully: ", #events, " events, status: ", res.status)
        return true
    else
        ngx.log(ngx.WARN, "Webhook returned non-2xx status: ", res.status, " body: ", res.body)
        return false, "HTTP " .. res.status
    end
end

-- Flush event queue (called by timer or manually)
function _M.flush_queue(premature)
    if premature then
        return
    end

    local config = get_webhook_config()
    if not config or not config.enabled then
        return
    end

    -- Take all events from queue
    local events_to_send = {}
    while #event_queue > 0 do
        table.insert(events_to_send, table.remove(event_queue, 1))
    end

    if #events_to_send == 0 then
        return
    end

    last_flush_time = ngx.now()

    -- Send to all configured webhooks
    local sent = 0
    local failed = 0

    -- Support single webhook or multiple
    local urls = config.urls or { config.url }
    for _, url in ipairs(urls) do
        local webhook_config = {
            url = url,
            headers = config.headers,
            ssl_verify = config.ssl_verify,
        }
        local ok, err = send_webhook(webhook_config, events_to_send)
        if ok then
            sent = sent + 1
        else
            failed = failed + 1
            ngx.log(ngx.ERR, "Failed to send webhook to ", url, ": ", err)
        end
    end

    ngx.log(ngx.INFO, "Webhook flush: ", #events_to_send, " events, ", sent, " sent, ", failed, " failed")
end

-- Start periodic flush timer
function _M.start_flush_timer()
    local config = get_webhook_config()
    local interval = (config and config.batch_interval) or DEFAULT_BATCH_INTERVAL

    local handler
    handler = function(premature)
        if premature then
            return
        end

        -- Flush if we have events and enough time has passed
        if #event_queue > 0 then
            local time_since_flush = ngx.now() - last_flush_time
            if time_since_flush >= interval then
                _M.flush_queue()
            end
        end

        -- Reschedule
        local ok, err = ngx.timer.at(interval, handler)
        if not ok then
            ngx.log(ngx.ERR, "Failed to reschedule webhook timer: ", err)
        end
    end

    local ok, err = ngx.timer.at(interval, handler)
    if not ok then
        ngx.log(ngx.ERR, "Failed to start webhook flush timer: ", err)
    end
end

-- Update webhook configuration from Redis
function _M.update_config(config_data)
    if config_data then
        webhook_cache:set("webhooks:config", cjson.encode(config_data), 300)
    end
end

-- Helper function to create common event data
function _M.create_event_data(context, extra_data)
    local data = {
        request_id = ngx.var.request_id or ngx.now(),
        client_ip = ngx.var.http_x_forwarded_for or ngx.var.remote_addr,
        host = ngx.var.http_host or ngx.var.host,
        path = ngx.var.uri,
        method = ngx.req.get_method(),
        user_agent = ngx.var.http_user_agent,
    }

    -- Add context info if available
    if context then
        if context.vhost then
            data.vhost_id = context.vhost.vhost_id
        end
        if context.endpoint then
            data.endpoint_id = context.endpoint.endpoint_id
        end
    end

    -- Merge extra data
    if extra_data then
        for k, v in pairs(extra_data) do
            data[k] = v
        end
    end

    return data
end

-- Convenience functions for common events

function _M.notify_blocked(context, reason, spam_score, spam_flags)
    local data = _M.create_event_data(context, {
        reason = reason,
        spam_score = spam_score,
        spam_flags = spam_flags,
    })
    return _M.queue_event(_M.EVENT_TYPES.REQUEST_BLOCKED, data)
end

function _M.notify_rate_limit(context, rate_type, current_rate, limit)
    local data = _M.create_event_data(context, {
        rate_type = rate_type,
        current_rate = current_rate,
        limit = limit,
    })
    return _M.queue_event(_M.EVENT_TYPES.RATE_LIMIT_TRIGGERED, data)
end

function _M.notify_high_spam_score(context, spam_score, threshold, spam_flags)
    local data = _M.create_event_data(context, {
        spam_score = spam_score,
        threshold = threshold,
        spam_flags = spam_flags,
    })
    return _M.queue_event(_M.EVENT_TYPES.HIGH_SPAM_SCORE, data)
end

function _M.notify_captcha_triggered(context, reason)
    local data = _M.create_event_data(context, {
        reason = reason,
    })
    return _M.queue_event(_M.EVENT_TYPES.CAPTCHA_TRIGGERED, data)
end

function _M.notify_honeypot(context, field_name)
    local data = _M.create_event_data(context, {
        honeypot_field = field_name,
    })
    return _M.queue_event(_M.EVENT_TYPES.HONEYPOT_TRIGGERED, data)
end

function _M.notify_disposable_email(context, emails)
    local data = _M.create_event_data(context, {
        disposable_emails = emails,
    })
    return _M.queue_event(_M.EVENT_TYPES.DISPOSABLE_EMAIL, data)
end

-- Get current queue stats
function _M.get_stats()
    return {
        queue_size = #event_queue,
        last_flush = last_flush_time,
        max_queue_size = MAX_QUEUE_SIZE,
    }
end

return _M
