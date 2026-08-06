-- api_handlers/slack.lua
-- Slack notification configuration handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"

-- Redis keys
local SLACK_KEYS = {
    config = "waf:slack:config",
    stats = "waf:slack:stats",
    active_attacks = "waf:slack:active_attacks",
}

-- Default configuration
local DEFAULT_CONFIG = {
    enabled = false,
    webhook_url = "",
    channel = "",
    update_interval = 300,      -- 5 minutes
    resolution_threshold = 600, -- 10 minutes
    events = {
        "request_blocked",
        "rate_limit_triggered",
        "high_spam_score",
        "honeypot_triggered",
        "fingerprint_flood",
    },
    mention_users = {},
    mention_on_high_severity = false,
    severity_thresholds = {
        high_event_count = 100,
        high_event_rate = 10,
    },
}

-- An empty Lua table encodes as a JSON object ({}), but the Admin UI treats these
-- fields as arrays (attacks.map(...), mention_users.includes(...)) and throws on an
-- object. Force array encoding for every list-valued field we emit.
-- R-06: the webhook URL is a bearer credential — anyone holding it can post
-- into the security channel. `slack:read` is granted to operator and viewer, so
-- it must never be returned verbatim. Mirrors the convention in
-- api_handlers/captcha.lua, which masks secret_key and accepts MASK on write to
-- preserve the stored value.
local URL_MASK = "***"

local function mask_webhook_url(url)
    if not url or url == "" then
        return ""
    end
    return URL_MASK
end

local function as_array(t)
    if type(t) ~= "table" then
        return setmetatable({}, cjson.array_mt)
    end
    return setmetatable(t, cjson.array_mt)
end

DEFAULT_CONFIG.events = as_array(DEFAULT_CONFIG.events)
DEFAULT_CONFIG.mention_users = as_array(DEFAULT_CONFIG.mention_users)

-- Valid event types
local VALID_EVENTS = {
    request_blocked = true,
    rate_limit_triggered = true,
    high_spam_score = true,
    captcha_triggered = true,
    honeypot_triggered = true,
    disposable_email = true,
    fingerprint_flood = true,
}

-- Handlers table
_M.handlers = {}

-- GET /slack/config - Get Slack configuration
_M.handlers["GET:/slack/config"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local config_str = red:get(SLACK_KEYS.config)
    utils.close_redis(red)

    local config = {}
    if config_str and config_str ~= ngx.null then
        config = cjson.decode(config_str) or {}
    end

    -- Merge with defaults
    for key, value in pairs(DEFAULT_CONFIG) do
        if config[key] == nil then
            config[key] = value
        end
    end

    config.events = as_array(config.events)
    config.mention_users = as_array(config.mention_users)

    -- R-06: never return the credential itself; `webhook_url_set` preserves the
    -- "is it configured?" signal the UI needs.
    config.webhook_url_set = (config.webhook_url or "") ~= ""
    config.webhook_url = mask_webhook_url(config.webhook_url)

    -- R-12: tell the UI which event types actually have an emitter so it can
    -- render the rest as unavailable rather than silently offering them.
    local webhooks = require "webhooks"
    local emitted, not_emitted = {}, {}
    for event_type, _ in pairs(VALID_EVENTS) do
        if webhooks.is_event_emitted and webhooks.is_event_emitted(event_type) then
            table.insert(emitted, event_type)
        else
            table.insert(not_emitted, event_type)
        end
    end
    table.sort(emitted)
    table.sort(not_emitted)

    return utils.json_response({
        config = config,
        defaults = DEFAULT_CONFIG,
        emitted_events = as_array(emitted),
        unavailable_events = as_array(not_emitted),
    })
end

-- PUT /slack/config - Update Slack configuration
_M.handlers["PUT:/slack/config"] = function()
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

    -- Validate webhook URL if provided and enabled.
    -- R-10: the previous check was `not slack_host and not https?://`, which is
    -- never true for any well-formed URL — the Slack-host pattern was dead code
    -- and plain http:// was accepted, sending the webhook token and every attack
    -- detail in cleartext.
    -- HTTPS is required. The host is deliberately not pinned to hooks.slack.com
    -- so Slack-compatible receivers (Mattermost, Rocket.Chat) keep working;
    -- outbound SSRF protection is applied at send time by http_utils (F15).
    if data.webhook_url and data.webhook_url ~= "" and data.webhook_url ~= URL_MASK then
        if not data.webhook_url:match("^https://") then
            utils.close_redis(red)
            return utils.error_response("Invalid webhook URL - must start with https:// (cleartext http:// would leak the webhook token and attack details)")
        end
        if #data.webhook_url > 1024 then
            utils.close_redis(red)
            return utils.error_response("webhook_url too long (max 1024 characters)")
        end
    end

    -- Validate channel format if provided (should start with # or be a channel ID)
    if data.channel and data.channel ~= "" then
        if not data.channel:match("^#") and not data.channel:match("^C[A-Z0-9]+$") then
            utils.close_redis(red)
            return utils.error_response("Invalid channel format - should start with # or be a channel ID")
        end
    end

    -- Validate update_interval (60 seconds to 30 minutes)
    if data.update_interval then
        local interval = tonumber(data.update_interval)
        if not interval or interval < 60 or interval > 1800 then
            utils.close_redis(red)
            return utils.error_response("update_interval must be between 60 and 1800 seconds")
        end
    end

    -- Validate resolution_threshold (2 to 60 minutes)
    if data.resolution_threshold then
        local threshold = tonumber(data.resolution_threshold)
        if not threshold or threshold < 120 or threshold > 3600 then
            utils.close_redis(red)
            return utils.error_response("resolution_threshold must be between 120 and 3600 seconds")
        end
    end

    -- Validate events if provided
    -- R-11: a non-array value previously skipped validation entirely and was then
    -- coerced to an empty array by as_array(), silently disabling every event
    -- while returning 200.
    if data.events ~= nil and type(data.events) ~= "table" then
        utils.close_redis(red)
        return utils.error_response("events must be an array of event type strings")
    end
    if data.events and type(data.events) == "table" then
        for _, event in ipairs(data.events) do
            if not VALID_EVENTS[event] and event ~= "*" then
                utils.close_redis(red)
                return utils.error_response("Invalid event type: " .. event)
            end
            -- R-12: accepted, but say so rather than failing silently later.
            local webhooks = require "webhooks"
            if webhooks.is_event_emitted and not webhooks.is_event_emitted(event) and event ~= "*" then
                ngx.log(ngx.WARN, "slack: event type '", event,
                        "' is enabled but has no emitter in this build; it will never fire")
            end
        end
    end

    -- Validate mention_users format (should be Slack user IDs)
    -- R-11: same silent-wipe applies here.
    if data.mention_users ~= nil and type(data.mention_users) ~= "table" then
        utils.close_redis(red)
        return utils.error_response("mention_users must be an array of Slack user IDs")
    end
    if data.mention_users and type(data.mention_users) == "table" then
        for i, user_id in ipairs(data.mention_users) do
            if type(user_id) ~= "string" or not user_id:match("^U[A-Z0-9]+$") then
                utils.close_redis(red)
                return utils.error_response("Invalid Slack user ID at index " .. i .. " - should match format U[A-Z0-9]+")
            end
        end
    end

    -- Validate severity_thresholds
    if data.severity_thresholds and type(data.severity_thresholds) == "table" then
        if data.severity_thresholds.high_event_count then
            local count = tonumber(data.severity_thresholds.high_event_count)
            if not count or count < 1 then
                utils.close_redis(red)
                return utils.error_response("high_event_count must be a positive number")
            end
        end
        if data.severity_thresholds.high_event_rate then
            local rate = tonumber(data.severity_thresholds.high_event_rate)
            if not rate or rate < 1 then
                utils.close_redis(red)
                return utils.error_response("high_event_rate must be a positive number")
            end
        end
    end

    -- R-06: GET returns the URL masked, so the UI submits URL_MASK back on save.
    -- Treat that as "unchanged" and keep the stored credential.
    local existing_config = {}
    local existing_str = red:get(SLACK_KEYS.config)
    if existing_str and existing_str ~= ngx.null then
        existing_config = cjson.decode(existing_str) or {}
    end

    local webhook_url = data.webhook_url
    if webhook_url == nil or webhook_url == URL_MASK then
        webhook_url = existing_config.webhook_url or ""
    end

    -- Build config object
    local config = {
        enabled = data.enabled == true,
        webhook_url = webhook_url,
        channel = data.channel or "",
        update_interval = tonumber(data.update_interval) or DEFAULT_CONFIG.update_interval,
        resolution_threshold = tonumber(data.resolution_threshold) or DEFAULT_CONFIG.resolution_threshold,
        events = as_array(data.events or DEFAULT_CONFIG.events),
        mention_users = as_array(data.mention_users),
        mention_on_high_severity = data.mention_on_high_severity == true,
        severity_thresholds = {
            high_event_count = tonumber((data.severity_thresholds or {}).high_event_count) or DEFAULT_CONFIG.severity_thresholds.high_event_count,
            high_event_rate = tonumber((data.severity_thresholds or {}).high_event_rate) or DEFAULT_CONFIG.severity_thresholds.high_event_rate,
        },
    }

    -- Save to Redis
    local ok, save_err = red:set(SLACK_KEYS.config, cjson.encode(config))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to save config: " .. (save_err or "unknown"))
    end

    -- Update local Slack module cache
    local slack_notifications = require "slack_notifications"
    slack_notifications.update_config(config)

    -- Trigger sync
    redis_sync.sync_now()

    local response_config = {}
    for k, v in pairs(config) do
        response_config[k] = v
    end
    response_config.webhook_url_set = (config.webhook_url or "") ~= ""
    response_config.webhook_url = mask_webhook_url(config.webhook_url)

    return utils.json_response({updated = true, config = response_config})
end

-- POST /slack/test - Send test notification to Slack
_M.handlers["POST:/slack/test"] = function()
    local slack_notifications = require "slack_notifications"

    local success, err = slack_notifications.send_test()

    if success then
        return utils.json_response({
            success = true,
            message = "Test notification sent successfully",
        })
    else
        return utils.json_response({
            success = false,
            message = "Failed to send test notification",
            error = err,
        })
    end
end

-- GET /slack/attacks - List active attack streams
_M.handlers["GET:/slack/attacks"] = function()
    local slack_notifications = require "slack_notifications"

    local attacks, err = slack_notifications.get_active_attacks()
    if not attacks then
        return utils.error_response("Failed to get active attacks: " .. (err or "unknown"))
    end

    return utils.json_response({
        attacks = as_array(attacks),
        count = #attacks,
    })
end

-- GET /slack/stats - Get notification statistics
_M.handlers["GET:/slack/stats"] = function()
    local slack_notifications = require "slack_notifications"

    local stats, err = slack_notifications.get_stats()
    if not stats then
        return utils.error_response("Failed to get stats: " .. (err or "unknown"))
    end

    return utils.json_response({
        stats = stats,
    })
end

-- POST /slack/stats/reset - Reset daily statistics
_M.handlers["POST:/slack/stats/reset"] = function()
    local slack_notifications = require "slack_notifications"

    local success, err = slack_notifications.reset_daily_stats()
    if success then
        return utils.json_response({
            reset = true,
            message = "Daily statistics reset successfully",
        })
    else
        return utils.error_response("Failed to reset stats: " .. (err or "unknown"))
    end
end

return _M
