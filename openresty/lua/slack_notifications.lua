--[[
    Slack Notifications Module
    Sends formatted notifications to Slack webhooks for security events

    Features:
    - Attack lifecycle tracking (started -> ongoing -> resolved)
    - Intelligent deduplication to avoid Slack flooding
    - Pretty-formatted messages with colored attachments and fields
    - Configurable update intervals and resolution thresholds
]]

local _M = {}

local http_utils = require "http_utils"
local cjson = require "cjson.safe"
local redis = require "resty.redis"
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local trusted_proxies = require "trusted_proxies"

-- Shared dictionary for config cache
local config_cache = ngx.shared.config_cache

-- Redis configuration (same as redis_sync.lua)
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil
local REDIS_DB = tonumber(os.getenv("REDIS_DB")) or 0

-- Redis key patterns
local KEYS = {
    config = "waf:slack:config",
    attack_prefix = "waf:slack:attack:",
    active_attacks = "waf:slack:active_attacks",
    stats = "waf:slack:stats",
}

-- Default configuration
local DEFAULT_CONFIG = {
    enabled = false,
    webhook_url = "",
    channel = "",
    update_interval = 300,      -- 5 minutes
    resolution_threshold = 600, -- 10 minutes
    -- R-12: only event types that are actually emitted today. Previously this
    -- shipped with rate_limit_triggered, high_spam_score and fingerprint_flood
    -- enabled by default, none of which have an emitter, so a default install
    -- advertised alerts it could never send.
    events = {
        "request_blocked",
        "captcha_triggered",
        "honeypot_triggered",
        "disposable_email",
    },
    mention_users = {},
    mention_on_high_severity = false,
    severity_thresholds = {
        high_event_count = 100,
        high_event_rate = 10,
    },
}

-- Message type colors (Slack color values)
local COLORS = {
    attack_started = "danger",   -- Red
    attack_ongoing = "warning",  -- Yellow
    attack_resolved = "good",    -- Green
}

-- Message type pretext (headers with emoji)
local PRETEXT = {
    attack_started = ":rotating_light: *Attack Detected*",
    attack_ongoing = ":warning: *Ongoing Attack Update*",
    attack_resolved = ":white_check_mark: *Attack Resolved*",
}

-- Attack type display names
local ATTACK_TYPE_DISPLAY = {
    request_blocked = "Request Blocked",
    rate_limit_triggered = "Rate Limit Triggered",
    high_spam_score = "High Spam Score",
    captcha_triggered = "CAPTCHA Triggered",
    honeypot_triggered = "Honeypot Triggered",
    disposable_email = "Disposable Email Detected",
    fingerprint_flood = "Fingerprint Flood Detected",
}

-- Get Redis connection
local function get_redis_connection()
    local red = redis:new()
    red:set_timeout(2000)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        return nil, "failed to connect to Redis: " .. (err or "unknown")
    end

    if REDIS_PASSWORD and REDIS_PASSWORD ~= "" then
        local res, err = red:auth(REDIS_PASSWORD)
        if not res then
            red:close()
            return nil, "Redis auth failed: " .. (err or "unknown")
        end
    end

    if REDIS_DB and REDIS_DB > 0 then
        local res, err = red:select(REDIS_DB)
        if not res then
            red:close()
            return nil, "Redis select failed: " .. (err or "unknown")
        end
    end

    return red
end

-- Return connection to pool
local function close_redis(red)
    if not red then return end
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        red:close()
    end
end

-- Sentinel stored in the shared dict to remember "no config in Redis".
-- Without it, an unconfigured Slack meant a fresh Redis connection on every
-- single call, forever (R-04).
local NEGATIVE_CACHE = "\0none"
local NEGATIVE_CACHE_TTL = 30

-- Get Slack configuration.
--
-- R-04: `allow_redis` MUST be false anywhere reachable from the request path.
-- The repository invariant is that nothing in the request path reads Redis;
-- config is populated into the shared dict by redis_sync and update_config.
-- Timer context (process_event, resolution checker) may pass true.
local function get_slack_config(allow_redis)
    -- Try cache first
    local cached = config_cache:get("slack:config")
    if cached then
        if cached == NEGATIVE_CACHE then
            return nil
        end
        return cjson.decode(cached)
    end

    if not allow_redis then
        -- Cache miss in the request path: treat as "not configured" rather than
        -- blocking on Redis. redis_sync repopulates within WAF_SYNC_INTERVAL.
        return nil
    end

    -- Fallback to Redis
    local red, err = get_redis_connection()
    if not red then
        ngx.log(ngx.WARN, "slack_notifications: failed to get Redis connection: ", err)
        return nil
    end

    local config_str, err = red:get(KEYS.config)
    close_redis(red)

    if not config_str or config_str == ngx.null then
        config_cache:set("slack:config", NEGATIVE_CACHE, NEGATIVE_CACHE_TTL)
        return nil
    end

    local config = cjson.decode(config_str)
    if config then
        -- Cache for 60 seconds
        config_cache:set("slack:config", config_str, 60)
    end

    return config
end

-- Check if Slack notifications are enabled
-- R-04: called synchronously from webhooks.queue_event in the access phase,
-- so this must never reach Redis.
function _M.is_enabled()
    local config = get_slack_config(false)
    return config and config.enabled and config.webhook_url and config.webhook_url ~= "" or false
end

-- Update configuration from external source (called by redis_sync)
function _M.update_config(config_data)
    if config_data then
        config_cache:set("slack:config", cjson.encode(config_data), 60)
    end
end

-- R-03: a failing Slack endpoint previously caused an immediate retry on every
-- event, because the attempt clock only advanced on success. Combined with one
-- timer per blocked request that exhausts lua_max_running_timers (default 256)
-- and starves redis_sync / instance_coordinator.
local FAILURE_KEY = "slack:consecutive_failures"
local BREAKER_KEY = "slack:breaker_until"
local BREAKER_THRESHOLD = 5
local BREAKER_COOLDOWN = 300      -- seconds to stay open
local INFLIGHT_KEY = "slack:inflight"
local MAX_INFLIGHT = 32           -- concurrent Slack timers

-- R-02: a hard ceiling on notifications per minute, independent of dedup.
-- Slack incoming webhooks rate-limit at roughly 1 msg/s, so without this the WAF
-- can denial-of-service its own alerting channel.
local NOTIFY_RATE_KEY = "slack:notify_rate:"
local MAX_NOTIFICATIONS_PER_MIN = 20
-- Ceiling on tracked concurrent attacks, so waf:slack:active_attacks cannot grow
-- without bound.
local MAX_ACTIVE_ATTACKS = 500

local function notification_budget_available()
    local window = math.floor(ngx.time() / 60)
    local count = config_cache:incr(NOTIFY_RATE_KEY .. window, 1, 0, 120)
    if count == nil then
        return true   -- shared dict unavailable: fail open rather than go silent
    end
    if count == MAX_NOTIFICATIONS_PER_MIN + 1 then
        ngx.log(ngx.WARN, "slack_notifications: notification rate limit reached (",
                MAX_NOTIFICATIONS_PER_MIN, "/min); suppressing further sends this minute")
    end
    return count <= MAX_NOTIFICATIONS_PER_MIN
end

local function breaker_is_open()
    local until_ts = config_cache:get(BREAKER_KEY)
    return until_ts ~= nil and until_ts > ngx.time()
end

local function record_send_result(success)
    if success then
        config_cache:set(FAILURE_KEY, 0)
        config_cache:delete(BREAKER_KEY)
        return
    end

    local failures = config_cache:incr(FAILURE_KEY, 1, 0, 3600) or 1
    if failures >= BREAKER_THRESHOLD then
        config_cache:set(BREAKER_KEY, ngx.time() + BREAKER_COOLDOWN, BREAKER_COOLDOWN + 60)
        ngx.log(ngx.ERR, "slack_notifications: circuit breaker opened after ",
                failures, " consecutive failures; pausing sends for ",
                BREAKER_COOLDOWN, "s")
    end
end

-- Schedule a notification without blocking the caller.
-- R-01: called directly by webhooks.queue_event *before* any webhook-specific
-- early return, so Slack no longer inherits the webhook enable flag, event
-- filter or queue-full condition.
function _M.dispatch_async(event_type, event_data)
    if not _M.is_enabled() then
        return false, "slack not enabled"
    end

    -- R-03: bound concurrent timers. init_ttl makes the counter self-healing if
    -- a worker dies mid-flight.
    local inflight = config_cache:incr(INFLIGHT_KEY, 1, 0, 60)
    if inflight and inflight > MAX_INFLIGHT then
        config_cache:incr(INFLIGHT_KEY, -1, 0, 60)
        ngx.log(ngx.WARN, "slack_notifications: ", MAX_INFLIGHT,
                " notifications already in flight, dropping event: ", event_type)
        return false, "in-flight cap reached"
    end

    local ok, err = ngx.timer.at(0, function(premature)
        if premature then
            config_cache:incr(INFLIGHT_KEY, -1, 0, 60)
            return
        end
        local pok, perr = pcall(_M.process_event, event_type, event_data or {})
        config_cache:incr(INFLIGHT_KEY, -1, 0, 60)
        if not pok then
            ngx.log(ngx.ERR, "slack_notifications: process_event failed: ", perr)
        end
    end)

    if not ok then
        config_cache:incr(INFLIGHT_KEY, -1, 0, 60)
        ngx.log(ngx.ERR, "slack_notifications: failed to schedule notification: ", err)
        return false, err
    end

    return true
end

-- Generate IP prefix from full IP (anonymize last octet)
local function get_ip_prefix(ip)
    if not ip then return "unknown" end

    -- Check if IPv6
    if ip:find(":") then
        -- For IPv6, use /48 prefix (first 3 segments)
        local segments = {}
        for seg in ip:gmatch("[^:]+") do
            table.insert(segments, seg)
            if #segments >= 3 then break end
        end
        return table.concat(segments, ":") .. "::/48"
    else
        -- For IPv4, use /24 prefix (first 3 octets)
        local parts = {}
        for part in ip:gmatch("%d+") do
            table.insert(parts, part)
            if #parts >= 3 then break end
        end
        return table.concat(parts, ".") .. ".x/24"
    end
end

-- Extract attack type identifier from event
local function get_attack_type(event_type, event_data)
    if event_type == "request_blocked" then
        local reason = event_data.reason or "unknown"
        return "blocked:" .. reason
    elseif event_type == "high_spam_score" then
        local score = event_data.spam_score or 0
        if score >= 90 then
            return "spam_score:90+"
        elseif score >= 80 then
            return "spam_score:80-89"
        else
            return "spam_score:high"
        end
    elseif event_type == "honeypot_triggered" then
        local field = event_data.honeypot_field or "unknown"
        return "honeypot:" .. field
    elseif event_type == "rate_limit_triggered" then
        local rate_type = event_data.rate_type or "unknown"
        return "rate_limit:" .. rate_type
    elseif event_type == "captcha_triggered" then
        local reason = event_data.reason or "unknown"
        return "captcha:" .. reason
    elseif event_type == "disposable_email" then
        return "disposable_email"
    elseif event_type == "fingerprint_flood" then
        return "fingerprint_flood"
    else
        return event_type
    end
end

-- R-02: event_data.host is ngx.var.http_host and event_data.path is
-- ngx.var.uri -- both fully attacker-controlled. Feeding them raw into the dedup
-- key let an attacker mint a distinct "attack" per request (/a1, /a2, ... or a
-- varying Host), each of which is brand new and therefore notifies immediately.
--
-- Only the WAF-resolved identifiers are trusted here: vhost_id and endpoint_id
-- come from the configured vhost/endpoint sets, so their cardinality is bounded
-- by configuration rather than by the attacker. When the request did not resolve
-- to a configured endpoint the exact path carries no grouping value anyway, so
-- it collapses to a single bucket.
local function resolved_component(value, fallback)
    if type(value) == "string" and value ~= "" then
        return value
    end
    return fallback
end

-- Generate unique attack key
function _M.generate_attack_key(event_type, event_data)
    local ip = event_data.client_ip or "unknown"
    local ip_prefix = get_ip_prefix(ip)
    local attack_type = get_attack_type(event_type, event_data)
    local vhost = resolved_component(event_data.vhost_id, "unresolved-vhost")
    local endpoint = resolved_component(event_data.endpoint_id, "unresolved-endpoint")

    -- Create hash of these components
    local sha256 = resty_sha256:new()
    sha256:update(ip_prefix)
    sha256:update("|")
    sha256:update(attack_type)
    sha256:update("|")
    sha256:update(vhost)
    sha256:update("|")
    sha256:update(endpoint)
    local digest = sha256:final()

    -- Return first 16 chars of hex digest as attack key
    return str.to_hex(digest):sub(1, 16)
end

-- Get attack state from Redis
local function get_attack_state(red, attack_key)
    local state_str, err = red:get(KEYS.attack_prefix .. attack_key)
    if not state_str or state_str == ngx.null then
        return nil
    end
    return cjson.decode(state_str)
end

-- Save attack state to Redis
local function save_attack_state(red, attack_key, state, ttl)
    local state_str = cjson.encode(state)
    red:setex(KEYS.attack_prefix .. attack_key, ttl, state_str)
end

-- Format Slack timestamp
local function format_slack_timestamp(timestamp)
    return string.format("<!date^%d^{date_short} {time}|%s>",
        timestamp,
        os.date("%Y-%m-%d %H:%M", timestamp))
end

-- Format duration for display
local function format_duration(start_time, end_time)
    local diff = (end_time or ngx.time()) - start_time
    if diff < 60 then
        return string.format("%d seconds", diff)
    elseif diff < 3600 then
        return string.format("%d minutes", math.floor(diff / 60))
    else
        local hours = math.floor(diff / 3600)
        local mins = math.floor((diff % 3600) / 60)
        return string.format("%d hours %d minutes", hours, mins)
    end
end

-- R-14: Slack parses <...> control sequences in message text and attachment
-- fields, so `<!channel>` pings everyone and `<https://evil|Slack Security>`
-- renders an attacker-chosen link inside what looks like an official WAF alert.
-- target_vhost is ngx.var.http_host, target_endpoint is ngx.var.uri, and
-- honeypot field names / spam reasons are attacker-influenced, so every one of
-- them must be escaped and length-capped before it reaches a payload.
-- Escaping per Slack's documented rules: & first, then < and >.
local function slack_escape(value, max_len)
    if value == nil then
        return ""
    end
    value = tostring(value)
    value = value:gsub("&", "&amp;")
    value = value:gsub("<", "&lt;")
    value = value:gsub(">", "&gt;")
    -- Backticks would otherwise break out of the code spans used below.
    value = value:gsub("`", "'")
    max_len = max_len or 128
    if #value > max_len then
        value = value:sub(1, max_len) .. "..."
    end
    return value
end

-- Format detection details from event data
local function format_detection_details(event_data)
    local details = {}

    if event_data.spam_flags and #event_data.spam_flags > 0 then
        local flags = {}
        for _, flag in ipairs(event_data.spam_flags) do
            table.insert(flags, "`" .. slack_escape(flag, 64) .. "`")
        end
        table.insert(details, "*Spam Flags:* " .. table.concat(flags, ", "))
    end

    if event_data.spam_score then
        table.insert(details, "*Spam Score:* " .. tostring(event_data.spam_score))
    end

    if event_data.reason then
        table.insert(details, "*Reason:* " .. slack_escape(event_data.reason))
    end

    if event_data.honeypot_field then
        table.insert(details, "*Honeypot Field:* `" .. slack_escape(event_data.honeypot_field, 64) .. "`")
    end

    if event_data.rate_type then
        table.insert(details, "*Rate Type:* " .. event_data.rate_type)
        if event_data.current_rate then
            table.insert(details, "*Current Rate:* " .. event_data.current_rate)
        end
        if event_data.limit then
            table.insert(details, "*Limit:* " .. event_data.limit)
        end
    end

    if #details == 0 then
        return nil
    end

    return table.concat(details, "\n")
end

-- Get human-readable attack type display name
local function get_attack_type_display(attack_type)
    -- Parse the attack_type to get base type
    local base_type = attack_type:match("^([^:]+)")
    if base_type == "blocked" then
        local reason = attack_type:match(":(.+)$")
        if reason == "keyword" then
            return "Keyword Filter Block"
        elseif reason == "spam_score" or reason == "spam_score_exceeded" then
            return "Spam Score Block"
        elseif reason == "hash" then
            return "Content Hash Block"
        elseif reason == "reputation" then
            return "IP Reputation Block"
        elseif reason == "geoip" then
            return "GeoIP Block"
        else
            return "Request Blocked (" .. (reason or "unknown") .. ")"
        end
    elseif base_type == "spam_score" then
        return "High Spam Score"
    elseif base_type == "honeypot" then
        return "Honeypot Triggered"
    elseif base_type == "rate_limit" then
        return "Rate Limit Exceeded"
    elseif base_type == "captcha" then
        return "CAPTCHA Required"
    elseif base_type == "disposable_email" then
        return "Disposable Email"
    elseif base_type == "fingerprint_flood" then
        return "Fingerprint Flood"
    else
        return attack_type
    end
end

-- Build fallback text for non-attachment clients
local function build_fallback_text(message_type, state)
    local action = ""
    if message_type == "attack_started" then
        action = "Attack Detected"
    elseif message_type == "attack_ongoing" then
        action = "Ongoing Attack Update"
    else
        action = "Attack Resolved"
    end

    return string.format("%s: %s on %s%s - %d events",
        action,
        get_attack_type_display(state.attack_type),
        slack_escape(state.target_vhost or "unknown"),
        slack_escape(state.target_endpoint or ""),
        state.event_count or 1)
end

-- Build footer text
local function build_footer(message_type, state, config)
    if message_type == "attack_started" then
        return string.format("Attack ID: %s | WAF Appliance", state.attack_key)
    elseif message_type == "attack_ongoing" then
        return string.format("Attack ID: %s | Started: %s",
            state.attack_key,
            os.date("%Y-%m-%d %H:%M", state.first_seen))
    else
        config = config or DEFAULT_CONFIG
        return string.format("Attack ID: %s | No new events for %d minutes",
            state.attack_key,
            math.floor((config.resolution_threshold or 600) / 60))
    end
end

-- Calculate event rate (events per minute)
local function calculate_event_rate(state)
    local duration = (state.last_seen or ngx.time()) - state.first_seen
    if duration <= 0 then
        return state.event_count or 1
    end
    return math.floor(((state.event_count or 1) / duration) * 60)
end

-- Format Slack attachment message
function _M.format_slack_attachment(message_type, state)
    local fields = {}

    -- Attack Type (short field)
    table.insert(fields, {
        title = "Attack Type",
        value = get_attack_type_display(state.attack_type),
        short = true,
    })

    -- Target (short field)
    table.insert(fields, {
        title = "Target",
        value = slack_escape((state.target_vhost or "unknown") .. (state.target_endpoint or ""), 256),
        short = true,
    })

    if message_type == "attack_started" then
        -- Source IP (short field)
        table.insert(fields, {
            title = "Source IP",
            value = slack_escape(state.source_ip_prefix or "unknown", 64),
            short = true,
        })

        -- Started time (short field)
        table.insert(fields, {
            title = "Started",
            value = format_slack_timestamp(state.first_seen),
            short = true,
        })

        -- Detection details (long field)
        if state.representative_event then
            local details = format_detection_details(state.representative_event)
            if details then
                table.insert(fields, {
                    title = "Detection Details",
                    value = details,
                    short = false,
                })
            end
        end

    elseif message_type == "attack_ongoing" or message_type == "attack_resolved" then
        -- Duration (short field)
        table.insert(fields, {
            title = "Duration",
            value = format_duration(state.first_seen, state.last_seen),
            short = true,
        })

        -- Total events (short field)
        table.insert(fields, {
            title = "Total Events",
            value = tostring(state.event_count or 0),
            short = true,
        })

        if message_type == "attack_ongoing" then
            -- Attack rate (short field)
            local rate = calculate_event_rate(state)
            table.insert(fields, {
                title = "Attack Rate",
                value = string.format("~%d events/min", rate),
                short = true,
            })

            -- Unique IPs (short field) - if tracked
            if state.unique_ips and state.unique_ips > 0 then
                table.insert(fields, {
                    title = "Unique IPs",
                    value = tostring(state.unique_ips),
                    short = true,
                })
            end
        end
    end

    return {
        fallback = build_fallback_text(message_type, state),
        color = COLORS[message_type],
        pretext = PRETEXT[message_type],
        fields = fields,
        footer = build_footer(message_type, state, config),
        ts = state.last_seen or ngx.time(),
    }
end

-- Build full Slack payload
local function build_slack_payload(config, message_type, state)
    local payload = {
        attachments = { _M.format_slack_attachment(message_type, state) },
    }

    -- Add channel if configured
    if config.channel and config.channel ~= "" then
        payload.channel = config.channel
    end

    -- Add @mentions for high severity
    if config.mention_on_high_severity and #(config.mention_users or {}) > 0 then
        local severity_thresholds = config.severity_thresholds or DEFAULT_CONFIG.severity_thresholds
        local is_high_severity = false

        -- Check event count threshold
        if (state.event_count or 0) >= (severity_thresholds.high_event_count or 100) then
            is_high_severity = true
        end

        -- Check event rate threshold
        local rate = calculate_event_rate(state)
        if rate >= (severity_thresholds.high_event_rate or 10) then
            is_high_severity = true
        end

        if is_high_severity then
            local mentions = {}
            for _, user_id in ipairs(config.mention_users) do
                table.insert(mentions, "<@" .. user_id .. ">")
            end
            payload.text = table.concat(mentions, " ")
        end
    end

    return payload
end

-- Send notification to Slack
local function send_to_slack(config, payload)
    if not config.webhook_url or config.webhook_url == "" then
        return false, "No webhook URL configured"
    end

    local headers = {
        ["Content-Type"] = "application/json",
        ["User-Agent"] = "FormsWAF-Slack/1.0",
    }

    local res, err = http_utils.request(config.webhook_url, {
        method = "POST",
        body = cjson.encode(payload),
        headers = headers,
        timeout = 5000,
        ssl_verify = true,
    })

    if not res then
        ngx.log(ngx.ERR, "slack_notifications: request failed: ", err)
        return false, err
    end

    if res.status >= 200 and res.status < 300 then
        ngx.log(ngx.DEBUG, "slack_notifications: sent successfully, status: ", res.status)
        return true
    else
        ngx.log(ngx.WARN, "slack_notifications: non-2xx status: ", res.status, " body: ", res.body)
        return false, "HTTP " .. res.status
    end
end

-- Check if we should notify for this attack state
local function should_notify(state, config)
    if not state then
        return true, "attack_started"
    end

    local now = ngx.time()
    local time_since_last = now - (state.last_notification or 0)
    local update_interval = config.update_interval or DEFAULT_CONFIG.update_interval

    if time_since_last >= update_interval then
        return true, "attack_ongoing"
    end

    return false, nil
end

-- Main function to process an event
function _M.process_event(event_type, event_data)
    local config = get_slack_config(true)
    if not config or not config.enabled then
        return false, "Slack notifications not enabled"
    end

    if not config.webhook_url or config.webhook_url == "" then
        return false, "No webhook URL configured"
    end

    -- Check if this event type is enabled
    local event_enabled = false
    local events = config.events or DEFAULT_CONFIG.events
    for _, evt in ipairs(events) do
        if evt == event_type or evt == "*" then
            event_enabled = true
            break
        end
    end

    if not event_enabled then
        return false, "Event type not enabled"
    end

    -- Generate attack key
    local attack_key = _M.generate_attack_key(event_type, event_data)

    -- Get Redis connection
    local red, err = get_redis_connection()
    if not red then
        ngx.log(ngx.ERR, "slack_notifications: failed to get Redis: ", err)
        return false, err
    end

    -- Calculate TTL (2x resolution threshold for cleanup)
    local resolution_threshold = config.resolution_threshold or DEFAULT_CONFIG.resolution_threshold
    local ttl = resolution_threshold * 2
    local now = ngx.time()
    local count_key = KEYS.attack_prefix .. attack_key .. ":count"

    -- Get existing attack state
    local state = get_attack_state(red, attack_key)

    -- R-05: a resolved record is terminal. check_resolved_attacks keeps it around
    -- for history, and the old code then treated a recurrence as "ongoing" -- no
    -- re-add to the active set, status stuck at "resolved", duration and rate
    -- computed from the previous run's first_seen, and no second resolution ever
    -- sent. Start a clean record instead.
    if state and state.status == "resolved" then
        state = nil
        red:del(count_key)
    end

    -- R-09: the event count is maintained with INCR rather than read-modify-write
    -- on the JSON blob, so concurrent workers and pods cannot lose events (which
    -- under-reported Attack Rate and suppressed the high-severity mention).
    local event_count = red:incr(count_key)
    if type(event_count) ~= "number" then
        event_count = 1
    end
    red:expire(count_key, ttl)

    -- Check if we should notify
    local notify, message_type = should_notify(state, config)

    if not state then
        -- R-09: claim creation atomically. Without this, two concurrent events
        -- for the same key both saw nil and both sent "Attack Detected".
        -- Only the worker whose SETNX succeeds announces the new attack.
        state = {
            attack_key = attack_key,
            attack_type = get_attack_type(event_type, event_data),
            source_ip_prefix = get_ip_prefix(event_data.client_ip),
            target_vhost = event_data.vhost_id or event_data.host,
            target_endpoint = event_data.endpoint_id or event_data.path,
            first_seen = now,
            last_seen = now,
            event_count = event_count,
            last_notification = 0,
            notification_count = 0,
            status = "active",
            representative_event = event_data,
        }

        local claimed = red:setnx(KEYS.attack_prefix .. attack_key, cjson.encode(state))
        if claimed ~= 1 then
            -- Another worker created it first: fall back to its record and treat
            -- this as an update rather than a second "attack started".
            local existing = get_attack_state(red, attack_key)
            if existing then
                state = existing
                state.last_seen = now
                state.event_count = event_count
                notify, message_type = should_notify(state, config)
            end
        else
            red:expire(KEYS.attack_prefix .. attack_key, ttl)

            -- R-02: bound the tracked set. Without a ceiling an attacker who can
            -- vary the key can grow waf:slack:active_attacks without limit.
            local active = red:scard(KEYS.active_attacks)
            if type(active) == "number" and active >= MAX_ACTIVE_ATTACKS then
                ngx.log(ngx.WARN, "slack_notifications: active attack cap (",
                        MAX_ACTIVE_ATTACKS, ") reached; not tracking new attack ", attack_key)
                notify = false
            else
                red:sadd(KEYS.active_attacks, attack_key)
            end
        end
    else
        -- Update existing attack
        state.last_seen = now
        state.event_count = event_count
    end

    if notify and not notification_budget_available() then
        -- R-02: over budget for this minute. Advance the attempt clock so the
        -- next window is not immediately consumed by a backlog.
        notify = false
        state.last_notification = now
    end

    if notify and breaker_is_open() then
        -- R-03: skip the send while the breaker is open, but still advance the
        -- attempt clock below so we do not spin once it closes.
        notify = false
        state.last_notification = now
    end

    if notify then
        -- R-03: advance the attempt clock before sending. Previously this only
        -- happened on success, so a failing endpoint retried on every single
        -- event with no backoff.
        state.last_notification = now

        -- Build and send notification
        local payload = build_slack_payload(config, message_type, state)
        local success, send_err = send_to_slack(config, payload)
        record_send_result(success)

        if success then
            state.notification_count = (state.notification_count or 0) + 1

            -- Increment stats
            red:hincrby(KEYS.stats, "total_notifications_sent", 1)
            if message_type == "attack_started" then
                red:hincrby(KEYS.stats, "attacks_detected_today", 1)
            end
        else
            ngx.log(ngx.ERR, "slack_notifications: failed to send: ", send_err)
        end
    end

    -- Save updated state
    save_attack_state(red, attack_key, state, ttl)

    close_redis(red)

    return true
end

-- Check for resolved attacks (called by timer)
function _M.check_resolved_attacks()
    local config = get_slack_config(true)
    -- R-02: when Slack is disabled the old code returned here, so
    -- waf:slack:active_attacks was never pruned and grew without bound. Keep
    -- pruning expired entries; only sending is gated on `enabled`.
    local sending_enabled = (config ~= nil and config.enabled == true)
    config = config or DEFAULT_CONFIG

    local red, err = get_redis_connection()
    if not red then
        ngx.log(ngx.ERR, "slack_notifications: failed to get Redis for resolution check: ", err)
        return
    end

    -- Get all active attacks
    local attacks, err = red:smembers(KEYS.active_attacks)
    if not attacks or type(attacks) ~= "table" then
        close_redis(red)
        return
    end

    local now = ngx.time()
    local resolution_threshold = config.resolution_threshold or DEFAULT_CONFIG.resolution_threshold

    for _, attack_key in ipairs(attacks) do
        local state = get_attack_state(red, attack_key)
        if state then
            local time_since_last = now - (state.last_seen or 0)

            if time_since_last >= resolution_threshold then
                -- Attack is resolved
                state.status = "resolved"

                local success = false
                local send_err = nil
                if sending_enabled and not breaker_is_open() and notification_budget_available() then
                    local payload = build_slack_payload(config, "attack_resolved", state)
                    success, send_err = send_to_slack(config, payload)
                    record_send_result(success)
                end

                if success then
                    -- Increment stats
                    red:hincrby(KEYS.stats, "attacks_resolved_today", 1)
                    ngx.log(ngx.INFO, "slack_notifications: attack resolved: ", attack_key)
                else
                    ngx.log(ngx.ERR, "slack_notifications: failed to send resolution: ", send_err)
                end

                -- Remove from active attacks
                red:srem(KEYS.active_attacks, attack_key)
                -- R-09: the INCR counter lives in its own key; expire it with the attack.
                red:del(KEYS.attack_prefix .. attack_key .. ":count")

                -- Update state with resolved status (keep for a bit longer for history)
                save_attack_state(red, attack_key, state, resolution_threshold)
            end
        else
            -- State expired, remove from active set
            red:srem(KEYS.active_attacks, attack_key)
            red:del(KEYS.attack_prefix .. attack_key .. ":count")
        end
    end

    close_redis(red)
end

-- Start the resolution checker timer (called once on worker init)
function _M.start_resolution_checker()
    local config = get_slack_config(true) or DEFAULT_CONFIG
    local check_interval = math.floor((config.resolution_threshold or DEFAULT_CONFIG.resolution_threshold) / 2)
    -- Minimum check interval of 30 seconds
    if check_interval < 30 then
        check_interval = 30
    end

    -- R-08: resolution checking and the daily reset are cluster singletons. The
    -- previous `ngx.worker.id() == 0` guard is once per *pod*, so at replicas=3
    -- one resolution produced three Slack messages and incremented
    -- attacks_resolved_today three times. instance_coordinator already provides
    -- SET NX PX leader election plus a task registry (redis_sync uses the same).
    local ok, coordinator = pcall(require, "instance_coordinator")
    if ok and coordinator and coordinator.register_for_leader_task then
        coordinator.register_for_leader_task("slack_resolution_check", function()
            _M.check_resolved_attacks()
        end, check_interval, 30)

        coordinator.register_for_leader_task("slack_daily_stats_reset", function()
            _M.reset_daily_stats_if_new_day()
        end, 300, 60)

        ngx.log(ngx.INFO, "slack_notifications: registered leader tasks (resolution check every ",
                check_interval, "s)")
        return
    end

    ngx.log(ngx.WARN, "slack_notifications: instance_coordinator unavailable; ",
            "running resolution checker unguarded (safe only for single-instance deployments)")

    local handler
    handler = function(premature)
        if premature then
            return
        end

        -- Run resolution check
        local ok, err = pcall(_M.check_resolved_attacks)
        if not ok then
            ngx.log(ngx.ERR, "slack_notifications: resolution check failed: ", err)
        end

        -- Reschedule
        local ok, err = ngx.timer.at(check_interval, handler)
        if not ok then
            ngx.log(ngx.ERR, "slack_notifications: failed to reschedule resolution checker: ", err)
        end
    end

    -- Start the timer
    local ok, err = ngx.timer.at(check_interval, handler)
    if not ok then
        ngx.log(ngx.ERR, "slack_notifications: failed to start resolution checker: ", err)
    else
        ngx.log(ngx.INFO, "slack_notifications: resolution checker started with interval ", check_interval, "s")
    end
end

-- Get active attacks (for API)
function _M.get_active_attacks()
    local red, err = get_redis_connection()
    if not red then
        return nil, err
    end

    local attacks = {}
    local attack_keys, err = red:smembers(KEYS.active_attacks)

    if attack_keys and type(attack_keys) == "table" then
        for _, key in ipairs(attack_keys) do
            local state = get_attack_state(red, key)
            if state then
                table.insert(attacks, state)
            end
        end
    end

    close_redis(red)
    return attacks
end

-- Get notification stats (for API)
function _M.get_stats()
    local red, err = get_redis_connection()
    if not red then
        return nil, err
    end

    local stats = red:hgetall(KEYS.stats)
    -- R-15: do the SCARD on the connection we already hold rather than opening
    -- a second one after closing this.
    local active_count = red:scard(KEYS.active_attacks)
    close_redis(red)
    if type(active_count) ~= "number" then
        active_count = 0
    end

    if not stats or type(stats) ~= "table" then
        return {
            total_notifications_sent = 0,
            attacks_detected_today = 0,
            attacks_resolved_today = 0,
            active_attacks_count = 0,
        }
    end

    -- Convert array to hash
    local result = {}
    for i = 1, #stats, 2 do
        result[stats[i]] = tonumber(stats[i+1]) or 0
    end

    -- R-13: hgetall returns an empty table on a fresh install, which passes the
    -- type guard above, so the response used to omit keys the UI declares as
    -- required numbers and the dashboard cards rendered blank. Always return a
    -- fully populated object.
    return {
        total_notifications_sent = result.total_notifications_sent or 0,
        attacks_detected_today = result.attacks_detected_today or 0,
        attacks_resolved_today = result.attacks_resolved_today or 0,
        active_attacks_count = active_count,
    }
end

-- R-13: reset_daily_stats had no scheduled caller -- only the manual endpoint --
-- so attacks_detected_today / attacks_resolved_today accumulated forever while
-- the UI labelled them "Attacks Today" / "Resolved Today". Registered as a
-- leader task so it runs once per cluster.
function _M.reset_daily_stats_if_new_day()
    local red, err = get_redis_connection()
    if not red then
        return false, err
    end

    local today = os.date("!%Y-%m-%d")
    local stored = red:hget(KEYS.stats, "stats_date")
    if stored and stored ~= ngx.null and stored == today then
        close_redis(red)
        return true, "no change"
    end

    red:hset(KEYS.stats, "attacks_detected_today", 0)
    red:hset(KEYS.stats, "attacks_resolved_today", 0)
    red:hset(KEYS.stats, "stats_date", today)
    close_redis(red)

    ngx.log(ngx.INFO, "slack_notifications: daily stats reset for ", today)
    return true
end

-- Reset daily stats (manual endpoint, and used by the daily leader task)
function _M.reset_daily_stats()
    local red, err = get_redis_connection()
    if not red then
        return false, err
    end

    red:hset(KEYS.stats, "attacks_detected_today", 0)
    red:hset(KEYS.stats, "attacks_resolved_today", 0)

    close_redis(red)
    return true
end

-- Send a test notification
function _M.send_test()
    local config = get_slack_config(true)
    if not config then
        return false, "Slack notifications not configured"
    end

    if not config.webhook_url or config.webhook_url == "" then
        return false, "No webhook URL configured"
    end

    local test_state = {
        attack_key = "test123",
        attack_type = "blocked:keyword",
        source_ip_prefix = "192.168.1.x/24",
        target_vhost = "example.com",
        target_endpoint = "/contact",
        first_seen = ngx.time() - 300,
        last_seen = ngx.time(),
        event_count = 42,
        notification_count = 1,
        status = "active",
        representative_event = {
            spam_score = 85,
            spam_flags = {"kw:test", "pattern:url"},
            reason = "spam_score_exceeded",
        },
    }

    local payload = build_slack_payload(config, "attack_started", test_state)
    payload.text = (payload.text or "") .. "\n_This is a test notification from WAF Appliance_"

    return send_to_slack(config, payload)
end

return _M
