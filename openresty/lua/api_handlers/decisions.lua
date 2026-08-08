-- api_handlers/decisions.lua
-- The request explorer: search enforcement decisions, and explain one.
--
-- Reads the capped list decision_recorder writes. Filtering happens here rather
-- than in Redis because the list is bounded (2000 by default) and a LIST has no
-- secondary indexes -- adding them would mean a second write path to keep
-- consistent, for a dataset small enough to scan.

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local decision_recorder = require "decision_recorder"

local KEYS = decision_recorder.get_keys()

local DEFAULT_LIMIT = 50
local MAX_LIMIT = 500
-- Scanned per search. The list is capped at the configured retention, so this
-- only bounds the work when retention is raised a long way.
local MAX_SCAN = 5000

--- How much of the score the trace actually accounts for.
--
-- This is reported rather than assumed. The invariant "the trace sums to the
-- score" was broken in three separate places while building this -- defense
-- lines in two merge paths, and vhost keywords added after the executor
-- returned -- each time silently, because a plausible-looking breakdown that
-- happens to omit a contributor looks exactly like a complete one. Surfacing
-- the shortfall means the next scoring path added outside the trace announces
-- itself instead of quietly making the explanation wrong.
local function attribute(record)
    local traced = 0
    for _, entry in ipairs(record.trace or {}) do
        traced = traced + (tonumber(entry.score) or 0)
    end
    record.traced_score = traced
    record.unattributed_score = (record.score or 0) - traced
    return record
end

local function as_array(t)
    if type(t) ~= "table" then
        return setmetatable({}, cjson.array_mt)
    end
    return setmetatable(t, cjson.array_mt)
end

local function query_arg(name, default)
    local args = ngx.req.get_uri_args()
    local value = args[name]
    if type(value) == "table" then value = value[1] end
    if value == nil or value == "" then return default end
    return value
end

local function clamp(value, default, min, max)
    local n = tonumber(value) or default
    n = math.floor(n)
    if n < min then return min end
    if n > max then return max end
    return n
end

--- Does this record match every supplied filter?
local function matches(record, f)
    if f.vhost_id and record.vhost_id ~= f.vhost_id then return false end
    if f.endpoint_id and record.endpoint_id ~= f.endpoint_id then return false end
    if f.client_ip and record.client_ip ~= f.client_ip then return false end
    if f.action and record.action ~= f.action then return false end
    if f.min_score and (record.score or 0) < f.min_score then return false end
    if f.since and (record.ts or 0) < f.since then return false end
    if f.until_ts and (record.ts or 0) > f.until_ts then return false end

    if f.flag then
        local found = false
        for _, flag in ipairs(record.flags or {}) do
            if flag == f.flag or flag:find(f.flag, 1, true) then
                found = true
                break
            end
        end
        if not found then return false end
    end

    -- Plain substring, not a pattern: an operator pasting a path from a log
    -- should not have to escape it, and a bad pattern here would error rather
    -- than simply not match.
    if f.path and not (record.path or ""):find(f.path, 1, true) then return false end

    return true
end

--- Walk the list, newest first, collecting matches.
local function search(red, filters, limit)
    local raw = red:lrange(KEYS.decisions, 0, MAX_SCAN - 1)
    if type(raw) ~= "table" then
        return {}, 0
    end

    local out, scanned = {}, 0
    for _, entry in ipairs(raw) do
        scanned = scanned + 1
        local record = cjson.decode(entry)
        if type(record) == "table" and matches(record, filters) then
            out[#out + 1] = attribute(record)
            if #out >= limit then break end
        end
    end
    return out, scanned
end

local function collect_filters()
    return {
        vhost_id    = query_arg("vhost_id"),
        endpoint_id = query_arg("endpoint_id"),
        client_ip   = query_arg("client_ip"),
        action      = query_arg("action"),
        flag        = query_arg("flag"),
        path        = query_arg("path"),
        min_score   = tonumber(query_arg("min_score")),
        since       = tonumber(query_arg("since")),
        until_ts    = tonumber(query_arg("until")),
    }
end

_M.handlers = {}

-- GET /decisions - search the decision log
_M.handlers["GET:/decisions"] = function()
    local limit = clamp(query_arg("limit", DEFAULT_LIMIT), DEFAULT_LIMIT, 1, MAX_LIMIT)

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end

    local decisions, scanned = search(red, collect_filters(), limit)
    local stats = red:hgetall(KEYS.stats)
    local total = 0
    local dropped = 0
    if type(stats) == "table" then
        for i = 1, #stats, 2 do
            if stats[i] == "total" then total = tonumber(stats[i + 1]) or 0 end
            if stats[i] == "dropped_total" then dropped = tonumber(stats[i + 1]) or 0 end
        end
    end
    utils.close_redis(red)

    local cfg = decision_recorder.get_config()

    return utils.json_response({
        decisions = as_array(decisions),
        count = #decisions,
        limit = limit,
        scanned = scanned,
        -- Non-zero means the recorder's buffer overflowed and the log has holes.
        dropped_total = dropped,
        recorded_total = total,
        retention = {
            enabled = cfg.enabled,
            max_records = cfg.max_records,
            ttl_seconds = cfg.ttl,
            min_score = cfg.min_score,
        },
    })
end

-- DELETE /decisions - discard the log
_M.handlers["DELETE:/decisions"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end

    red:del(KEYS.decisions)
    red:del(KEYS.stats)
    utils.close_redis(red)

    ngx.log(ngx.WARN, "DECISION_LOG_CLEARED by=",
            (ngx.ctx.admin_user and ngx.ctx.admin_user.username) or "unknown")

    return utils.json_response({ cleared = true })
end

-- Parametric: GET /decisions/{request_id} - explain one decision
_M.resource_handlers = {}

_M.resource_handlers["GET"] = function(request_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end

    local raw = red:lrange(KEYS.decisions, 0, MAX_SCAN - 1)
    utils.close_redis(red)

    if type(raw) == "table" then
        for _, entry in ipairs(raw) do
            local record = cjson.decode(entry)
            if type(record) == "table" and record.request_id == request_id then
                return utils.json_response({ decision = attribute(record) })
            end
        end
    end

    -- 404 here means "not retained", which is a different thing from "never
    -- happened" -- the log is capped and time-limited by design.
    return utils.error_response(
        "No decision recorded for request id '" .. tostring(request_id) ..
        "'. The log is capped and time-limited, so an older request may have aged out.", 404)
end

return _M
