--[[
    Decision recorder
    =================
    Answers "why was this blocked?" without a log grep.

    The engine already computes a rich verdict -- a score, a flag per detection,
    and now a per-node trace of which mechanism contributed what. All of it was
    being reduced to one log line and discarded. Support questions about a
    specific blocked request had no better answer than "look for it in the error
    log", which does not survive contact with a customer who has a request id and
    a complaint.

    Recorded in the log phase, deliberately
    ---------------------------------------
    process_request has several enforcement branches -- block by profile, block by
    threshold, CAPTCHA challenge, tarpit, monitoring pass-through, plain allow --
    and hooking each one is how you end up with a recorder that covers most of
    them. That exact mistake was made in shadow mode, where one of two would-block
    branches was missed at first.

    So process_request stashes the verdict on ngx.ctx and a single log-phase call
    records it with the response status attached. One record per request, with
    the outcome that actually happened rather than the one predicted mid-pipeline.

    What is kept
    ------------
    Not every request: a busy site would fill Redis with successful form posts
    that nobody will ever look up. By default only decisions that did something --
    blocked, challenged, tarpitted, or would-have-blocked -- plus anything scoring
    above a threshold, so a near-miss is still explicable. Both bounded and both
    configurable, because "why did this get through?" is as common a question as
    "why was this blocked?".
]]

local buffer_lib = require "decision_buffer"

local _M = {}

local KEYS = {
    decisions = "waf:decisions",        -- capped list, newest first
    stats     = "waf:decisions:stats",  -- HASH totals
}

-- Bounds. Ceilings, not tuning knobs: each is what stops the decision log
-- becoming its own incident on a busy site.
local MAX_BUFFERED    = 500
local MAX_TRACE       = 20      -- nodes itemised per record
local MAX_FLAGS       = 30
local MAX_FLAG_LENGTH = 120
local MAX_PATH_LENGTH = 256
local MAX_UA_LENGTH   = 200

local DEFAULT_MAX_RECORDS = 2000
local DEFAULT_TTL         = 7 * 24 * 3600
local DEFAULT_MIN_SCORE   = 1

local clip = buffer_lib.clip

local buffer = buffer_lib.new({
    dict_name    = "decision_cache",
    prefix       = "decision",
    max_buffered = MAX_BUFFERED,
})

--- Retention is configurable because the right answer differs by deployment: a
--- high-traffic site wants a short window, an audited one wants a long tail.
--- Read once per worker -- these do not change without a restart.
local _config
local function config()
    if _config then return _config end

    local function num(name, default, min, max)
        local v = tonumber(os.getenv(name))
        if not v then return default end
        if v < min then return min end
        if max and v > max then return max end
        return v
    end

    _config = {
        -- Off is a legitimate choice: the decision log stores request paths and
        -- client IPs, which some deployments would rather not retain at all.
        enabled     = os.getenv("WAF_DECISION_LOG_ENABLED") ~= "false",
        max_records = num("WAF_DECISION_LOG_MAX", DEFAULT_MAX_RECORDS, 10, 50000),
        ttl         = num("WAF_DECISION_LOG_TTL", DEFAULT_TTL, 60),
        -- Below this score an allowed request is not worth a record. 0 records
        -- everything, which is supported but will fill the buffer on a busy site.
        min_score   = num("WAF_DECISION_LOG_MIN_SCORE", DEFAULT_MIN_SCORE, 0),
    }
    return _config
end

--- Reset the memoised config. Tests only.
function _M._reset_config()
    _config = nil
end

local function clip_list(list, limit, max_len)
    if type(list) ~= "table" then return nil end
    local out = {}
    for i = 1, math.min(#list, limit) do
        out[i] = clip(list[i], max_len)
    end
    return out
end

--- Trim a trace to what is useful in a detail view: the mechanisms that did
--- something. A profile with 30 nodes mostly reports zeros, and storing them
--- crowds out the entries that explain the verdict.
local function compact_trace(trace)
    if type(trace) ~= "table" then return nil end

    local significant = {}
    for _, entry in ipairs(trace) do
        if type(entry) == "table" then
            local contributed = (entry.score or 0) ~= 0 or entry.blocked
                or (entry.flags and #entry.flags > 0)
                or entry.suppressed
            if contributed then
                significant[#significant + 1] = {
                    node       = entry.node,
                    defense    = entry.defense,
                    score      = entry.score or 0,
                    blocked    = entry.blocked or nil,
                    flags      = clip_list(entry.flags, 8, MAX_FLAG_LENGTH),
                    suppressed = clip_list(entry.suppressed, 8, MAX_FLAG_LENGTH),
                }
                if #significant >= MAX_TRACE then break end
            end
        end
    end
    return significant
end

--- Should this decision be kept?
function _M.should_record(action, score)
    local cfg = config()
    if not cfg.enabled then return false end
    if action and action ~= "allowed" then return true end
    return (score or 0) >= cfg.min_score
end

--- Record one enforcement decision. Log phase only -- must not touch Redis.
-- @param decision table  request_id, vhost_id, endpoint_id, client_ip, host,
--                        path, method, user_agent, action, status, mode, score,
--                        flags, blocked_by, block_reason, trace
function _M.record(decision)
    if type(decision) ~= "table" then
        return false
    end
    if not _M.should_record(decision.action, decision.score) then
        return false
    end

    return buffer:record({
        ts           = ngx.time(),
        request_id   = decision.request_id,
        vhost_id     = decision.vhost_id or "unknown",
        endpoint_id  = decision.endpoint_id or "global",
        client_ip    = decision.client_ip,
        host         = clip(decision.host, MAX_PATH_LENGTH),
        path         = clip(decision.path, MAX_PATH_LENGTH),
        method       = decision.method,
        user_agent   = clip(decision.user_agent, MAX_UA_LENGTH),
        action       = decision.action,
        status       = decision.status,
        mode         = decision.mode,
        score        = decision.score or 0,
        block_reason = clip(decision.block_reason, MAX_FLAG_LENGTH),
        blocked_by   = clip_list(decision.blocked_by, 10, MAX_FLAG_LENGTH),
        flags        = clip_list(decision.flags, MAX_FLAGS, MAX_FLAG_LENGTH),
        trace        = compact_trace(decision.trace),
    })
end

local function write_record(red, decoded, raw)
    red:lpush(KEYS.decisions, raw)
    red:hincrby(KEYS.stats, "total", 1)
    red:hincrby(KEYS.stats, "action:" .. (decoded.action or "unknown"), 1)
end

--- Drain into Redis. Timer context only.
function _M.flush(red)
    if not red then
        return 0
    end

    local cfg = config()
    local flushed, dropped = buffer:flush(red, write_record)

    if flushed > 0 then
        red:ltrim(KEYS.decisions, 0, cfg.max_records - 1)
        red:expire(KEYS.decisions, cfg.ttl)
        red:expire(KEYS.stats, cfg.ttl)
    end

    if dropped > 0 then
        red:hincrby(KEYS.stats, "dropped_total", dropped)
    end

    return flushed
end

function _M.get_keys()
    return KEYS
end

function _M.get_config()
    return config()
end

function _M.buffer_depth()
    return buffer:depth()
end

return _M
