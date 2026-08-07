--[[
    Shadow mode recorder
    ====================
    Monitoring mode already decides what it *would* have blocked -- waf_handler
    computes is_monitoring_would_block, writes a line to the error log and bumps a
    counter. Then it throws the detail away, so the only way to answer "what
    happens if I turn blocking on?" is to grep logs.

    This keeps that decision, with attribution, so the answer becomes a query.

    Two constraints shape the design, both learned from defects in this codebase:

      * Nothing in the request path may read or write Redis (R-04). Recording
        therefore writes to a shared dict and a timer flushes it.
      * One timer per request is how you exhaust lua_max_running_timers and
        starve redis_sync (R-03). A single periodic flush is used instead, the
        same shape field_learner already uses for its batching.

    The buffering itself lives in decision_buffer, shared with the enforcement
    recorder -- it carries two concurrency defects' worth of hard-won detail, and
    a second copy would likely reproduce one of them.

    Storage is bounded on purpose. A WAF in monitoring mode on a busy site sees
    everything, and an unbounded recorder becomes its own outage.
]]

local buffer_lib = require "decision_buffer"

local _M = {}

-- Redis keys
local KEYS = {
    decisions = "waf:shadow:decisions",              -- capped list of recent records
    rules     = "waf:shadow:rules",                  -- HASH profile/rule -> count
    flags     = "waf:shadow:flags",                  -- HASH detection flag -> count
    endpoints = "waf:shadow:endpoints",              -- HASH vhost|endpoint -> count
    stats     = "waf:shadow:stats",                  -- HASH totals
}

-- Bounds. These are deliberate ceilings, not tuning knobs to raise casually:
-- every one of them is what stops a busy site's monitoring mode from becoming an
-- incident of its own.
local MAX_BUFFERED     = 500     -- records held in the shared dict between flushes
local MAX_DECISIONS    = 2000    -- records retained in Redis for the detail view
local DECISION_TTL     = 7 * 24 * 3600
local MAX_FLAG_LENGTH  = 120
local MAX_PATH_LENGTH  = 256

local clip = buffer_lib.clip

-- Keys stay "shadow:*" so an in-flight buffer survives the upgrade to the
-- shared implementation rather than being stranded and expiring unflushed.
local buffer = buffer_lib.new({
    dict_name    = "shadow_cache",
    prefix       = "shadow",
    max_buffered = MAX_BUFFERED,
})

--- Record one would-block decision. Called from the request path, so this must
--- stay allocation-light and must never touch Redis.
-- @param decision table  vhost_id, endpoint_id, client_ip, host, path, method,
--                        score, blocked_by (array), flags (array)
function _M.record(decision)
    if type(decision) ~= "table" then
        return false
    end

    return buffer:record({
        ts          = ngx.time(),
        vhost_id    = decision.vhost_id or "unknown",
        endpoint_id = decision.endpoint_id or "global",
        client_ip   = decision.client_ip,
        host        = clip(decision.host, MAX_PATH_LENGTH),
        path        = clip(decision.path, MAX_PATH_LENGTH),
        method      = decision.method,
        score       = decision.score or 0,
        blocked_by  = decision.blocked_by,
        flags       = decision.flags,
    })
end

local function write_record(red, decoded, raw)
    red:lpush(KEYS.decisions, raw)

    local scope = (decoded.vhost_id or "unknown") .. "|" .. (decoded.endpoint_id or "global")
    red:hincrby(KEYS.endpoints, scope, 1)
    red:hincrby(KEYS.stats, "would_block_total", 1)

    for _, rule in ipairs(decoded.blocked_by or {}) do
        red:hincrby(KEYS.rules, clip(rule, MAX_FLAG_LENGTH), 1)
    end

    -- blocked_by names the profile ("legacy"), which tells an operator nothing
    -- about what to suppress. The flags carry the actual reason -- kw:viagra,
    -- fp_flag:suspicious-bot -- so count those too; they are what the diff view
    -- is for.
    for _, flag in ipairs(decoded.flags or {}) do
        red:hincrby(KEYS.flags, clip(flag, MAX_FLAG_LENGTH), 1)
    end
end

--- Drain the buffer into Redis. Timer context only.
-- @param red  an open Redis connection
-- @return number of records flushed
function _M.flush(red)
    if not red then
        return 0
    end

    local flushed, dropped = buffer:flush(red, write_record)

    if flushed > 0 then
        red:ltrim(KEYS.decisions, 0, MAX_DECISIONS - 1)
        red:expire(KEYS.decisions, DECISION_TTL)
        red:expire(KEYS.rules, DECISION_TTL)
        red:expire(KEYS.flags, DECISION_TTL)
        red:expire(KEYS.endpoints, DECISION_TTL)
        red:expire(KEYS.stats, DECISION_TTL)
    end

    if dropped > 0 then
        red:hincrby(KEYS.stats, "dropped_total", dropped)
    end

    return flushed
end

function _M.get_keys()
    return KEYS
end

--- Exposed for tests and for the API's "is anything buffered" check.
function _M.buffer_depth()
    return buffer:depth()
end

return _M
