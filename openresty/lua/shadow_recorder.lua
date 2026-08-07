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

    Storage is bounded on purpose. A WAF in monitoring mode on a busy site sees
    everything, and an unbounded recorder becomes its own outage.
]]

local cjson = require "cjson.safe"

local _M = {}

local shadow_cache = ngx.shared.shadow_cache

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

local BUFFER_HEAD = "shadow:head"   -- next write slot
local BUFFER_TAIL = "shadow:tail"   -- next slot to flush
local DROPPED     = "shadow:dropped"

--- Trim a value that originates from the request, so a long or hostile field
--- cannot bloat storage.
local function clip(value, limit)
    if value == nil then return nil end
    value = tostring(value)
    if #value > limit then
        return value:sub(1, limit) .. "..."
    end
    return value
end

--- Record one would-block decision. Called from the request path, so this must
--- stay allocation-light and must never touch Redis.
-- @param decision table  vhost_id, endpoint_id, client_ip, host, path, method,
--                        score, blocked_by (array), flags (array)
function _M.record(decision)
    if not shadow_cache or type(decision) ~= "table" then
        return false
    end

    local head = shadow_cache:incr(BUFFER_HEAD, 1, 0)
    if not head then
        return false
    end

    local tail = shadow_cache:get(BUFFER_TAIL) or 0
    if head - tail > MAX_BUFFERED then
        -- Buffer is full: drop this record rather than evicting an older one, and
        -- count the loss so the UI can say "showing a sample" instead of implying
        -- completeness.
        shadow_cache:incr(DROPPED, 1, 0)
        return false, "buffer full"
    end

    local record = cjson.encode({
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
    if not record then
        return false
    end

    -- Slots expire well after a flush would have consumed them, so a stalled
    -- flush cannot pin memory indefinitely.
    shadow_cache:set("shadow:rec:" .. head, record, 600)
    return true
end

--- Drain the buffer into Redis. Timer context only.
-- @param red  an open Redis connection
-- @return number of records flushed
function _M.flush(red)
    if not shadow_cache or not red then
        return 0
    end

    local head = shadow_cache:get(BUFFER_HEAD) or 0
    local tail = shadow_cache:get(BUFFER_TAIL) or 0
    if head <= tail then
        return 0
    end

    -- redis_sync's timer runs on EVERY worker, so several of them reach this at
    -- the same moment. Reading the tail, draining, then writing the tail back
    -- lets each worker drain the same slots -- three workers turned one
    -- would-block decision into three recorded copies, which would have
    -- overstated the impact of promoting an endpoint by 3x.
    --
    -- incr is atomic on a shared dict, so claim the range first and let each
    -- worker own a disjoint slice. Whoever claims nothing does nothing.
    local pending = head - tail
    local claimed_end = shadow_cache:incr(BUFFER_TAIL, pending, 0)
    if not claimed_end then
        return 0
    end
    local claimed_start = claimed_end - pending + 1

    local flushed = 0
    for slot = claimed_start, claimed_end do
        local key = "shadow:rec:" .. slot
        local record = shadow_cache:get(key)
        if record then
            local decoded = cjson.decode(record)
            if decoded then
                red:lpush(KEYS.decisions, record)

                local scope = (decoded.vhost_id or "unknown") .. "|" .. (decoded.endpoint_id or "global")
                red:hincrby(KEYS.endpoints, scope, 1)
                red:hincrby(KEYS.stats, "would_block_total", 1)

                for _, rule in ipairs(decoded.blocked_by or {}) do
                    red:hincrby(KEYS.rules, clip(rule, MAX_FLAG_LENGTH), 1)
                end

                -- blocked_by names the profile ("legacy"), which tells an
                -- operator nothing about what to suppress. The flags carry the
                -- actual reason -- kw:viagra, fp_flag:suspicious-bot -- so count
                -- those too; they are what the diff view is for.
                for _, flag in ipairs(decoded.flags or {}) do
                    red:hincrby(KEYS.flags, clip(flag, MAX_FLAG_LENGTH), 1)
                end
                flushed = flushed + 1
            end
            shadow_cache:delete(key)
        end
    end

    if flushed > 0 then
        red:ltrim(KEYS.decisions, 0, MAX_DECISIONS - 1)
        red:expire(KEYS.decisions, DECISION_TTL)
        red:expire(KEYS.rules, DECISION_TTL)
        red:expire(KEYS.flags, DECISION_TTL)
        red:expire(KEYS.endpoints, DECISION_TTL)
        red:expire(KEYS.stats, DECISION_TTL)
    end

    local dropped = shadow_cache:get(DROPPED)
    if dropped and dropped > 0 then
        red:hincrby(KEYS.stats, "dropped_total", dropped)
        shadow_cache:set(DROPPED, 0)
    end

    return flushed
end

function _M.get_keys()
    return KEYS
end

--- Exposed for tests and for the API's "is anything buffered" check.
function _M.buffer_depth()
    if not shadow_cache then return 0 end
    local head = shadow_cache:get(BUFFER_HEAD) or 0
    local tail = shadow_cache:get(BUFFER_TAIL) or 0
    return math.max(0, head - tail)
end

return _M
