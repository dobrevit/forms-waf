--[[
    Decision buffer
    ===============
    Shared machinery for "record something in the request path, write it to Redis
    from a timer". Extracted from shadow_recorder when a second recorder needed
    the same thing, because what it holds is not boilerplate -- it is two
    concurrency defects that were each found the hard way:

      * redis_sync's timer runs on EVERY worker (24 on a typical box). Reading
        the tail, draining, then writing it back let every worker drain the same
        slots, turning one decision into one record per worker.

      * Claiming a range with incr(TAIL, pending) fixed the duplicates and
        introduced something worse. A second worker claiming the same `pending`
        pushed the tail past the head, into slots the writer had not filled yet.
        Those claims drained nothing, and every record written into the gap was
        skipped for good -- no duplicates, so the obvious test passed, while
        records were silently lost.

    A second hand-rolled copy of this would very likely reproduce one of them.

    The design that survives both: a single drainer holds an atomic add() lock,
    and the tail advances one slot at a time as each is written, so a drain that
    dies part-way resumes exactly where it stopped -- neither replaying a record
    nor losing one.

    Callers supply the Redis writes, which is the only part that differs between
    recorders.
]]

local cjson = require "cjson.safe"

local _M = {}

local Buffer = {}
Buffer.__index = Buffer

--- @param opts table
--   dict_name    name of the lua_shared_dict to buffer in (required)
--   prefix       key namespace within that dict (required)
--   max_buffered records held between flushes, beyond which new ones are dropped
--   slot_ttl     seconds a buffered record survives, so a stalled flush cannot
--                pin memory indefinitely
--   lock_ttl     seconds the drain lock survives a worker that dies outright
function _M.new(opts)
    assert(type(opts) == "table" and opts.dict_name and opts.prefix,
           "decision_buffer.new requires dict_name and prefix")

    return setmetatable({
        dict_name    = opts.dict_name,
        prefix       = opts.prefix,
        max_buffered = opts.max_buffered or 500,
        slot_ttl     = opts.slot_ttl or 600,
        lock_ttl     = opts.lock_ttl or 30,
        head_key     = opts.prefix .. ":head",
        tail_key     = opts.prefix .. ":tail",
        dropped_key  = opts.prefix .. ":dropped",
        lock_key     = opts.prefix .. ":draining",
        slot_prefix  = opts.prefix .. ":rec:",
    }, Buffer)
end

-- Resolved per call rather than at construction: the dict does not exist when a
-- module is required at init, only once nginx has set up shared memory.
function Buffer:dict()
    return ngx.shared[self.dict_name]
end

--- Buffer one record. Called from the request path, so it must stay
--- allocation-light and must never touch Redis.
-- @return true, or false plus a reason
function Buffer:record(entry)
    local dict = self:dict()
    if not dict or type(entry) ~= "table" then
        return false
    end

    local head = dict:incr(self.head_key, 1, 0)
    if not head then
        return false
    end

    local tail = dict:get(self.tail_key) or 0
    if head - tail > self.max_buffered then
        -- Drop the new record rather than evicting an older one, and count the
        -- loss so a consumer can say "showing a sample" instead of implying
        -- completeness.
        dict:incr(self.dropped_key, 1, 0)
        return false, "buffer full"
    end

    local encoded = cjson.encode(entry)
    if not encoded then
        return false
    end

    dict:set(self.slot_prefix .. head, encoded, self.slot_ttl)
    return true
end

--- Write one slot range. Called under the drain lock, and separated out so
--- flush() can run it under pcall and still release that lock.
local function drain_range(self, dict, red, from, to, write_record)
    local flushed = 0
    for slot = from, to do
        local key = self.slot_prefix .. slot
        local raw = dict:get(key)
        if raw then
            local decoded = cjson.decode(raw)
            if type(decoded) == "table" then
                write_record(red, decoded, raw)
                flushed = flushed + 1
            end
            dict:delete(key)
        end
        -- One slot at a time, not a jump at the end: this is what makes a
        -- failed drain resumable rather than lossy.
        dict:set(self.tail_key, slot)
    end
    return flushed
end

--- Drain into Redis. Timer context only.
-- @param red           an open Redis connection
-- @param write_record  function(red, decoded, raw) called per record
-- @return flushed count, dropped-since-last-flush count
function Buffer:flush(red, write_record)
    local dict = self:dict()
    if not dict or not red or type(write_record) ~= "function" then
        return 0, 0
    end

    local head = dict:get(self.head_key) or 0
    local tail = dict:get(self.tail_key) or 0
    if head <= tail then
        return 0, 0
    end

    -- add() is atomic and fails when the key already exists, so exactly one
    -- worker drains and the rest return immediately.
    if not dict:add(self.lock_key, 1, self.lock_ttl) then
        return 0, 0
    end

    local ok, flushed = pcall(drain_range, self, dict, red, tail + 1, head, write_record)
    if not ok then
        -- Release rather than leaving the buffer wedged until the lock TTL. The
        -- tail already advanced per completed slot, so the next drain resumes
        -- where this one stopped.
        dict:delete(self.lock_key)
        ngx.log(ngx.ERR, "decision_buffer(", self.prefix,
                ") flush failed, resuming from last completed slot: ", tostring(flushed))
        return 0, 0
    end

    local dropped = dict:get(self.dropped_key) or 0
    if dropped > 0 then
        dict:set(self.dropped_key, 0)
    end

    dict:delete(self.lock_key)
    return flushed, dropped
end

--- Records buffered but not yet written.
function Buffer:depth()
    local dict = self:dict()
    if not dict then return 0 end
    local head = dict:get(self.head_key) or 0
    local tail = dict:get(self.tail_key) or 0
    local depth = head - tail
    return depth > 0 and depth or 0
end

--- Trim a value that originates from the request, so a long or hostile field
--- cannot bloat storage. Shared because every recorder needs it.
function _M.clip(value, limit)
    if value == nil then return nil end
    value = tostring(value)
    if #value > limit then
        return value:sub(1, limit) .. "..."
    end
    return value
end

return _M
