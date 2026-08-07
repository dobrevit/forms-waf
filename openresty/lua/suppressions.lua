--[[
    Rule suppression
    ================
    Shadow mode answers "what would blocking have rejected?". It names the rule
    responsible -- kw:viagra, fp_flag:suspicious-bot -- but naming it is only half
    an answer. Without a way to say "that one is wrong for this form", the
    operator's only choices are to promote and accept the false positives, or not
    to promote at all. That is the choice that stops WAFs being turned on.

    A suppression says: for this scope, this detection does not count.

    Applied at the node result
    --------------------------
    Every defense mechanism returns through execute_defense_node, so that is the
    single place this has to hook into. Suppressed flags are removed from the
    node's result; if a node's flags are *entirely* suppressed, the node is
    neutralised -- score zeroed, block cleared.

    The honest limitation: a mechanism reports one aggregate score for all its
    flags, so there is no per-flag score to subtract. Suppressing one of several
    flags on a node therefore removes the flag but leaves the score, and the
    remaining detections still stand on their own. That is the conservative
    direction -- a partially-suppressed node can still block, and cannot be used
    to silently defeat a rule that is also matching something else.

    Scope precedence is additive, not overriding. A global suppression, a vhost
    one and an endpoint one all apply to a request in that endpoint; the narrower
    scope adds to the broader rather than replacing it. Deep-merge semantics
    (as config_resolver uses) would let an endpoint entry silently drop the
    global ones, which is the wrong default for a safety control.
]]

local cjson = require "cjson.safe"

local _M = {}

local CACHE_KEY = "suppressions"

-- Bounded on purpose: this list is read on every defense node of every request.
local MAX_SUPPRESSIONS = 200

local function cache()
    return ngx.shared.suppression_cache
end

-- apply() runs on every defense node, so several times per request. Decoding the
-- same JSON blob each time is work with no new answer. Keyed on the raw string,
-- so a redis_sync write is picked up on the very next call rather than after a
-- TTL -- a stale suppression is either traffic wrongly blocked or wrongly
-- allowed, and neither should wait.
local _cached_raw, _cached_list

--- Every suppression currently in force, as stored by redis_sync.
-- @return array of {id, scope_type, scope_id, flag, reason, created_at, created_by}
function _M.get_all()
    local dict = cache()
    if not dict then return {} end

    local raw = dict:get(CACHE_KEY)
    if not raw then return {} end

    if raw == _cached_raw then
        return _cached_list
    end

    local decoded = cjson.decode(raw)
    if type(decoded) ~= "table" then return {} end

    _cached_raw, _cached_list = raw, decoded
    return decoded
end

--- Does `flag` match `pattern`?
-- Exact match, or a trailing `*` covering a whole family: `kw:*` suppresses
-- every keyword detection without needing one entry per word. Deliberately not
-- a Lua pattern -- an operator typing a rule name should not have to know that
-- `-` and `.` mean something, and a bad pattern here fails open.
function _M.matches(flag, pattern)
    if type(flag) ~= "string" or type(pattern) ~= "string" then return false end
    if pattern == flag then return true end

    local prefix = pattern:match("^(.-)%*$")
    if prefix then
        return prefix == "" or flag:sub(1, #prefix) == prefix
    end
    return false
end

--- Is this suppression in force for this scope?
local function applies_to_scope(entry, vhost_id, endpoint_id)
    local scope_type = entry.scope_type or "global"
    if scope_type == "global" then
        return true
    elseif scope_type == "vhost" then
        return entry.scope_id == vhost_id
    elseif scope_type == "endpoint" then
        return entry.scope_id == endpoint_id
    end
    return false
end

--- The flag patterns in force for one scope.
function _M.active_patterns(vhost_id, endpoint_id)
    local patterns = {}
    for _, entry in ipairs(_M.get_all()) do
        if entry.flag and applies_to_scope(entry, vhost_id, endpoint_id) then
            patterns[#patterns + 1] = entry.flag
        end
    end
    return patterns
end

--- Apply suppressions to one defense node's result.
-- @return result (mutated in place), the flags removed, and whether the node
--         lost its verdict entirely. The caller logs the third case louder: a
--         suppression that merely drops a flag is routine, one that turns a
--         block into a pass is the answer to "why did this get through?".
function _M.apply(result, vhost_id, endpoint_id)
    if type(result) ~= "table" then return result, nil, false end

    local original = result.flags
    if type(original) ~= "table" or #original == 0 then
        return result, nil, false
    end

    local patterns = _M.active_patterns(vhost_id, endpoint_id)
    if #patterns == 0 then
        return result, nil, false
    end

    local kept, removed = {}, {}
    for _, flag in ipairs(original) do
        local suppressed = false
        for _, pattern in ipairs(patterns) do
            if _M.matches(flag, pattern) then
                suppressed = true
                break
            end
        end
        if suppressed then
            removed[#removed + 1] = flag
        else
            kept[#kept + 1] = flag
        end
    end

    if #removed == 0 then
        return result, nil, false
    end

    result.flags = kept
    result.details = result.details or {}
    result.details.suppressed = removed

    -- Only a node whose every detection was suppressed loses its verdict. One
    -- surviving flag means something the operator did not suppress still fired,
    -- and that finding is left intact.
    local neutralised = false
    if #kept == 0 then
        neutralised = result.blocked or (result.score or 0) > 0
        result.score = 0
        result.blocked = false
        result.block_reason = nil
    end

    return result, removed, neutralised
end

function _M.get_cache_key()
    return CACHE_KEY
end

function _M.get_max()
    return MAX_SUPPRESSIONS
end

return _M
