-- api_handlers/shadow.lua
-- Shadow mode: what monitoring mode would have blocked, and promoting a scope
-- to blocking once you can see it.

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"

local KEYS = {
    decisions = "waf:shadow:decisions",
    rules     = "waf:shadow:rules",
    flags     = "waf:shadow:flags",
    endpoints = "waf:shadow:endpoints",
    stats     = "waf:shadow:stats",
}

local DEFAULT_LIMIT = 100
local MAX_LIMIT = 500

-- An empty Lua table encodes as a JSON object. The UI treats these as arrays and
-- calls .map on them, so force array encoding (same defect as the Slack handler).
local function as_array(t)
    if type(t) ~= "table" then
        return setmetatable({}, cjson.array_mt)
    end
    return setmetatable(t, cjson.array_mt)
end

local function redis_hash_to_table(raw)
    local out = {}
    if type(raw) ~= "table" then return out end
    for i = 1, #raw, 2 do
        out[raw[i]] = tonumber(raw[i + 1]) or 0
    end
    return out
end

--- Sort a name->count map into a descending array, capped.
local function top_n(counts, limit)
    local list = {}
    for name, count in pairs(counts) do
        table.insert(list, { name = name, count = count })
    end
    table.sort(list, function(a, b)
        if a.count == b.count then return a.name < b.name end
        return a.count > b.count
    end)
    while #list > (limit or 10) do table.remove(list) end
    return as_array(list)
end

local function query_arg(name, default)
    local args = ngx.req.get_uri_args()
    local value = args[name]
    if type(value) == "table" then value = value[1] end
    if value == nil or value == "" then return default end
    return value
end

--- Decode the stored decision list, optionally narrowed to one scope.
local function read_decisions(red, vhost_id, endpoint_id, limit)
    local raw = red:lrange(KEYS.decisions, 0, MAX_LIMIT - 1)
    local out = {}
    if type(raw) ~= "table" then return out end

    for _, entry in ipairs(raw) do
        local decision = cjson.decode(entry)
        if decision then
            local matches = true
            if vhost_id and decision.vhost_id ~= vhost_id then matches = false end
            if endpoint_id and decision.endpoint_id ~= endpoint_id then matches = false end
            if matches then
                table.insert(out, decision)
                if #out >= limit then break end
            end
        end
    end
    return out
end

_M.handlers = {}

-- GET /shadow/summary - what monitoring mode has withheld so far
_M.handlers["GET:/shadow/summary"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end

    local stats = redis_hash_to_table(red:hgetall(KEYS.stats))
    local rules = redis_hash_to_table(red:hgetall(KEYS.rules))
    local flags = redis_hash_to_table(red:hgetall(KEYS.flags))
    local endpoints = redis_hash_to_table(red:hgetall(KEYS.endpoints))
    local retained = red:llen(KEYS.decisions)
    utils.close_redis(red)

    -- Split the "vhost|endpoint" aggregate key back into its parts so the UI does
    -- not have to know the encoding.
    local scopes = {}
    for scope, count in pairs(endpoints) do
        local vhost_id, endpoint_id = scope:match("^(.-)|(.*)$")
        table.insert(scopes, {
            vhost_id = vhost_id or scope,
            endpoint_id = endpoint_id or "global",
            would_block_count = count,
        })
    end
    table.sort(scopes, function(a, b) return a.would_block_count > b.would_block_count end)

    return utils.json_response({
        would_block_total = stats.would_block_total or 0,
        -- Non-zero means the buffer overflowed and the sample is incomplete. The
        -- UI must say so rather than presenting the counts as exhaustive.
        dropped_total = stats.dropped_total or 0,
        retained_decisions = tonumber(retained) or 0,
        top_rules = top_n(rules, 10),
        -- The actionable breakdown: which detections drove the would-blocks.
        top_flags = top_n(flags, 15),
        scopes = as_array(scopes),
    })
end

-- GET /shadow/decisions - the individual records behind the summary
_M.handlers["GET:/shadow/decisions"] = function()
    local limit = math.min(tonumber(query_arg("limit", DEFAULT_LIMIT)) or DEFAULT_LIMIT, MAX_LIMIT)
    local vhost_id = query_arg("vhost_id")
    local endpoint_id = query_arg("endpoint_id")

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end
    local decisions = read_decisions(red, vhost_id, endpoint_id, limit)
    utils.close_redis(red)

    return utils.json_response({
        decisions = as_array(decisions),
        count = #decisions,
        limit = limit,
    })
end

-- GET /shadow/impact - the pre-flight answer to "what happens if I promote this?"
_M.handlers["GET:/shadow/impact"] = function()
    local vhost_id = query_arg("vhost_id")
    if not vhost_id then
        return utils.error_response("vhost_id is required")
    end
    local endpoint_id = query_arg("endpoint_id")

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end

    local decisions = read_decisions(red, vhost_id, endpoint_id, MAX_LIMIT)
    local stats = redis_hash_to_table(red:hgetall(KEYS.stats))
    utils.close_redis(red)

    local rules, flags, ips, endpoints_hit = {}, {}, {}, {}
    local score_total, oldest, newest = 0, nil, nil
    for _, d in ipairs(decisions) do
        for _, rule in ipairs(d.blocked_by or {}) do
            rules[rule] = (rules[rule] or 0) + 1
        end
        for _, flag in ipairs(d.flags or {}) do
            flags[flag] = (flags[flag] or 0) + 1
        end
        if d.client_ip then ips[d.client_ip] = true end
        local ep = d.endpoint_id or "global"
        endpoints_hit[ep] = (endpoints_hit[ep] or 0) + 1
        score_total = score_total + (d.score or 0)
        if not oldest or (d.ts or 0) < oldest then oldest = d.ts end
        if not newest or (d.ts or 0) > newest then newest = d.ts end
    end

    local unique_ips = 0
    for _ in pairs(ips) do unique_ips = unique_ips + 1 end

    return utils.json_response({
        vhost_id = vhost_id,
        endpoint_id = endpoint_id,
        -- What promoting this scope would have blocked, over the retained window.
        would_block_count = #decisions,
        unique_client_ips = unique_ips,
        average_score = (#decisions > 0) and math.floor(score_total / #decisions) or 0,
        window_start = oldest,
        window_end = newest,
        top_rules = top_n(rules, 10),
        top_flags = top_n(flags, 15),
        affected_endpoints = top_n(endpoints_hit, 20),
        -- Carried through so the caller cannot mistake a truncated sample for the
        -- full picture when deciding to promote.
        sample_incomplete = (stats.dropped_total or 0) > 0,
        dropped_total = stats.dropped_total or 0,
    })
end

-- POST /shadow/promote - switch a vhost from monitoring to blocking
_M.handlers["POST:/shadow/promote"] = function()
    local data, err = utils.get_json_body()
    if not data then
        return utils.error_response(err or "Invalid JSON")
    end
    local ok, verr = utils.validate_required(data, { "vhost_id" })
    if not ok then
        return utils.error_response(verr)
    end

    local red, rerr = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (rerr or "unknown"))
    end

    local key = "waf:vhosts:config:" .. data.vhost_id
    local raw = red:get(key)
    if not raw or raw == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Virtual host not found: " .. data.vhost_id, 404)
    end

    local config = cjson.decode(raw)
    if not config then
        utils.close_redis(red)
        return utils.error_response("Stored vhost configuration is not valid JSON", 500)
    end

    config.waf = config.waf or {}
    local previous_mode = config.waf.mode
    if previous_mode == "blocking" then
        utils.close_redis(red)
        return utils.json_response({
            promoted = false,
            vhost_id = data.vhost_id,
            mode = "blocking",
            message = "Already in blocking mode; nothing to do",
        })
    end

    config.waf.mode = "blocking"
    local saved, serr = red:set(key, cjson.encode(config))
    utils.close_redis(red)
    if not saved then
        return utils.error_response("Failed to save configuration: " .. (serr or "unknown"))
    end

    redis_sync.sync_now()

    ngx.log(ngx.WARN, string.format(
        "SHADOW PROMOTE: vhost=%s mode %s -> blocking by user=%s",
        data.vhost_id, tostring(previous_mode),
        (ngx.ctx.admin_user and ngx.ctx.admin_user.username) or "unknown"))

    return utils.json_response({
        promoted = true,
        vhost_id = data.vhost_id,
        previous_mode = previous_mode,
        mode = "blocking",
    })
end

-- DELETE /shadow/decisions - reset the observation window
_M.handlers["DELETE:/shadow/decisions"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end
    red:del(KEYS.decisions, KEYS.rules, KEYS.flags, KEYS.endpoints, KEYS.stats)
    utils.close_redis(red)
    return utils.json_response({ cleared = true })
end

return _M
