-- api_handlers/suppressions.lua
-- Rule suppressions: "this detection does not count for this scope".
--
-- The counterpart to shadow mode. Shadow mode names the rule that would have
-- blocked; this is how an operator says that rule is wrong here, without
-- turning the whole endpoint off.

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"
local suppressions = require "suppressions"

local REDIS_KEY = "waf:suppressions"

local VALID_SCOPES = { global = true, vhost = true, endpoint = true }

-- An empty Lua table encodes as a JSON object; the UI calls .map on these.
local function as_array(t)
    if type(t) ~= "table" then
        return setmetatable({}, cjson.array_mt)
    end
    return setmetatable(t, cjson.array_mt)
end

--- A stable id from the scope and flag, so the same suppression added twice is
--- the same entry rather than a duplicate that has to be deleted twice.
local function suppression_id(scope_type, scope_id, flag)
    return ngx.md5(scope_type .. "|" .. (scope_id or "") .. "|" .. flag)
end

local function read_all(red)
    local raw, err = red:hgetall(REDIS_KEY)
    if not raw then return nil, err end

    local out = {}
    if type(raw) == "table" then
        for i = 1, #raw, 2 do
            local decoded = cjson.decode(raw[i + 1])
            if decoded then
                decoded.id = decoded.id or raw[i]
                out[#out + 1] = decoded
            end
        end
    end
    table.sort(out, function(a, b)
        return (a.created_at or 0) > (b.created_at or 0)
    end)
    return out
end

_M.handlers = {}

-- GET /suppressions - everything currently in force
_M.handlers["GET:/suppressions"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end

    local entries, read_err = read_all(red)
    utils.close_redis(red)
    if not entries then
        return utils.error_response("Failed to read suppressions: " .. (read_err or "unknown"))
    end

    return utils.json_response({
        suppressions = as_array(entries),
        count = #entries,
        max = suppressions.get_max(),
    })
end

-- POST /suppressions - stop a detection counting for one scope
_M.handlers["POST:/suppressions"] = function()
    local body, err = utils.get_json_body()
    if not body then
        return utils.error_response(err or "Invalid JSON body", 400)
    end

    local valid, missing = utils.validate_required(body, { "flag" })
    if not valid then
        return utils.error_response("Missing required field: " .. missing, 400)
    end

    local flag = tostring(body.flag)
    if #flag == 0 or #flag > 120 then
        return utils.error_response("flag must be 1-120 characters", 400)
    end

    local scope_type = body.scope_type or "global"
    if not VALID_SCOPES[scope_type] then
        return utils.error_response("scope_type must be one of: global, vhost, endpoint", 400)
    end

    local scope_id = body.scope_id
    if scope_type ~= "global" then
        if not scope_id or scope_id == "" then
            return utils.error_response("scope_id is required when scope_type is " .. scope_type, 400)
        end
        scope_id = tostring(scope_id)
    else
        scope_id = nil
    end

    -- A bare "*" would suppress every detection everywhere, which is a WAF that
    -- is on but does nothing -- the failure mode this feature must not enable by
    -- a single typo. Turning the vhost off is the honest way to express that.
    if flag == "*" and scope_type == "global" then
        return utils.error_response(
            "Refusing a global '*' suppression: that disables all detection. " ..
            "Scope it to a vhost or endpoint, or set the vhost mode to passthrough.", 400)
    end

    local red, conn_err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (conn_err or "unknown"))
    end

    local existing = read_all(red)
    local id = suppression_id(scope_type, scope_id, flag)
    local already = false
    for _, entry in ipairs(existing or {}) do
        if entry.id == id then already = true break end
    end

    -- Bounded: this list is walked on every defense node of every request.
    if not already and existing and #existing >= suppressions.get_max() then
        utils.close_redis(red)
        return utils.error_response(
            "Suppression limit reached (" .. suppressions.get_max() .. "). " ..
            "Delete unused entries, or use a trailing '*' to cover a family in one rule.", 400)
    end

    local entry = {
        id = id,
        scope_type = scope_type,
        scope_id = scope_id,
        flag = flag,
        reason = body.reason and tostring(body.reason):sub(1, 500) or nil,
        created_at = ngx.time(),
        created_by = ngx.ctx.admin_user and ngx.ctx.admin_user.username or "unknown",
    }

    local encoded = cjson.encode(entry)
    local ok, set_err = red:hset(REDIS_KEY, id, encoded)
    utils.close_redis(red)
    if not ok then
        return utils.error_response("Failed to store suppression: " .. (set_err or "unknown"))
    end

    -- Push it to this pod's workers now; other pods pick it up on their timer.
    redis_sync.sync_now()

    ngx.log(ngx.WARN, "SUPPRESSION_ADDED: flag=", flag, " scope=", scope_type,
            ":", tostring(scope_id), " by=", entry.created_by)

    return utils.json_response({
        suppression = entry,
        created = not already,
    }, already and 200 or 201)
end

-- DELETE /suppressions - remove every suppression at once
_M.handlers["DELETE:/suppressions"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end

    red:del(REDIS_KEY)
    utils.close_redis(red)
    redis_sync.sync_now()

    ngx.log(ngx.WARN, "SUPPRESSIONS_CLEARED by=",
            ngx.ctx.admin_user and ngx.ctx.admin_user.username or "unknown")

    return utils.json_response({ cleared = true })
end

-- Parametric: DELETE /suppressions/{id}
_M.resource_handlers = {}

_M.resource_handlers["DELETE"] = function(id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. (err or "unknown"))
    end

    local removed = red:hdel(REDIS_KEY, id)
    utils.close_redis(red)

    if not removed or removed == 0 then
        return utils.error_response("Suppression not found: " .. tostring(id), 404)
    end

    redis_sync.sync_now()
    ngx.log(ngx.WARN, "SUPPRESSION_REMOVED: id=", id, " by=",
            ngx.ctx.admin_user and ngx.ctx.admin_user.username or "unknown")

    return utils.json_response({ deleted = true, id = id })
end

return _M
