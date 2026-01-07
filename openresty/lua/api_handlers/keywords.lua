-- api_handlers/keywords.lua
-- Blocked and flagged keywords handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"

-- Handlers table
_M.handlers = {}

-- ==================== Blocked Keywords ====================
-- Note: All keywords are stored in lowercase to enable case-insensitive matching
-- during request processing. This prevents duplicate entries (e.g., "Spam" vs "spam")
-- and ensures consistent lookup behavior across the system.

-- GET /keywords/blocked - List blocked keywords
_M.handlers["GET:/keywords/blocked"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local keywords = red:smembers("waf:keywords:blocked")
    utils.close_redis(red)

    return utils.json_response({keywords = keywords or {}})
end

-- POST /keywords/blocked - Add blocked keyword
_M.handlers["POST:/keywords/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return utils.error_response("Missing 'keyword' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:keywords:blocked", data.keyword:lower())
    utils.close_redis(red)

    -- Trigger immediate sync
    redis_sync.sync_now()

    return utils.json_response({added = added == 1, keyword = data.keyword:lower()})
end

-- DELETE /keywords/blocked - Remove blocked keyword
_M.handlers["DELETE:/keywords/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return utils.error_response("Missing 'keyword' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local removed = red:srem("waf:keywords:blocked", data.keyword:lower())
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({removed = removed == 1, keyword = data.keyword:lower()})
end

-- PUT /keywords/blocked - Edit blocked keyword (atomic rename)
_M.handlers["PUT:/keywords/blocked"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.old_keyword or not data.new_keyword then
        return utils.error_response("Missing 'old_keyword' or 'new_keyword' field")
    end

    local old_kw = data.old_keyword:lower()
    local new_kw = data.new_keyword:lower()

    if old_kw == new_kw then
        return utils.json_response({updated = false, reason = "keywords are identical"})
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if old keyword exists
    local exists = red:sismember("waf:keywords:blocked", old_kw)
    if exists ~= 1 then
        utils.close_redis(red)
        return utils.error_response("Keyword not found: " .. old_kw, 404)
    end

    -- Check if new keyword already exists
    local new_exists = red:sismember("waf:keywords:blocked", new_kw)
    if new_exists == 1 then
        utils.close_redis(red)
        return utils.error_response("Keyword already exists: " .. new_kw, 409)
    end

    -- Atomic transaction: add new first, then remove old
    -- If add fails, old keyword is preserved
    red:multi()
    red:sadd("waf:keywords:blocked", new_kw)
    red:srem("waf:keywords:blocked", old_kw)
    local results, err = red:exec()

    if not results then
        utils.close_redis(red)
        return utils.error_response("Transaction failed: " .. (err or "unknown"), 500)
    end

    utils.close_redis(red)
    redis_sync.sync_now()

    return utils.json_response({updated = true, old_keyword = old_kw, new_keyword = new_kw})
end

-- ==================== Flagged Keywords ====================

-- GET /keywords/flagged - List flagged keywords
_M.handlers["GET:/keywords/flagged"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local keywords = red:smembers("waf:keywords:flagged")
    utils.close_redis(red)

    return utils.json_response({keywords = keywords or {}})
end

-- POST /keywords/flagged - Add flagged keyword
_M.handlers["POST:/keywords/flagged"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return utils.error_response("Missing 'keyword' field")
    end

    local keyword_entry = data.keyword:lower()
    if data.score then
        keyword_entry = keyword_entry .. ":" .. tostring(data.score)
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local added = red:sadd("waf:keywords:flagged", keyword_entry)
    utils.close_redis(red)

    redis_sync.sync_now()

    return utils.json_response({added = added == 1, keyword = keyword_entry})
end

-- DELETE /keywords/flagged - Remove flagged keyword
_M.handlers["DELETE:/keywords/flagged"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.keyword then
        return utils.error_response("Missing 'keyword' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Flagged keywords may have score suffix, so we need to find and remove the matching entry
    local keyword_lower = data.keyword:lower()
    local members = red:smembers("waf:keywords:flagged")
    local removed = 0

    if members and type(members) == "table" then
        for _, member in ipairs(members) do
            -- Match keyword with or without score suffix
            local kw = member:match("^([^:]+)")
            if kw == keyword_lower or member == keyword_lower then
                local result = red:srem("waf:keywords:flagged", member)
                if result == 1 then
                    removed = removed + 1
                end
            end
        end
    end

    utils.close_redis(red)
    redis_sync.sync_now()

    return utils.json_response({removed = removed > 0, keyword = keyword_lower, count = removed})
end

-- PUT /keywords/flagged - Edit flagged keyword (atomic rename)
_M.handlers["PUT:/keywords/flagged"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data or not data.old_keyword then
        return utils.error_response("Missing 'old_keyword' field")
    end

    -- new_keyword or new_score (or both) must be provided
    if not data.new_keyword and data.new_score == nil then
        return utils.error_response("Missing 'new_keyword' or 'new_score' field")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Find the existing entry (keyword may have score suffix)
    local old_kw_lower = data.old_keyword:lower()
    local members = red:smembers("waf:keywords:flagged")
    local old_entry = nil
    local old_keyword_base = nil
    local old_score = nil

    if members and type(members) == "table" then
        for _, member in ipairs(members) do
            local kw, score = member:match("^([^:]+):?(%d*)$")
            if kw == old_kw_lower or member == old_kw_lower then
                old_entry = member
                old_keyword_base = kw
                old_score = score ~= "" and tonumber(score) or nil
                break
            end
        end
    end

    if not old_entry then
        utils.close_redis(red)
        return utils.error_response("Keyword not found: " .. old_kw_lower, 404)
    end

    -- Build new entry
    local new_keyword_base = data.new_keyword and data.new_keyword:lower() or old_keyword_base
    local new_score = data.new_score ~= nil and data.new_score or old_score

    local new_entry = new_keyword_base
    if new_score then
        new_entry = new_keyword_base .. ":" .. tostring(new_score)
    end

    -- If nothing changed, return early
    if old_entry == new_entry then
        utils.close_redis(red)
        return utils.json_response({updated = false, reason = "no changes detected"})
    end

    -- Check if new keyword already exists (only if keyword itself changed)
    if new_keyword_base ~= old_keyword_base then
        for _, member in ipairs(members) do
            local kw = member:match("^([^:]+)")
            if kw == new_keyword_base then
                utils.close_redis(red)
                return utils.error_response("Keyword already exists: " .. new_keyword_base, 409)
            end
        end
    end

    -- Atomic transaction: add new first, then remove old
    -- If add fails, old keyword is preserved
    red:multi()
    red:sadd("waf:keywords:flagged", new_entry)
    red:srem("waf:keywords:flagged", old_entry)
    local results, err = red:exec()

    if not results then
        utils.close_redis(red)
        return utils.error_response("Transaction failed: " .. (err or "unknown"), 500)
    end

    utils.close_redis(red)
    redis_sync.sync_now()

    return utils.json_response({
        updated = true,
        old_keyword = old_entry,
        new_keyword = new_entry
    })
end

return _M
