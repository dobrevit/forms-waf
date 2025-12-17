-- api_handlers/bulk.lua
-- Bulk import/export handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local redis_sync = require "redis_sync"

-- Redis keys
local KEYS = {
    blocked_keywords = "waf:keywords:blocked",
    flagged_keywords = "waf:keywords:flagged",
    ip_whitelist = "waf:whitelist:ips",
    blocked_hashes = "waf:hashes:blocked",
}

-- Handlers table
_M.handlers = {}

-- GET /bulk/export/keywords - Export all keywords (blocked and flagged)
_M.handlers["GET:/bulk/export/keywords"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local blocked = red:smembers(KEYS.blocked_keywords) or {}
    local flagged = red:smembers(KEYS.flagged_keywords) or {}

    utils.close_redis(red)

    -- Convert to regular arrays if ngx.null
    if blocked == ngx.null then blocked = {} end
    if flagged == ngx.null then flagged = {} end

    return utils.json_response({
        blocked_keywords = blocked,
        flagged_keywords = flagged,
        export_timestamp = ngx.time(),
        counts = {
            blocked = #blocked,
            flagged = #flagged,
        }
    })
end

-- POST /bulk/import/keywords - Import keywords (add to existing)
_M.handlers["POST:/bulk/import/keywords"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data, decode_err = cjson.decode(body)

    if not data then
        return utils.error_response("Invalid JSON: " .. (decode_err or "unknown error"))
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local stats = {
        blocked_added = 0,
        blocked_skipped = 0,
        flagged_added = 0,
        flagged_skipped = 0,
    }

    -- Import blocked keywords
    if data.blocked_keywords and type(data.blocked_keywords) == "table" then
        for _, kw in ipairs(data.blocked_keywords) do
            if type(kw) == "string" and kw ~= "" then
                local added = red:sadd(KEYS.blocked_keywords, kw:lower())
                if added == 1 then
                    stats.blocked_added = stats.blocked_added + 1
                else
                    stats.blocked_skipped = stats.blocked_skipped + 1
                end
            end
        end
    end

    -- Import flagged keywords
    if data.flagged_keywords and type(data.flagged_keywords) == "table" then
        for _, kw in ipairs(data.flagged_keywords) do
            if type(kw) == "string" and kw ~= "" then
                local added = red:sadd(KEYS.flagged_keywords, kw:lower())
                if added == 1 then
                    stats.flagged_added = stats.flagged_added + 1
                else
                    stats.flagged_skipped = stats.flagged_skipped + 1
                end
            end
        end
    end

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        success = true,
        stats = stats,
    })
end

-- GET /bulk/export/ips - Export allowlisted IPs
_M.handlers["GET:/bulk/export/ips"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local ips = red:smembers(KEYS.ip_whitelist) or {}

    utils.close_redis(red)

    if ips == ngx.null then ips = {} end

    return utils.json_response({
        whitelisted_ips = ips,
        export_timestamp = ngx.time(),
        count = #ips,
    })
end

-- POST /bulk/import/ips - Import allowlisted IPs
_M.handlers["POST:/bulk/import/ips"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data, decode_err = cjson.decode(body)

    if not data then
        return utils.error_response("Invalid JSON: " .. (decode_err or "unknown error"))
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local stats = {
        added = 0,
        skipped = 0,
        invalid = 0,
    }

    -- Import IPs
    if data.whitelisted_ips and type(data.whitelisted_ips) == "table" then
        for _, ip in ipairs(data.whitelisted_ips) do
            if type(ip) == "string" and ip ~= "" then
                -- Basic IP validation
                if ip:match("^%d+%.%d+%.%d+%.%d+$") or ip:match("^%d+%.%d+%.%d+%.%d+/%d+$") or ip:match(":") then
                    local added = red:sadd(KEYS.ip_whitelist, ip)
                    if added == 1 then
                        stats.added = stats.added + 1
                    else
                        stats.skipped = stats.skipped + 1
                    end
                else
                    stats.invalid = stats.invalid + 1
                end
            end
        end
    end

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        success = true,
        stats = stats,
    })
end

-- GET /bulk/export/hashes - Export blocked hashes
_M.handlers["GET:/bulk/export/hashes"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local hashes = red:smembers(KEYS.blocked_hashes) or {}

    utils.close_redis(red)

    if hashes == ngx.null then hashes = {} end

    return utils.json_response({
        blocked_hashes = hashes,
        export_timestamp = ngx.time(),
        count = #hashes,
    })
end

-- POST /bulk/import/hashes - Import blocked hashes
_M.handlers["POST:/bulk/import/hashes"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data, decode_err = cjson.decode(body)

    if not data then
        return utils.error_response("Invalid JSON: " .. (decode_err or "unknown error"))
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local stats = {
        added = 0,
        skipped = 0,
        invalid = 0,
    }

    -- Import hashes
    if data.blocked_hashes and type(data.blocked_hashes) == "table" then
        for _, hash in ipairs(data.blocked_hashes) do
            if type(hash) == "string" and hash ~= "" then
                -- Basic hash validation (should be hex string)
                if hash:match("^[a-fA-F0-9]+$") and #hash >= 16 then
                    local added = red:sadd(KEYS.blocked_hashes, hash:lower())
                    if added == 1 then
                        stats.added = stats.added + 1
                    else
                        stats.skipped = stats.skipped + 1
                    end
                else
                    stats.invalid = stats.invalid + 1
                end
            end
        end
    end

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        success = true,
        stats = stats,
    })
end

-- DELETE /bulk/clear/keywords - Clear all keywords (with confirmation)
_M.handlers["DELETE:/bulk/clear/keywords"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    -- Require explicit confirmation
    if not data or data.confirm ~= true then
        return utils.error_response("Bulk clear requires 'confirm: true' in request body")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local blocked_count = red:scard(KEYS.blocked_keywords) or 0
    local flagged_count = red:scard(KEYS.flagged_keywords) or 0

    red:del(KEYS.blocked_keywords)
    red:del(KEYS.flagged_keywords)

    utils.close_redis(red)

    -- Trigger sync
    redis_sync.sync_now()

    return utils.json_response({
        success = true,
        cleared = {
            blocked_keywords = blocked_count,
            flagged_keywords = flagged_count,
        }
    })
end

-- GET /bulk/export/all - Export everything (keywords, IPs, hashes)
_M.handlers["GET:/bulk/export/all"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local blocked_keywords = red:smembers(KEYS.blocked_keywords) or {}
    local flagged_keywords = red:smembers(KEYS.flagged_keywords) or {}
    local whitelisted_ips = red:smembers(KEYS.ip_whitelist) or {}
    local blocked_hashes = red:smembers(KEYS.blocked_hashes) or {}

    utils.close_redis(red)

    -- Convert ngx.null to empty arrays
    if blocked_keywords == ngx.null then blocked_keywords = {} end
    if flagged_keywords == ngx.null then flagged_keywords = {} end
    if whitelisted_ips == ngx.null then whitelisted_ips = {} end
    if blocked_hashes == ngx.null then blocked_hashes = {} end

    return utils.json_response({
        export_version = "1.0",
        export_timestamp = ngx.time(),
        data = {
            blocked_keywords = blocked_keywords,
            flagged_keywords = flagged_keywords,
            whitelisted_ips = whitelisted_ips,
            blocked_hashes = blocked_hashes,
        },
        counts = {
            blocked_keywords = #blocked_keywords,
            flagged_keywords = #flagged_keywords,
            whitelisted_ips = #whitelisted_ips,
            blocked_hashes = #blocked_hashes,
        }
    })
end

return _M
