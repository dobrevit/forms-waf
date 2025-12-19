-- api_handlers/system.lua
-- System status, metrics, sync, and learning handlers

local _M = {}

local utils = require "api_handlers.utils"
local redis_sync = require "redis_sync"
local waf_config = require "waf_config"
local metrics = require "metrics"
local field_learner = require "field_learner"

-- Handlers table
_M.handlers = {}

-- GET /status - Get WAF status
_M.handlers["GET:/status"] = function()
    local status = redis_sync.get_status()
    status.config = waf_config.get_all()
    return utils.json_response(status)
end

-- GET /metrics - Get WAF metrics summary (local and global)
_M.handlers["GET:/metrics"] = function()
    local summary = metrics.get_summary()

    -- Try to get global metrics from Redis
    local red, redis_err = utils.get_redis()
    if red then
        local global, global_err = metrics.get_global_summary(red)
        utils.close_redis(red)

        if global then
            -- Convert last_updated timestamp to ISO format (if present)
            if global.last_updated then
                global.last_updated = os.date("!%Y-%m-%dT%H:%M:%SZ", global.last_updated)
            end
            summary.global = global
        elseif global_err and not global_err:find("no global metrics") then
            -- Log actual errors (not just "no data available")
            ngx.log(ngx.WARN, "metrics: failed to get global summary: ", global_err)
        end
    end

    return utils.json_response(summary)
end

-- POST /metrics/reset - Reset all metrics (for testing)
_M.handlers["POST:/metrics/reset"] = function()
    metrics.reset()
    return utils.json_response({success = true, message = "Metrics reset"})
end

-- POST /sync - Force sync from Redis
_M.handlers["POST:/sync"] = function()
    redis_sync.sync_now()
    return utils.json_response({synced = true})
end

-- GET /learning/stats - Get learning statistics
_M.handlers["GET:/learning/stats"] = function()
    return utils.json_response({
        stats = field_learner.get_stats()
    })
end

return _M
