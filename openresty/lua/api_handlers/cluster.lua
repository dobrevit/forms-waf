-- api_handlers/cluster.lua
-- Cluster status, instances, and leader election handlers

local _M = {}

local utils = require "api_handlers.utils"
local instance_coordinator = require "instance_coordinator"

-- Handlers table
_M.handlers = {}

-- GET /cluster/status - Get cluster health status
_M.handlers["GET:/cluster/status"] = function()
    local status, err = instance_coordinator.get_cluster_status()
    if not status then
        return utils.error_response("Failed to get cluster status: " .. (err or "unknown"), 500)
    end
    return utils.json_response(status)
end

-- GET /cluster/instances - List all registered instances
_M.handlers["GET:/cluster/instances"] = function()
    local instances, err, current_leader = instance_coordinator.get_all_instances()
    if not instances then
        return utils.error_response("Failed to get instances: " .. (err or "unknown"), 500)
    end

    return utils.json_response({
        instances = instances,
        total = #instances,
        current_leader = current_leader
    })
end

-- GET /cluster/leader - Get current leader info
_M.handlers["GET:/cluster/leader"] = function()
    local leader = instance_coordinator.get_current_leader()
    local is_this_leader = instance_coordinator.is_leader()

    return utils.json_response({
        leader = leader,
        this_instance = {
            id = instance_coordinator.get_instance_id(),
            is_leader = is_this_leader
        }
    })
end

-- GET /cluster/config - Get coordinator configuration
_M.handlers["GET:/cluster/config"] = function()
    local config = instance_coordinator.get_config()
    return utils.json_response(config)
end

-- GET /cluster/this - Get info about this instance
_M.handlers["GET:/cluster/this"] = function()
    local config = instance_coordinator.get_config()
    local is_leader = instance_coordinator.is_leader()

    return utils.json_response({
        instance_id = config.instance_id,
        is_leader = is_leader,
        worker_id = ngx.worker.id(),
        worker_count = ngx.worker.count(),
        config = {
            heartbeat_interval = config.heartbeat_interval,
            leader_ttl = config.leader_ttl,
            drift_threshold = config.drift_threshold,
            stale_threshold = config.stale_threshold
        }
    })
end

return _M
