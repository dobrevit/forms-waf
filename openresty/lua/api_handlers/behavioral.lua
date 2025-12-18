-- api_handlers/behavioral.lua
-- Behavioral tracking and anomaly detection API handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local behavioral_tracker = require "behavioral_tracker"

-- Handlers table
_M.handlers = {}

-- GET /behavioral/stats - Get behavioral statistics
-- Query params: vhost_id (required), flow_name (required), bucket_type (optional, default: hour), count (optional, default: 24)
_M.handlers["GET:/behavioral/stats"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id
    local flow_name = args.flow_name
    local bucket_type = args.bucket_type or "hour"
    local count = tonumber(args.count) or 24

    if not vhost_id then
        return utils.error_response("vhost_id is required", 400)
    end

    if not flow_name then
        return utils.error_response("flow_name is required", 400)
    end

    -- Validate bucket_type
    local valid_bucket_types = {hour = true, day = true, week = true, month = true, year = true}
    if not valid_bucket_types[bucket_type] then
        return utils.error_response("Invalid bucket_type. Must be one of: hour, day, week, month, year", 400)
    end

    local stats, err = behavioral_tracker.get_stats(vhost_id, flow_name, bucket_type, count)
    if not stats then
        return utils.error_response("Failed to get stats: " .. (err or "unknown"), 500)
    end

    return utils.json_response({
        vhost_id = vhost_id,
        flow_name = flow_name,
        bucket_type = bucket_type,
        count = count,
        stats = stats
    })
end

-- GET /behavioral/baseline - Get baseline data for a flow
-- Query params: vhost_id (required), flow_name (required)
_M.handlers["GET:/behavioral/baseline"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id
    local flow_name = args.flow_name

    if not vhost_id then
        return utils.error_response("vhost_id is required", 400)
    end

    if not flow_name then
        return utils.error_response("flow_name is required", 400)
    end

    local baseline, err = behavioral_tracker.get_baseline(vhost_id, flow_name)
    if not baseline then
        return utils.json_response({
            vhost_id = vhost_id,
            flow_name = flow_name,
            baseline = nil,
            status = "no_data",
            message = err or "No baseline data available"
        })
    end

    return utils.json_response({
        vhost_id = vhost_id,
        flow_name = flow_name,
        baseline = baseline,
        status = baseline.learning_complete and "ready" or "learning"
    })
end

-- POST /behavioral/recalculate - Force baseline recalculation
-- Query params: vhost_id (required), flow_name (optional - recalculates all flows if not provided)
_M.handlers["POST:/behavioral/recalculate"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id
    local flow_name = args.flow_name  -- Optional

    if not vhost_id then
        return utils.error_response("vhost_id is required", 400)
    end

    -- Get vhost config for baselines settings
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    local vhost_config_json = red:get("waf:vhosts:config:" .. vhost_id)
    local baselines_config = {}
    if vhost_config_json and vhost_config_json ~= ngx.null then
        local vhost_config = cjson.decode(vhost_config_json)
        if vhost_config and vhost_config.behavioral then
            baselines_config = vhost_config.behavioral.baselines or {}
        end
    end
    utils.close_redis(red)

    local results = behavioral_tracker.recalculate_baselines(vhost_id, flow_name, baselines_config)

    return utils.json_response({
        vhost_id = vhost_id,
        flow_name = flow_name or "all",
        results = results
    })
end

-- GET /behavioral/flows - List all flows for a vhost
-- Query params: vhost_id (required)
_M.handlers["GET:/behavioral/flows"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id

    if not vhost_id then
        return utils.error_response("vhost_id is required", 400)
    end

    local flows = behavioral_tracker.get_flows(vhost_id)

    -- Get flow configurations from vhost config
    local red, err = utils.get_redis()
    if not red then
        return utils.json_response({
            vhost_id = vhost_id,
            flows = flows,
            configs = {}
        })
    end

    local vhost_config_json = red:get("waf:vhosts:config:" .. vhost_id)
    local flow_configs = {}
    if vhost_config_json and vhost_config_json ~= ngx.null then
        local vhost_config = cjson.decode(vhost_config_json)
        if vhost_config and vhost_config.behavioral and vhost_config.behavioral.flows then
            for _, flow in ipairs(vhost_config.behavioral.flows) do
                flow_configs[flow.name] = flow
            end
        end
    end
    utils.close_redis(red)

    return utils.json_response({
        vhost_id = vhost_id,
        flows = flows,
        configs = flow_configs
    })
end

-- GET /behavioral/vhosts - List all vhosts with behavioral tracking enabled
_M.handlers["GET:/behavioral/vhosts"] = function()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    -- Get all vhost IDs from index
    local vhost_ids = red:zrange("waf:vhosts:index", 0, -1)
    local behavioral_vhosts = {}

    if type(vhost_ids) == "table" then
        for _, vhost_id in ipairs(vhost_ids) do
            local config_json = red:get("waf:vhosts:config:" .. vhost_id)
            if config_json and config_json ~= ngx.null then
                local config = cjson.decode(config_json)
                if config and config.behavioral and config.behavioral.enabled then
                    local flow_names = {}
                    if config.behavioral.flows then
                        for _, flow in ipairs(config.behavioral.flows) do
                            table.insert(flow_names, flow.name)
                        end
                    end

                    table.insert(behavioral_vhosts, {
                        vhost_id = vhost_id,
                        name = config.name,
                        hostnames = config.hostnames,
                        flows = flow_names,
                        tracking = config.behavioral.tracking,
                        anomaly_detection = config.behavioral.anomaly_detection
                    })
                end
            end
        end
    end

    utils.close_redis(red)

    return utils.json_response({
        vhosts = behavioral_vhosts,
        total = #behavioral_vhosts
    })
end

-- GET /behavioral/summary - Get summary of behavioral tracking status
-- Query params: vhost_id (optional - returns all vhosts if not provided)
_M.handlers["GET:/behavioral/summary"] = function()
    local args = ngx.req.get_uri_args()
    local vhost_id = args.vhost_id

    local tracked_vhosts = behavioral_tracker.get_tracked_vhosts()
    local summary = {
        total_tracked_vhosts = #(tracked_vhosts or {}),
        vhosts = {}
    }

    -- Filter by vhost_id if provided
    local vhosts_to_process = {}
    if vhost_id then
        for _, v in ipairs(tracked_vhosts or {}) do
            if v == vhost_id then
                table.insert(vhosts_to_process, v)
                break
            end
        end
    else
        vhosts_to_process = tracked_vhosts or {}
    end

    for _, vid in ipairs(vhosts_to_process) do
        local flows = behavioral_tracker.get_flows(vid)
        local flow_summaries = {}

        for _, flow_name in ipairs(flows or {}) do
            local baseline = behavioral_tracker.get_baseline(vid, flow_name)
            local stats = behavioral_tracker.get_stats(vid, flow_name, "hour", 1)
            local latest_stats = stats and stats[1] or nil

            table.insert(flow_summaries, {
                name = flow_name,
                baseline_status = baseline and (baseline.learning_complete and "ready" or "learning") or "no_data",
                samples_collected = baseline and baseline.samples_used or 0,
                last_hour = latest_stats and {
                    submissions = latest_stats.submissions,
                    blocked = latest_stats.blocked,
                    allowed = latest_stats.allowed,
                    unique_ips = latest_stats.unique_ips,
                    avg_spam_score = latest_stats.avg_spam_score
                } or nil
            })
        end

        table.insert(summary.vhosts, {
            vhost_id = vid,
            flows = flow_summaries
        })
    end

    return utils.json_response(summary)
end

return _M
