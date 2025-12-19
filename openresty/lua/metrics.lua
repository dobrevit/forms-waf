-- metrics.lua
-- Prometheus metrics exporter with per-vhost and per-endpoint counters

local _M = {}

-- Shared dictionaries
local keyword_cache = ngx.shared.keyword_cache
local hash_cache = ngx.shared.hash_cache
local rate_limit = ngx.shared.rate_limit
local waf_metrics = ngx.shared.waf_metrics

-- Metric key prefixes
local PREFIX = {
    requests_total = "req_total:",
    requests_blocked = "req_blocked:",
    requests_monitored = "req_monitored:",
    requests_allowed = "req_allowed:",
    requests_skipped = "req_skipped:",
    spam_score_sum = "spam_score:",
    form_submissions = "form_sub:",
    validation_errors = "val_err:",
}

-- Build metric key with labels
local function build_key(prefix, vhost_id, endpoint_id)
    vhost_id = vhost_id or "_default"
    endpoint_id = endpoint_id or "_global"
    return prefix .. vhost_id .. ":" .. endpoint_id
end

-- Increment a counter
function _M.incr(metric, vhost_id, endpoint_id, value)
    if not waf_metrics then
        return
    end

    local key = build_key(PREFIX[metric] or metric, vhost_id, endpoint_id)
    local new_val, err = waf_metrics:incr(key, value or 1, 0)
    if not new_val and err then
        ngx.log(ngx.DEBUG, "metrics incr failed: ", err)
    end
end

-- Record a request with its outcome
function _M.record_request(vhost_id, endpoint_id, action, spam_score)
    if not waf_metrics then
        return
    end

    -- Always increment total
    _M.incr("requests_total", vhost_id, endpoint_id)

    -- Increment action-specific counter
    if action == "blocked" then
        _M.incr("requests_blocked", vhost_id, endpoint_id)
    elseif action == "monitored" then
        _M.incr("requests_monitored", vhost_id, endpoint_id)
    elseif action == "skipped" then
        _M.incr("requests_skipped", vhost_id, endpoint_id)
    else
        _M.incr("requests_allowed", vhost_id, endpoint_id)
    end

    -- Record spam score sum for average calculation
    if spam_score and spam_score > 0 then
        _M.incr("spam_score_sum", vhost_id, endpoint_id, spam_score)
    end
end

-- Record a form submission
function _M.record_form_submission(vhost_id, endpoint_id)
    _M.incr("form_submissions", vhost_id, endpoint_id)
end

-- Record a validation error
function _M.record_validation_error(vhost_id, endpoint_id)
    _M.incr("validation_errors", vhost_id, endpoint_id)
end

-- Get a counter value
function _M.get(metric, vhost_id, endpoint_id)
    if not waf_metrics then
        return 0
    end

    local key = build_key(PREFIX[metric] or metric, vhost_id, endpoint_id)
    return waf_metrics:get(key) or 0
end

-- Get all keys with a prefix
local function get_keys_with_prefix(prefix)
    if not waf_metrics then
        return {}
    end

    local keys = waf_metrics:get_keys(0)  -- 0 = get all keys
    local result = {}

    for _, key in ipairs(keys) do
        if key:sub(1, #prefix) == prefix then
            table.insert(result, key)
        end
    end

    return result
end

-- Parse metric key to extract labels
local function parse_key(key, prefix)
    -- Key format: prefix:vhost_id:endpoint_id
    local rest = key:sub(#prefix + 1)
    local vhost_id, endpoint_id = rest:match("^([^:]+):(.+)$")
    return vhost_id or "_default", endpoint_id or "_global"
end

-- Generate Prometheus format metrics
function _M.get_prometheus()
    local lines = {}

    -- Helper to add metric header
    local function add_header(name, help, type)
        table.insert(lines, "# HELP " .. name .. " " .. help)
        table.insert(lines, "# TYPE " .. name .. " " .. type)
    end

    -- Helper to add metric with labels
    local function add_metric_with_labels(name, value, labels)
        table.insert(lines, name .. "{" .. labels .. "} " .. tostring(value))
    end

    -- Helper to add simple metric
    local function add_metric(name, help, type, value, labels)
        add_header(name, help, type)
        if labels then
            add_metric_with_labels(name, value, labels)
        else
            table.insert(lines, name .. " " .. tostring(value))
        end
    end

    -- ========================================================================
    -- WAF Request Metrics (per vhost/endpoint)
    -- ========================================================================

    -- Requests total
    add_header("waf_requests_total", "Total number of requests processed", "counter")
    local total_keys = get_keys_with_prefix(PREFIX.requests_total)
    for _, key in ipairs(total_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_total)
        local value = waf_metrics:get(key) or 0
        add_metric_with_labels("waf_requests_total", value,
            'vhost="' .. vhost .. '",endpoint="' .. endpoint .. '"')
    end

    -- Requests blocked
    add_header("waf_requests_blocked_total", "Total number of blocked requests", "counter")
    local blocked_keys = get_keys_with_prefix(PREFIX.requests_blocked)
    for _, key in ipairs(blocked_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_blocked)
        local value = waf_metrics:get(key) or 0
        add_metric_with_labels("waf_requests_blocked_total", value,
            'vhost="' .. vhost .. '",endpoint="' .. endpoint .. '"')
    end

    -- Requests monitored (would have blocked)
    add_header("waf_requests_monitored_total", "Total number of monitored requests (would block)", "counter")
    local monitored_keys = get_keys_with_prefix(PREFIX.requests_monitored)
    for _, key in ipairs(monitored_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_monitored)
        local value = waf_metrics:get(key) or 0
        add_metric_with_labels("waf_requests_monitored_total", value,
            'vhost="' .. vhost .. '",endpoint="' .. endpoint .. '"')
    end

    -- Requests allowed
    add_header("waf_requests_allowed_total", "Total number of allowed requests", "counter")
    local allowed_keys = get_keys_with_prefix(PREFIX.requests_allowed)
    for _, key in ipairs(allowed_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_allowed)
        local value = waf_metrics:get(key) or 0
        add_metric_with_labels("waf_requests_allowed_total", value,
            'vhost="' .. vhost .. '",endpoint="' .. endpoint .. '"')
    end

    -- Requests skipped (WAF bypassed)
    add_header("waf_requests_skipped_total", "Total number of skipped requests (WAF bypassed)", "counter")
    local skipped_keys = get_keys_with_prefix(PREFIX.requests_skipped)
    for _, key in ipairs(skipped_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_skipped)
        local value = waf_metrics:get(key) or 0
        add_metric_with_labels("waf_requests_skipped_total", value,
            'vhost="' .. vhost .. '",endpoint="' .. endpoint .. '"')
    end

    -- Spam score sum (for calculating averages)
    add_header("waf_spam_score_total", "Sum of spam scores for average calculation", "counter")
    local score_keys = get_keys_with_prefix(PREFIX.spam_score_sum)
    for _, key in ipairs(score_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.spam_score_sum)
        local value = waf_metrics:get(key) or 0
        add_metric_with_labels("waf_spam_score_total", value,
            'vhost="' .. vhost .. '",endpoint="' .. endpoint .. '"')
    end

    -- Form submissions
    add_header("waf_form_submissions_total", "Total number of form submissions processed", "counter")
    local form_keys = get_keys_with_prefix(PREFIX.form_submissions)
    for _, key in ipairs(form_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.form_submissions)
        local value = waf_metrics:get(key) or 0
        add_metric_with_labels("waf_form_submissions_total", value,
            'vhost="' .. vhost .. '",endpoint="' .. endpoint .. '"')
    end

    -- Validation errors
    add_header("waf_validation_errors_total", "Total number of validation errors", "counter")
    local val_keys = get_keys_with_prefix(PREFIX.validation_errors)
    for _, key in ipairs(val_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.validation_errors)
        local value = waf_metrics:get(key) or 0
        add_metric_with_labels("waf_validation_errors_total", value,
            'vhost="' .. vhost .. '",endpoint="' .. endpoint .. '"')
    end

    -- ========================================================================
    -- Shared Dictionary Stats
    -- ========================================================================

    local function dict_stats(name, dict)
        if dict then
            local capacity = dict:capacity() or 0
            local free = dict:free_space() or 0
            local used = capacity - free

            add_metric(
                "waf_shared_dict_bytes",
                "Shared dictionary memory usage",
                "gauge",
                used,
                'dict="' .. name .. '"'
            )
            add_metric(
                "waf_shared_dict_capacity_bytes",
                "Shared dictionary capacity",
                "gauge",
                capacity,
                'dict="' .. name .. '"'
            )
        end
    end

    dict_stats("keyword_cache", keyword_cache)
    dict_stats("hash_cache", hash_cache)
    dict_stats("rate_limit", rate_limit)
    dict_stats("waf_metrics", waf_metrics)

    -- ========================================================================
    -- Worker Info
    -- ========================================================================

    add_metric(
        "waf_worker_id",
        "Current worker ID",
        "gauge",
        ngx.worker.id()
    )

    add_metric(
        "waf_worker_count",
        "Total worker count",
        "gauge",
        ngx.worker.count()
    )

    -- ========================================================================
    -- Connection Stats
    -- ========================================================================

    add_metric(
        "waf_connections_active",
        "Active connections",
        "gauge",
        ngx.var.connections_active or 0
    )

    add_metric(
        "waf_connections_reading",
        "Connections reading",
        "gauge",
        ngx.var.connections_reading or 0
    )

    add_metric(
        "waf_connections_writing",
        "Connections writing",
        "gauge",
        ngx.var.connections_writing or 0
    )

    add_metric(
        "waf_connections_waiting",
        "Connections waiting",
        "gauge",
        ngx.var.connections_waiting or 0
    )

    return table.concat(lines, "\n") .. "\n"
end

-- Get summary stats for admin API
function _M.get_summary()
    local summary = {
        total_requests = 0,
        blocked_requests = 0,
        monitored_requests = 0,
        allowed_requests = 0,
        skipped_requests = 0,
        form_submissions = 0,
        validation_errors = 0,
        by_vhost = {},
        by_endpoint = {}
    }

    if not waf_metrics then
        return summary
    end

    -- Aggregate totals
    local total_keys = get_keys_with_prefix(PREFIX.requests_total)
    for _, key in ipairs(total_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_total)
        local value = waf_metrics:get(key) or 0
        summary.total_requests = summary.total_requests + value

        -- Per-vhost aggregation
        if not summary.by_vhost[vhost] then
            summary.by_vhost[vhost] = { total = 0, blocked = 0, monitored = 0, allowed = 0 }
        end
        summary.by_vhost[vhost].total = summary.by_vhost[vhost].total + value

        -- Per-endpoint aggregation
        if not summary.by_endpoint[endpoint] then
            summary.by_endpoint[endpoint] = { total = 0, blocked = 0, monitored = 0, allowed = 0 }
        end
        summary.by_endpoint[endpoint].total = summary.by_endpoint[endpoint].total + value
    end

    -- Blocked
    local blocked_keys = get_keys_with_prefix(PREFIX.requests_blocked)
    for _, key in ipairs(blocked_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_blocked)
        local value = waf_metrics:get(key) or 0
        summary.blocked_requests = summary.blocked_requests + value

        if summary.by_vhost[vhost] then
            summary.by_vhost[vhost].blocked = summary.by_vhost[vhost].blocked + value
        end
        if summary.by_endpoint[endpoint] then
            summary.by_endpoint[endpoint].blocked = summary.by_endpoint[endpoint].blocked + value
        end
    end

    -- Monitored
    local monitored_keys = get_keys_with_prefix(PREFIX.requests_monitored)
    for _, key in ipairs(monitored_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_monitored)
        local value = waf_metrics:get(key) or 0
        summary.monitored_requests = summary.monitored_requests + value

        if summary.by_vhost[vhost] then
            summary.by_vhost[vhost].monitored = summary.by_vhost[vhost].monitored + value
        end
        if summary.by_endpoint[endpoint] then
            summary.by_endpoint[endpoint].monitored = summary.by_endpoint[endpoint].monitored + value
        end
    end

    -- Allowed
    local allowed_keys = get_keys_with_prefix(PREFIX.requests_allowed)
    for _, key in ipairs(allowed_keys) do
        local vhost, endpoint = parse_key(key, PREFIX.requests_allowed)
        local value = waf_metrics:get(key) or 0
        summary.allowed_requests = summary.allowed_requests + value

        if summary.by_vhost[vhost] then
            summary.by_vhost[vhost].allowed = summary.by_vhost[vhost].allowed + value
        end
        if summary.by_endpoint[endpoint] then
            summary.by_endpoint[endpoint].allowed = summary.by_endpoint[endpoint].allowed + value
        end
    end

    -- Skipped
    local skipped_keys = get_keys_with_prefix(PREFIX.requests_skipped)
    for _, key in ipairs(skipped_keys) do
        local value = waf_metrics:get(key) or 0
        summary.skipped_requests = summary.skipped_requests + value
    end

    -- Form submissions
    local form_keys = get_keys_with_prefix(PREFIX.form_submissions)
    for _, key in ipairs(form_keys) do
        local value = waf_metrics:get(key) or 0
        summary.form_submissions = summary.form_submissions + value
    end

    -- Validation errors
    local val_keys = get_keys_with_prefix(PREFIX.validation_errors)
    for _, key in ipairs(val_keys) do
        local value = waf_metrics:get(key) or 0
        summary.validation_errors = summary.validation_errors + value
    end

    return summary
end

-- Reset all metrics (for testing)
function _M.reset()
    if waf_metrics then
        waf_metrics:flush_all()
    end
end

-- ============================================================================
-- Cluster Metrics (Redis-based distributed metrics)
-- ============================================================================

-- Redis keys for cluster metrics
local METRICS_KEYS = {
    instance_prefix = "waf:metrics:instance:",
    instance_updated_suffix = ":updated",
    global = "waf:metrics:global",
    global_updated = "waf:metrics:global:updated",
}

-- TTL for instance metrics (should be > STALE_THRESHOLD to allow for cleanup)
local METRICS_TTL = 300  -- 5 minutes

-- Metric fields to sync
local SYNC_FIELDS = {
    "total_requests",
    "blocked_requests",
    "monitored_requests",
    "allowed_requests",
    "skipped_requests",
    "form_submissions",
    "validation_errors"
}

--- Push local metrics to Redis atomically using a transaction.
-- Called by the instance coordinator heartbeat timer every 30 seconds.
-- Uses MULTI/EXEC to ensure atomic write of metrics hash and TTL.
--
-- @param instance_id string The unique identifier for this instance (e.g., pod name)
-- @param red table An established resty.redis connection object
-- @return boolean True on success, false on failure
-- @return string|nil Error message on failure, nil on success
function _M.push_to_redis(instance_id, red)
    if not red or not instance_id then
        return false, "invalid arguments: instance_id and redis connection required"
    end

    local summary = _M.get_summary()
    local metrics_key = METRICS_KEYS.instance_prefix .. instance_id
    local updated_key = metrics_key .. METRICS_KEYS.instance_updated_suffix
    local now = ngx.time()

    -- Build HMSET arguments
    local args = {}
    for _, field in ipairs(SYNC_FIELDS) do
        table.insert(args, field)
        table.insert(args, tostring(summary[field] or 0))
    end

    -- Use MULTI/EXEC transaction to ensure atomicity
    -- This prevents orphaned keys if the process crashes mid-operation
    local ok, err = red:multi()
    if not ok then
        ngx.log(ngx.WARN, "metrics: failed to start transaction: ", err)
        return false, err
    end

    -- Queue all commands in the transaction
    red:hmset(metrics_key, unpack(args))
    red:expire(metrics_key, METRICS_TTL)
    red:setex(updated_key, METRICS_TTL, tostring(now))

    -- Execute transaction
    local results, err = red:exec()
    if not results then
        ngx.log(ngx.WARN, "metrics: transaction failed: ", err)
        red:discard()  -- Clean up on error
        return false, err
    end

    ngx.log(ngx.DEBUG, "metrics: pushed metrics for instance '", instance_id, "'")
    return true
end

--- Cleanup metrics for a removed instance.
-- Called by the instance coordinator when removing stale instances.
--
-- @param red table An established resty.redis connection object
-- @param instance_id string The unique identifier of the instance to clean up
-- @return boolean True on success, false on failure
-- @return string|nil Error message on failure, nil on success
function _M.cleanup_instance_metrics(red, instance_id)
    if not red or not instance_id then
        return false, "invalid arguments: redis connection and instance_id required"
    end

    local metrics_key = METRICS_KEYS.instance_prefix .. instance_id
    local updated_key = metrics_key .. METRICS_KEYS.instance_updated_suffix

    -- Delete metrics hash and updated key
    red:del(metrics_key)
    red:del(updated_key)

    ngx.log(ngx.INFO, "metrics: cleaned up metrics for instance '", instance_id, "'")
    return true
end

--- Aggregate metrics from all instances with metrics in Redis (leader only).
-- Scans Redis for all waf:metrics:instance:* keys to include metrics from
-- instances that may have recently restarted or been removed but whose
-- metrics haven't expired yet. Uses Redis pipelining for efficiency.
--
-- @param red table An established resty.redis connection object
-- @param active_instances table Array of active instance objects (used for instance_count display)
-- @return boolean True on success, false on failure
-- @return number|string On success: count of metrics sources aggregated; on failure: error message
function _M.aggregate_global_metrics(red, active_instances)
    if not red then
        return false, "no redis connection"
    end

    -- Scan Redis for all instance metrics keys
    -- This ensures we include metrics from instances that:
    -- 1. Recently restarted (old metrics still have TTL)
    -- 2. Were removed from cluster but metrics haven't expired
    local metrics_keys = {}
    local cursor = "0"
    local scan_pattern = METRICS_KEYS.instance_prefix .. "*"

    repeat
        local res, err = red:scan(cursor, "MATCH", scan_pattern, "COUNT", 100)
        if not res then
            ngx.log(ngx.WARN, "metrics: scan failed: ", err)
            return false, err
        end
        cursor = res[1]
        local keys = res[2]
        for _, key in ipairs(keys) do
            -- Skip the :updated timestamp keys, only get the metrics hashes
            if not key:match(":updated$") then
                table.insert(metrics_keys, key)
            end
        end
    until cursor == "0"

    local metrics_count = #metrics_keys

    if metrics_count == 0 then
        -- No metrics to aggregate - write zeros
        local args = {}
        for _, field in ipairs(SYNC_FIELDS) do
            table.insert(args, field)
            table.insert(args, "0")
        end
        table.insert(args, "instance_count")
        table.insert(args, "0")

        local ok, err = red:hmset(METRICS_KEYS.global, unpack(args))
        if not ok then
            ngx.log(ngx.WARN, "metrics: failed to write empty global metrics: ", err)
            return false, err
        end
        return true, 0
    end

    -- Initialize pipeline for batched HMGET commands
    red:init_pipeline()

    -- Queue HMGET for all found metrics keys
    for _, metrics_key in ipairs(metrics_keys) do
        red:hmget(metrics_key, unpack(SYNC_FIELDS))
    end

    -- Execute pipeline and get all results at once
    local results, err = red:commit_pipeline()
    if not results then
        ngx.log(ngx.WARN, "metrics: pipeline failed: ", err)
        return false, err
    end

    -- Initialize totals
    local totals = {}
    for _, field in ipairs(SYNC_FIELDS) do
        totals[field] = 0
    end

    -- Sum metrics from all pipeline results
    local sources_with_data = 0
    for _, values in ipairs(results) do
        if values and type(values) == "table" then
            local has_data = false
            for i, field in ipairs(SYNC_FIELDS) do
                local val = values[i]
                if val and val ~= ngx.null then
                    totals[field] = totals[field] + (tonumber(val) or 0)
                    has_data = true
                end
            end
            if has_data then
                sources_with_data = sources_with_data + 1
            end
        end
    end

    -- Use active_instances count for display (reflects healthy cluster state)
    -- but sources_with_data reflects actual metrics aggregated
    local display_count = #(active_instances or {})
    if display_count == 0 then
        display_count = sources_with_data
    end

    -- Write global metrics
    local args = {}
    for _, field in ipairs(SYNC_FIELDS) do
        table.insert(args, field)
        table.insert(args, tostring(totals[field]))
    end
    table.insert(args, "instance_count")
    table.insert(args, tostring(display_count))

    local ok, err = red:hmset(METRICS_KEYS.global, unpack(args))
    if not ok then
        ngx.log(ngx.WARN, "metrics: failed to write global metrics: ", err)
        return false, err
    end

    -- Update timestamp with error checking
    local now = ngx.time()
    ok, err = red:set(METRICS_KEYS.global_updated, tostring(now))
    if not ok then
        ngx.log(ngx.WARN, "metrics: failed to update global_updated timestamp: ", err)
        -- Don't return error here as the main metrics were written successfully
    end

    ngx.log(ngx.DEBUG, "metrics: aggregated global metrics from ", sources_with_data,
            " sources (", metrics_count, " keys scanned)")
    return true, sources_with_data
end

--- Get global metrics from Redis.
-- Returns aggregated metrics from all cluster instances.
--
-- @param red table An established resty.redis connection object
-- @return table|nil On success: table with metric fields and optional last_updated;
--                   on failure: nil
-- @return string|nil Error message on failure (distinguishes between errors and no data)
function _M.get_global_summary(red)
    if not red then
        return nil, "no redis connection"
    end

    -- Get all fields including instance_count
    local fields = {}
    for _, field in ipairs(SYNC_FIELDS) do
        table.insert(fields, field)
    end
    table.insert(fields, "instance_count")

    local values, err = red:hmget(METRICS_KEYS.global, unpack(fields))
    if not values then
        return nil, "redis error: " .. (err or "unknown")
    end

    if values == ngx.null then
        return nil, "no global metrics available"
    end

    -- Check if there's any data
    local has_data = false
    for _, v in ipairs(values) do
        if v and v ~= ngx.null then
            has_data = true
            break
        end
    end

    if not has_data then
        return nil, "no global metrics available"
    end

    -- Build result
    local result = {}
    for i, field in ipairs(fields) do
        local val = values[i]
        if val and val ~= ngx.null then
            result[field] = tonumber(val) or 0
        else
            result[field] = 0
        end
    end

    -- Get last updated timestamp (optional field)
    local updated, updated_err = red:get(METRICS_KEYS.global_updated)
    if updated and updated ~= ngx.null then
        result.last_updated = tonumber(updated)
    end
    -- Note: last_updated may be nil if timestamp key doesn't exist

    return result
end

return _M
