-- behavioral_tracker.lua
-- ML-based behavioral tracking for form submission pattern analysis
-- Tracks submission counts, fill durations, and detects anomalies against baselines

local _M = {}

local cjson = require "cjson.safe"

-- Bucket types and their TTLs in seconds
local BUCKET_TTLS = {
    hour = 90 * 24 * 60 * 60,     -- 90 days
    day = 365 * 24 * 60 * 60,     -- 1 year
    week = 2 * 365 * 24 * 60 * 60, -- 2 years
    month = 5 * 365 * 24 * 60 * 60, -- 5 years
    year = 10 * 365 * 24 * 60 * 60  -- 10 years
}

-- Duration histogram buckets (in seconds)
local DURATION_BUCKETS = {
    {min = 0, max = 2, label = "0-2"},
    {min = 2, max = 5, label = "2-5"},
    {min = 5, max = 10, label = "5-10"},
    {min = 10, max = 30, label = "10-30"},
    {min = 30, max = 60, label = "30-60"},
    {min = 60, max = 120, label = "60-120"},
    {min = 120, max = 300, label = "120-300"},
    {min = 300, max = math.huge, label = "300+"}
}

-- Get duration bucket label for a given duration
local function get_duration_bucket(duration)
    for _, bucket in ipairs(DURATION_BUCKETS) do
        if duration >= bucket.min and duration < bucket.max then
            return bucket.label
        end
    end
    return "300+"
end

-- Get current time bucket IDs
local function get_bucket_ids(timestamp)
    timestamp = timestamp or ngx.time()
    local date = os.date("!*t", timestamp)

    return {
        hour = string.format("%04d%02d%02d%02d", date.year, date.month, date.day, date.hour),
        day = string.format("%04d%02d%02d", date.year, date.month, date.day),
        week = string.format("%04dW%02d", date.year, math.ceil((date.yday) / 7)),
        month = string.format("%04d%02d", date.year, date.month),
        year = string.format("%04d", date.year)
    }
end

-- Get TTL for a bucket type
function _M.get_bucket_ttl(bucket_type)
    return BUCKET_TTLS[bucket_type] or BUCKET_TTLS.hour
end

-- Build Redis key for submission counts
local function build_counts_key(vhost_id, flow_name, bucket_type, bucket_id)
    return string.format("waf:behavioral:%s:%s:counts:%s:%s",
        vhost_id, flow_name, bucket_type, bucket_id)
end

-- Build Redis key for duration histogram
local function build_duration_key(vhost_id, flow_name, bucket_type, bucket_id)
    return string.format("waf:behavioral:%s:%s:duration:%s:%s",
        vhost_id, flow_name, bucket_type, bucket_id)
end

-- Build Redis key for unique IPs (HyperLogLog)
local function build_ips_key(vhost_id, flow_name, bucket_type, bucket_id)
    return string.format("waf:behavioral:%s:%s:ips:%s:%s",
        vhost_id, flow_name, bucket_type, bucket_id)
end

-- Build Redis key for baseline data
local function build_baseline_key(vhost_id, flow_name)
    return string.format("waf:behavioral:%s:%s:baseline", vhost_id, flow_name)
end

-- Check if a path matches using the specified match mode
-- @param path: The request path to check
-- @param patterns: Array of patterns to match against
-- @param match_mode: "exact", "prefix", or "regex"
local function path_matches(path, patterns, match_mode)
    if not path or not patterns then
        return false
    end

    match_mode = match_mode or "prefix"

    for _, pattern in ipairs(patterns) do
        if match_mode == "exact" then
            if path == pattern then
                return true
            end
        elseif match_mode == "prefix" then
            -- Support glob-style wildcards: /blog/* matches /blog/anything
            if pattern:find("%*") then
                local prefix = pattern:gsub("%*$", "")
                if path:sub(1, #prefix) == prefix then
                    return true
                end
            elseif path == pattern or path:sub(1, #pattern + 1) == pattern .. "/" then
                return true
            end
        elseif match_mode == "regex" then
            local ok, match = pcall(ngx.re.match, path, pattern, "jo")
            if ok and match then
                return true
            end
        end
    end

    return false
end

-- Check if method matches
-- @param method: The request method (GET, POST, etc.)
-- @param allowed_methods: Array of allowed methods, or nil for any
local function method_matches(method, allowed_methods)
    if not allowed_methods or #allowed_methods == 0 then
        return true  -- No restriction
    end

    method = method:upper()
    for _, m in ipairs(allowed_methods) do
        if m:upper() == method then
            return true
        end
    end

    return false
end

-- Match request to a flow configuration
-- @param flows: Array of flow configurations
-- @param path: Request path
-- @param method: Request method
-- @param is_start: true if checking start paths, false for end paths
-- @return: flow config if matched, nil otherwise
function _M.match_flow(flows, path, method, is_start)
    if not flows or not path then
        return nil
    end

    for _, flow in ipairs(flows) do
        local paths, methods

        if is_start then
            paths = flow.start_paths
            methods = flow.start_methods
        else
            paths = flow.end_paths
            methods = flow.end_methods
        end

        if path_matches(path, paths, flow.path_match_mode) and
           method_matches(method, methods) then
            return flow
        end
    end

    return nil
end

-- Record a form submission
-- @param context: Table with vhost_id, flow_name, vhost_config
-- @param fill_duration: Time in seconds from start to submission
-- @param spam_score: The spam score for this submission
-- @param action: "allowed", "blocked", or "monitored"
-- @param client_ip: Client IP address for unique IP tracking
function _M.record_submission(context, fill_duration, spam_score, action, client_ip)
    if not context or not context.vhost_id or not context.flow_name then
        return false, "missing context"
    end

    local vhost_config = context.vhost_config
    if not vhost_config or not vhost_config.behavioral then
        return false, "behavioral tracking not configured"
    end

    local behavioral = vhost_config.behavioral
    if not behavioral.enabled then
        return false, "behavioral tracking disabled"
    end

    local tracking = behavioral.tracking or {}
    local bucket_ids = get_bucket_ids()

    -- Get Redis connection
    local redis_sync = require "redis_sync"
    local red = redis_sync.get_connection()
    if not red then
        ngx.log(ngx.WARN, "behavioral_tracker: no Redis connection")
        return false, "no Redis connection"
    end

    local vhost_id = context.vhost_id
    local flow_name = context.flow_name

    -- Record data for each bucket type
    for bucket_type, bucket_id in pairs(bucket_ids) do
        local ttl = _M.get_bucket_ttl(bucket_type)

        -- Record submission counts
        if tracking.submission_counts ~= false then
            local counts_key = build_counts_key(vhost_id, flow_name, bucket_type, bucket_id)

            red:hincrby(counts_key, "submissions", 1)
            red:hincrby(counts_key, action or "allowed", 1)

            -- Track spam score sum and count for average calculation
            if tracking.avg_spam_score ~= false and spam_score then
                red:hincrby(counts_key, "spam_score_sum", math.floor(spam_score))
                red:hincrby(counts_key, "spam_score_count", 1)
            end

            red:expire(counts_key, ttl)
        end

        -- Record fill duration histogram
        if tracking.fill_duration ~= false and fill_duration then
            local duration_key = build_duration_key(vhost_id, flow_name, bucket_type, bucket_id)
            local bucket_label = get_duration_bucket(fill_duration)

            red:zincrby(duration_key, 1, bucket_label)
            red:expire(duration_key, ttl)
        end

        -- Record unique IPs using HyperLogLog
        if tracking.unique_ips ~= false and client_ip then
            local ips_key = build_ips_key(vhost_id, flow_name, bucket_type, bucket_id)

            red:pfadd(ips_key, client_ip)
            red:expire(ips_key, ttl)
        end
    end

    -- Update vhost/flow index for cleanup and enumeration
    red:sadd("waf:behavioral:index:vhosts", vhost_id)
    red:sadd("waf:behavioral:index:" .. vhost_id .. ":flows", flow_name)

    redis_sync.release_connection(red)

    return true
end

-- Check current submission rate against baseline for anomaly detection
-- @param context: Table with vhost_id, flow_name, vhost_config
-- @return: Table with score (number), flags (array), details (table)
function _M.check_anomaly(context)
    local result = {
        score = 0,
        flags = {},
        details = {}
    }

    if not context or not context.vhost_id or not context.flow_name then
        return result
    end

    local vhost_config = context.vhost_config
    if not vhost_config or not vhost_config.behavioral then
        return result
    end

    local behavioral = vhost_config.behavioral
    if not behavioral.enabled then
        return result
    end

    local anomaly_config = behavioral.anomaly_detection
    if not anomaly_config or not anomaly_config.enabled then
        return result
    end

    local redis_sync = require "redis_sync"
    local red = redis_sync.get_connection()
    if not red then
        return result
    end

    local vhost_id = context.vhost_id
    local flow_name = context.flow_name

    -- Get baseline data
    local baseline_key = build_baseline_key(vhost_id, flow_name)
    local baseline = red:hgetall(baseline_key)

    if not baseline or #baseline == 0 then
        redis_sync.release_connection(red)
        result.details.reason = "no_baseline"
        return result
    end

    -- Convert array to hash table
    local baseline_data = {}
    for i = 1, #baseline, 2 do
        baseline_data[baseline[i]] = baseline[i + 1]
    end

    -- Check if learning is complete
    if baseline_data.learning_complete ~= "1" then
        redis_sync.release_connection(red)
        result.details.reason = "learning_in_progress"
        return result
    end

    -- Get current hour's submission count
    local bucket_ids = get_bucket_ids()
    local current_hour_key = build_counts_key(vhost_id, flow_name, "hour", bucket_ids.hour)
    local current_submissions = tonumber(red:hget(current_hour_key, "submissions")) or 0

    redis_sync.release_connection(red)

    -- Calculate z-score
    local hourly_avg = tonumber(baseline_data.hourly_avg_submissions) or 0
    local hourly_std = tonumber(baseline_data.hourly_std_dev_submissions) or 0

    if hourly_std > 0 then
        local z_score = (current_submissions - hourly_avg) / hourly_std
        result.details.z_score = z_score
        result.details.current_submissions = current_submissions
        result.details.baseline_avg = hourly_avg
        result.details.baseline_std = hourly_std

        local threshold = tonumber(anomaly_config.std_dev_threshold) or 2.0

        if z_score > threshold then
            table.insert(result.flags, "behavioral:high_rate")
            result.details.anomaly_detected = true

            -- Apply score if action is "score"
            if anomaly_config.action == "score" then
                result.score = tonumber(anomaly_config.score_addition) or 15
            end
        end
    end

    return result
end

-- Calculate baselines from historical data
-- Should be called periodically (e.g., hourly) by a background timer
-- @param red: Redis connection
-- @param vhost_id: Virtual host ID
-- @param flow_name: Flow name
-- @param config: Baselines configuration from vhost config
function _M.calculate_baselines(red, vhost_id, flow_name, config)
    if not red or not vhost_id or not flow_name then
        return false, "missing parameters"
    end

    config = config or {}
    local learning_period_days = tonumber(config.learning_period_days) or 14
    local min_samples = tonumber(config.min_samples) or 100

    -- Get hourly bucket keys for the learning period
    local now = ngx.time()
    local learning_start = now - (learning_period_days * 24 * 60 * 60)

    local submissions = {}
    local total_samples = 0

    -- Iterate through hours in the learning period
    for timestamp = learning_start, now - 3600, 3600 do
        local bucket_ids = get_bucket_ids(timestamp)
        local counts_key = build_counts_key(vhost_id, flow_name, "hour", bucket_ids.hour)

        local count = red:hget(counts_key, "submissions")
        if count then
            count = tonumber(count) or 0
            table.insert(submissions, count)
            total_samples = total_samples + 1
        end
    end

    if total_samples < min_samples then
        -- Not enough data yet
        local baseline_key = build_baseline_key(vhost_id, flow_name)
        red:hset(baseline_key, "learning_complete", "0")
        red:hset(baseline_key, "samples_collected", tostring(total_samples))
        red:hset(baseline_key, "min_samples_needed", tostring(min_samples))
        red:hset(baseline_key, "last_updated", tostring(now))
        return false, "insufficient samples"
    end

    -- Calculate mean
    local sum = 0
    for _, count in ipairs(submissions) do
        sum = sum + count
    end
    local mean = sum / #submissions

    -- Calculate standard deviation
    local variance_sum = 0
    for _, count in ipairs(submissions) do
        variance_sum = variance_sum + (count - mean) ^ 2
    end
    local std_dev = math.sqrt(variance_sum / #submissions)

    -- Calculate percentiles (sort submissions first)
    table.sort(submissions)
    local p50_idx = math.floor(#submissions * 0.50)
    local p90_idx = math.floor(#submissions * 0.90)
    local p99_idx = math.floor(#submissions * 0.99)

    local p50 = submissions[p50_idx] or 0
    local p90 = submissions[p90_idx] or 0
    local p99 = submissions[p99_idx] or 0

    -- Store baseline data
    local baseline_key = build_baseline_key(vhost_id, flow_name)
    red:hmset(baseline_key,
        "learning_complete", "1",
        "hourly_avg_submissions", string.format("%.2f", mean),
        "hourly_std_dev_submissions", string.format("%.2f", std_dev),
        "hourly_p50_submissions", tostring(p50),
        "hourly_p90_submissions", tostring(p90),
        "hourly_p99_submissions", tostring(p99),
        "samples_used", tostring(total_samples),
        "learning_period_days", tostring(learning_period_days),
        "last_updated", tostring(now)
    )

    ngx.log(ngx.INFO, string.format(
        "behavioral_tracker: calculated baseline for %s:%s - avg=%.2f, std=%.2f, samples=%d",
        vhost_id, flow_name, mean, std_dev, total_samples
    ))

    return true
end

-- Get historical stats for a vhost/flow
-- @param vhost_id: Virtual host ID
-- @param flow_name: Flow name (optional, returns all flows if nil)
-- @param bucket_type: "hour", "day", "week", "month", or "year"
-- @param count: Number of buckets to retrieve
-- @return: Array of stats objects
function _M.get_stats(vhost_id, flow_name, bucket_type, count)
    bucket_type = bucket_type or "hour"
    count = count or 24

    local redis_sync = require "redis_sync"
    local red = redis_sync.get_connection()
    if not red then
        return nil, "no Redis connection"
    end

    local stats = {}
    local now = ngx.time()

    -- Calculate time step based on bucket type
    local step
    if bucket_type == "hour" then
        step = 3600
    elseif bucket_type == "day" then
        step = 86400
    elseif bucket_type == "week" then
        step = 7 * 86400
    elseif bucket_type == "month" then
        step = 30 * 86400
    else
        step = 365 * 86400
    end

    for i = 0, count - 1 do
        local timestamp = now - (i * step)
        local bucket_ids = get_bucket_ids(timestamp)
        local bucket_id = bucket_ids[bucket_type]

        local counts_key = build_counts_key(vhost_id, flow_name, bucket_type, bucket_id)
        local duration_key = build_duration_key(vhost_id, flow_name, bucket_type, bucket_id)
        local ips_key = build_ips_key(vhost_id, flow_name, bucket_type, bucket_id)

        -- Get counts
        local counts = red:hgetall(counts_key)
        local counts_data = {}
        if counts and #counts > 0 then
            for j = 1, #counts, 2 do
                counts_data[counts[j]] = tonumber(counts[j + 1]) or 0
            end
        end

        -- Get duration histogram
        local durations = red:zrange(duration_key, 0, -1, "WITHSCORES")
        local duration_data = {}
        if durations and #durations > 0 then
            for j = 1, #durations, 2 do
                duration_data[durations[j]] = tonumber(durations[j + 1]) or 0
            end
        end

        -- Get unique IP count
        local unique_ips = red:pfcount(ips_key)

        table.insert(stats, {
            bucket_id = bucket_id,
            timestamp = timestamp,
            submissions = counts_data.submissions or 0,
            allowed = counts_data.allowed or 0,
            blocked = counts_data.blocked or 0,
            monitored = counts_data.monitored or 0,
            avg_spam_score = counts_data.spam_score_count and counts_data.spam_score_count > 0
                and (counts_data.spam_score_sum / counts_data.spam_score_count) or 0,
            duration_histogram = duration_data,
            unique_ips = unique_ips or 0
        })
    end

    redis_sync.release_connection(red)

    return stats
end

-- Get baseline data for a vhost/flow
-- @param vhost_id: Virtual host ID
-- @param flow_name: Flow name
-- @return: Baseline data table
function _M.get_baseline(vhost_id, flow_name)
    local redis_sync = require "redis_sync"
    local red = redis_sync.get_connection()
    if not red then
        return nil, "no Redis connection"
    end

    local baseline_key = build_baseline_key(vhost_id, flow_name)
    local data = red:hgetall(baseline_key)

    redis_sync.release_connection(red)

    if not data or #data == 0 then
        return nil, "no baseline data"
    end

    -- Convert array to hash table
    local result = {}
    for i = 1, #data, 2 do
        local key = data[i]
        local value = data[i + 1]
        -- Convert numeric fields
        if key:match("^hourly_") or key:match("samples") or key:match("period") then
            result[key] = tonumber(value) or value
        elseif key == "learning_complete" then
            result[key] = value == "1"
        else
            result[key] = value
        end
    end

    return result
end

-- Get all configured flows for a vhost
-- @param vhost_id: Virtual host ID
-- @return: Array of flow names
function _M.get_flows(vhost_id)
    local redis_sync = require "redis_sync"
    local red = redis_sync.get_connection()
    if not red then
        return nil, "no Redis connection"
    end

    local flows = red:smembers("waf:behavioral:index:" .. vhost_id .. ":flows")

    redis_sync.release_connection(red)

    return flows or {}
end

-- Get all vhosts with behavioral tracking
-- @return: Array of vhost IDs
function _M.get_tracked_vhosts()
    local redis_sync = require "redis_sync"
    local red = redis_sync.get_connection()
    if not red then
        return nil, "no Redis connection"
    end

    local vhosts = red:smembers("waf:behavioral:index:vhosts")

    redis_sync.release_connection(red)

    return vhosts or {}
end

-- Force recalculation of baselines for a vhost/flow
-- @param vhost_id: Virtual host ID
-- @param flow_name: Flow name (optional, recalculates all flows if nil)
-- @param config: Baselines configuration
function _M.recalculate_baselines(vhost_id, flow_name, config)
    local redis_sync = require "redis_sync"
    local red = redis_sync.get_connection()
    if not red then
        return false, "no Redis connection"
    end

    local results = {}

    if flow_name then
        -- Recalculate single flow
        local ok, err = _M.calculate_baselines(red, vhost_id, flow_name, config)
        results[flow_name] = {success = ok, error = err}
    else
        -- Recalculate all flows for vhost
        local flows = red:smembers("waf:behavioral:index:" .. vhost_id .. ":flows")
        if flows then
            for _, fn in ipairs(flows) do
                local ok, err = _M.calculate_baselines(red, vhost_id, fn, config)
                results[fn] = {success = ok, error = err}
            end
        end
    end

    redis_sync.release_connection(red)

    return results
end

return _M
