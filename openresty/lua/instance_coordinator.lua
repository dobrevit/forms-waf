-- instance_coordinator.lua
-- OpenResty instance registration and leader election mechanism
--
-- Provides distributed coordination for multi-pod deployments:
-- - Instance registration with heartbeat
-- - Leader election using Redis SET NX PX
-- - Drift detection and stale instance cleanup
-- - Opt-in API for scheduled tasks requiring single-execution
--
-- Usage:
--   local coordinator = require "instance_coordinator"
--   coordinator.start_coordinator_timer()  -- Call in init_worker (worker 0 only)
--
--   -- Check if this instance is leader
--   if coordinator.is_leader() then
--       -- run singleton task
--   end
--
--   -- Or register a task to run only on leader
--   coordinator.register_for_leader_task("my_task", my_callback, 3600)

local _M = {}

local redis = require "resty.redis"
local cjson = require "cjson.safe"

-- Configuration from environment (following redis_sync.lua patterns)
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil
local REDIS_DB = tonumber(os.getenv("REDIS_DB")) or 0

-- Instance identification
local INSTANCE_ID = os.getenv("HOSTNAME") or ("unknown-" .. ngx.worker.pid())

-- Timing constants (in seconds)
local HEARTBEAT_INTERVAL = 15      -- How often to send heartbeat
local HEARTBEAT_TTL = 90           -- 6x heartbeat interval for tolerance
local LEADER_TTL = 30              -- Leader key TTL
local LEADER_RENEW_INTERVAL = 10   -- How often leader renews TTL
local DRIFT_THRESHOLD = 60         -- Mark as down after 1 minute without heartbeat
local STALE_THRESHOLD = 300        -- Remove after 5 minutes without heartbeat
local METRICS_PUSH_INTERVAL = 30   -- How often to push metrics to Redis

-- Redis keys
local KEYS = {
    instances = "waf:cluster:instances",
    heartbeat_prefix = "waf:cluster:instance:",
    heartbeat_suffix = ":heartbeat",
    leader = "waf:cluster:leader",
    leader_since = "waf:cluster:leader:since",
}

-- Module state
local coordinator_cache = nil  -- Set during initialization
local registered_tasks = {}    -- Tasks registered for leader-only execution
local is_initialized = false
local cached_leader = nil
local cached_leader_time = 0
local LEADER_CACHE_TTL = 5     -- Cache leader status for 5 seconds
local last_metrics_push = 0    -- Track when metrics were last pushed

-- ============================================================================
-- Redis Connection Helpers (following redis_sync.lua patterns)
-- ============================================================================

local function get_redis_connection()
    local red = redis:new()
    red:set_timeout(2000)  -- 2 second timeout

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        ngx.log(ngx.ERR, "instance_coordinator: failed to connect to Redis: ", err)
        return nil, err
    end

    if REDIS_PASSWORD and REDIS_PASSWORD ~= "" then
        local res, err = red:auth(REDIS_PASSWORD)
        if not res then
            red:close()
            ngx.log(ngx.ERR, "instance_coordinator: Redis auth failed: ", err)
            return nil, err
        end
    end

    if REDIS_DB and REDIS_DB > 0 then
        local res, err = red:select(REDIS_DB)
        if not res then
            red:close()
            ngx.log(ngx.ERR, "instance_coordinator: Redis select failed: ", err)
            return nil, err
        end
    end

    return red
end

local function close_redis(red)
    if not red then return end
    local ok, err = red:set_keepalive(10000, 100)
    if not ok then
        red:close()
    end
end

-- ============================================================================
-- Instance Identification
-- ============================================================================

function _M.get_instance_id()
    return INSTANCE_ID
end

-- ============================================================================
-- Instance Registration
-- ============================================================================

local function register_instance()
    local red, err = get_redis_connection()
    if not red then
        return false, err
    end

    local now = ngx.time()
    local metadata = cjson.encode({
        instance_id = INSTANCE_ID,
        started_at = now,
        last_heartbeat = now,
        status = "active",
        worker_count = ngx.worker.count()
    })

    -- Register in instances hash
    local ok, err = red:hset(KEYS.instances, INSTANCE_ID, metadata)
    if not ok then
        close_redis(red)
        ngx.log(ngx.ERR, "instance_coordinator: failed to register instance: ", err)
        return false, err
    end

    -- Set initial heartbeat with TTL
    local heartbeat_key = KEYS.heartbeat_prefix .. INSTANCE_ID .. KEYS.heartbeat_suffix
    ok, err = red:setex(heartbeat_key, HEARTBEAT_TTL, tostring(now))
    if not ok then
        close_redis(red)
        ngx.log(ngx.ERR, "instance_coordinator: failed to set heartbeat: ", err)
        return false, err
    end

    close_redis(red)
    ngx.log(ngx.INFO, "instance_coordinator: registered instance '", INSTANCE_ID, "'")
    return true
end

-- ============================================================================
-- Heartbeat
-- ============================================================================

local function send_heartbeat()
    local red, err = get_redis_connection()
    if not red then
        return false, err
    end

    local now = ngx.time()

    -- Update heartbeat key with TTL
    local heartbeat_key = KEYS.heartbeat_prefix .. INSTANCE_ID .. KEYS.heartbeat_suffix
    local ok, err = red:setex(heartbeat_key, HEARTBEAT_TTL, tostring(now))
    if not ok then
        close_redis(red)
        return false, err
    end

    -- Update last_heartbeat in instance metadata
    local metadata_json = red:hget(KEYS.instances, INSTANCE_ID)
    if metadata_json and metadata_json ~= ngx.null then
        local metadata = cjson.decode(metadata_json)
        if metadata then
            metadata.last_heartbeat = now
            metadata.status = "active"
            red:hset(KEYS.instances, INSTANCE_ID, cjson.encode(metadata))
        end
    end

    close_redis(red)
    return true
end

local function heartbeat_timer_handler(premature)
    if premature then
        return  -- nginx shutting down
    end

    -- Send heartbeat (no blocking retries - next interval will retry if needed)
    -- With 15s interval and 90s TTL, missing one heartbeat is not critical
    local ok, err = send_heartbeat()
    if not ok then
        ngx.log(ngx.WARN, "instance_coordinator: heartbeat failed: ", err)
    end

    -- Push metrics to Redis periodically (every METRICS_PUSH_INTERVAL seconds)
    local now = ngx.now()
    if now - last_metrics_push >= METRICS_PUSH_INTERVAL then
        -- Get Redis connection for metrics push
        local red, redis_err = get_redis_connection()
        if red then
            local metrics = require "metrics"
            local push_ok, push_err = metrics.push_to_redis(INSTANCE_ID, red)
            if push_ok then
                last_metrics_push = now
            else
                ngx.log(ngx.WARN, "instance_coordinator: metrics push failed: ", push_err)
            end
            close_redis(red)
        else
            ngx.log(ngx.WARN, "instance_coordinator: failed to connect to Redis for metrics: ", redis_err)
        end
    end

    -- Always reschedule
    local ok, err = ngx.timer.at(HEARTBEAT_INTERVAL, heartbeat_timer_handler)
    if not ok then
        ngx.log(ngx.ERR, "instance_coordinator: failed to reschedule heartbeat timer: ", err)
    end
end

-- ============================================================================
-- Leader Election
-- ============================================================================

local function try_acquire_leadership()
    local red, err = get_redis_connection()
    if not red then
        return false, err
    end

    -- Atomic: SET key value NX PX milliseconds
    -- NX = only set if not exists
    -- PX = expire in milliseconds
    local ok = red:set(KEYS.leader, INSTANCE_ID, "NX", "PX", LEADER_TTL * 1000)

    if ok == "OK" then
        -- Record when leadership was acquired (no TTL - deleted when leader key expires or released)
        red:set(KEYS.leader_since, ngx.time())
        close_redis(red)
        ngx.log(ngx.INFO, "instance_coordinator: instance '", INSTANCE_ID, "' acquired leadership")
        -- Update cache
        cached_leader = INSTANCE_ID
        cached_leader_time = ngx.time()
        return true
    end

    close_redis(red)
    return false
end

local function renew_leadership()
    local red, err = get_redis_connection()
    if not red then
        return false, err
    end

    -- Only renew if we are still the leader
    local current_leader = red:get(KEYS.leader)
    -- Handle ngx.null (key doesn't exist) - normalize to nil
    if current_leader == ngx.null then
        current_leader = nil
    end
    if current_leader ~= INSTANCE_ID then
        close_redis(red)
        -- Update cache - we lost leadership
        cached_leader = current_leader
        cached_leader_time = ngx.time()
        return false, "not leader"
    end

    -- Extend TTL
    -- EXPIRE returns 1 if successful, 0 if key doesn't exist (expired between GET and EXPIRE)
    local result, err = red:expire(KEYS.leader, LEADER_TTL)
    close_redis(red)

    if not result then
        return false, err
    end

    -- Check if EXPIRE actually succeeded (key still existed)
    if result == 0 then
        -- Key expired between GET and EXPIRE - we lost leadership
        cached_leader = nil
        cached_leader_time = ngx.time()
        return false, "leader key expired during renewal"
    end

    return true
end

function _M.is_leader()
    -- Quick check from cache first
    local now = ngx.time()
    if cached_leader and (now - cached_leader_time) < LEADER_CACHE_TTL then
        return cached_leader == INSTANCE_ID
    end

    -- Fetch from Redis
    local red, err = get_redis_connection()
    if not red then
        return false
    end

    local leader = red:get(KEYS.leader)
    close_redis(red)

    -- Update cache
    if leader and leader ~= ngx.null then
        cached_leader = leader
        cached_leader_time = now
        return leader == INSTANCE_ID
    end

    cached_leader = nil
    cached_leader_time = now
    return false
end

function _M.get_current_leader()
    local red, err = get_redis_connection()
    if not red then
        return nil, err
    end

    local leader = red:get(KEYS.leader)
    close_redis(red)

    if leader and leader ~= ngx.null then
        return leader
    end

    return nil
end

-- ============================================================================
-- Health Monitoring (Leader-only)
-- ============================================================================

local function check_instance_health()
    local red, err = get_redis_connection()
    if not red then
        return nil, err
    end

    local now = ngx.time()
    local instances = red:hgetall(KEYS.instances)

    if not instances or instances == ngx.null then
        close_redis(red)
        return {}
    end

    local results = {}
    local stale_instances = {}

    -- Process key-value pairs from hgetall
    for i = 1, #instances, 2 do
        local instance_id = instances[i]
        local metadata_json = instances[i + 1]
        local metadata = cjson.decode(metadata_json)

        if metadata then
            -- Check heartbeat key for actual last activity
            local heartbeat_key = KEYS.heartbeat_prefix .. instance_id .. KEYS.heartbeat_suffix
            local heartbeat_time = red:get(heartbeat_key)

            local last_seen = metadata.last_heartbeat or 0
            if heartbeat_time and heartbeat_time ~= ngx.null then
                last_seen = tonumber(heartbeat_time) or last_seen
            end

            local age = now - last_seen
            local status = "active"

            if age > STALE_THRESHOLD then
                status = "down"
                table.insert(stale_instances, instance_id)
            elseif age > DRIFT_THRESHOLD then
                status = "drifted"
                -- Update status in Redis
                metadata.status = "drifted"
                red:hset(KEYS.instances, instance_id, cjson.encode(metadata))
            end

            table.insert(results, {
                instance_id = instance_id,
                status = status,
                last_heartbeat = last_seen,
                age = age,
                started_at = metadata.started_at,
                worker_count = metadata.worker_count
            })
        end
    end

    -- Cleanup stale instances
    for _, instance_id in ipairs(stale_instances) do
        ngx.log(ngx.WARN, "instance_coordinator: removing stale instance '", instance_id, "'")
        red:hdel(KEYS.instances, instance_id)
        local heartbeat_key = KEYS.heartbeat_prefix .. instance_id .. KEYS.heartbeat_suffix
        red:del(heartbeat_key)
        -- Note: Don't cleanup metrics here - let TTL handle expiration
        -- This allows metrics to persist across instance restarts and be
        -- included in global aggregation until they naturally expire
    end

    close_redis(red)
    return results
end

-- ============================================================================
-- Leader Tasks
-- ============================================================================

function _M.register_for_leader_task(task_name, callback, interval, initial_delay)
    if not task_name or not callback or not interval then
        ngx.log(ngx.ERR, "instance_coordinator: invalid task registration")
        return false
    end

    registered_tasks[task_name] = {
        callback = callback,
        interval = interval,
        initial_delay = initial_delay or 0,
        last_run = 0,
        registered_at = ngx.time()
    }

    ngx.log(ngx.INFO, "instance_coordinator: registered leader task '", task_name,
            "' (interval: ", interval, "s)")
    return true
end

local function run_leader_tasks()
    local now = ngx.time()

    for task_name, task in pairs(registered_tasks) do
        local time_since_register = now - task.registered_at
        local time_since_run = now - task.last_run

        -- Check initial delay
        if time_since_register < task.initial_delay then
            goto continue
        end

        -- Check interval
        if task.last_run > 0 and time_since_run < task.interval then
            goto continue
        end

        -- Run the task
        ngx.log(ngx.INFO, "instance_coordinator: running leader task '", task_name, "'")
        local ok, err = pcall(task.callback)
        if not ok then
            ngx.log(ngx.ERR, "instance_coordinator: leader task '", task_name, "' failed: ", err)
        end
        task.last_run = now

        ::continue::
    end
end

-- ============================================================================
-- Leader Maintenance Timer
-- ============================================================================

local function leader_maintenance_handler(premature)
    if premature then
        return  -- nginx shutting down
    end

    -- Try to acquire or renew leadership
    local is_leader = _M.is_leader()

    if is_leader then
        -- Renew leadership TTL
        local ok, err = renew_leadership()
        if not ok then
            ngx.log(ngx.WARN, "instance_coordinator: failed to renew leadership: ", err)
            is_leader = false
        end
    else
        -- Try to acquire leadership if no leader exists
        local ok = try_acquire_leadership()
        is_leader = ok
    end

    -- Leader-only tasks
    if is_leader then
        -- Health check and cleanup
        local instances, err = check_instance_health()
        if instances then
            local active = 0
            local drifted = 0
            local active_instances = {}

            for _, inst in ipairs(instances) do
                if inst.status == "active" then
                    active = active + 1
                    table.insert(active_instances, inst)
                elseif inst.status == "drifted" then
                    drifted = drifted + 1
                end
            end

            if drifted > 0 then
                ngx.log(ngx.WARN, "instance_coordinator: cluster status - ",
                        active, " active, ", drifted, " drifted instances")
            end

            -- Aggregate metrics from all active instances
            local red, redis_err = get_redis_connection()
            if red then
                local metrics = require "metrics"
                local agg_ok, agg_err = metrics.aggregate_global_metrics(red, active_instances)
                if not agg_ok then
                    ngx.log(ngx.WARN, "instance_coordinator: metrics aggregation failed: ", agg_err)
                end
                close_redis(red)
            end
        end

        -- Run registered leader tasks
        run_leader_tasks()
    end

    -- Reschedule
    local ok, err = ngx.timer.at(LEADER_RENEW_INTERVAL, leader_maintenance_handler)
    if not ok then
        ngx.log(ngx.ERR, "instance_coordinator: failed to reschedule leader timer: ", err)
    end
end

-- ============================================================================
-- Cluster Status API
-- ============================================================================

function _M.get_all_instances()
    local red, err = get_redis_connection()
    if not red then
        return nil, err
    end

    local instances = red:hgetall(KEYS.instances)
    close_redis(red)

    if not instances or instances == ngx.null or #instances == 0 then
        -- Return empty array (not object) for proper JSON serialization
        return setmetatable({}, cjson.array_mt), nil, nil
    end

    local results = {}
    local now = ngx.time()
    local current_leader = _M.get_current_leader()

    for i = 1, #instances, 2 do
        local instance_id = instances[i]
        local metadata_json = instances[i + 1]
        local metadata = cjson.decode(metadata_json)

        if metadata then
            table.insert(results, {
                instance_id = instance_id,
                status = metadata.status or "unknown",
                is_leader = (instance_id == current_leader),
                started_at = metadata.started_at,
                last_heartbeat = metadata.last_heartbeat,
                worker_count = metadata.worker_count
            })
        end
    end

    -- Ensure array serialization even if results is empty after filtering
    if #results == 0 then
        return setmetatable({}, cjson.array_mt), nil, current_leader
    end

    -- Return both instances and current_leader to avoid redundant Redis calls
    return results, nil, current_leader
end

function _M.get_cluster_status()
    local instances, err = _M.get_all_instances()
    if not instances then
        return nil, err
    end

    local active = 0
    local drifted = 0
    local stale = 0
    local current_leader = _M.get_current_leader()

    -- Get leader_since timestamp
    local leader_since = nil
    if current_leader then
        local red, redis_err = get_redis_connection()
        if red then
            local since = red:get(KEYS.leader_since)
            if since and since ~= ngx.null then
                leader_since = tonumber(since)
            end
            close_redis(red)
        end
    end

    for _, inst in ipairs(instances) do
        if inst.status == "active" then
            active = active + 1
        elseif inst.status == "drifted" then
            drifted = drifted + 1
        elseif inst.status == "down" then
            stale = stale + 1
        end
    end

    return {
        cluster_healthy = (drifted == 0 and stale == 0 and current_leader ~= nil),
        instance_count = #instances,
        active_instances = active,
        drifted_instances = drifted,
        leader = current_leader and {
            instance_id = current_leader,
            since = leader_since
        } or nil,
        this_instance = {
            id = INSTANCE_ID,
            is_leader = _M.is_leader()
        }
    }
end

-- ============================================================================
-- Initialization
-- ============================================================================

function _M.start_coordinator_timer()
    -- Only worker 0 participates in coordination
    if ngx.worker.id() ~= 0 then
        ngx.log(ngx.DEBUG, "instance_coordinator: skipping on worker ", ngx.worker.id())
        return true
    end

    if is_initialized then
        ngx.log(ngx.WARN, "instance_coordinator: already initialized")
        return true
    end

    -- Get shared dict for caching
    coordinator_cache = ngx.shared.coordinator_cache
    if not coordinator_cache then
        ngx.log(ngx.WARN, "instance_coordinator: coordinator_cache shared dict not available, using config_cache")
        coordinator_cache = ngx.shared.config_cache
    end

    ngx.log(ngx.INFO, "instance_coordinator: initializing instance '", INSTANCE_ID, "'")

    -- Defer registration to timer (Redis not allowed directly in init_worker)
    local ok, err = ngx.timer.at(0, function()
        -- Register instance
        local ok, err = register_instance()
        if not ok then
            ngx.log(ngx.ERR, "instance_coordinator: failed to register: ", err)
        end

        -- Try to acquire leadership
        try_acquire_leadership()

        -- Start heartbeat timer
        local ok, err = ngx.timer.at(HEARTBEAT_INTERVAL, heartbeat_timer_handler)
        if not ok then
            ngx.log(ngx.ERR, "instance_coordinator: failed to start heartbeat timer: ", err)
        end

        -- Start leader maintenance timer
        ok, err = ngx.timer.at(LEADER_RENEW_INTERVAL, leader_maintenance_handler)
        if not ok then
            ngx.log(ngx.ERR, "instance_coordinator: failed to start leader timer: ", err)
        end
    end)

    if not ok then
        ngx.log(ngx.ERR, "instance_coordinator: failed to schedule initialization: ", err)
        return false, err
    end

    is_initialized = true
    return true
end

-- ============================================================================
-- Module Info
-- ============================================================================

function _M.get_config()
    return {
        instance_id = INSTANCE_ID,
        heartbeat_interval = HEARTBEAT_INTERVAL,
        heartbeat_ttl = HEARTBEAT_TTL,
        leader_ttl = LEADER_TTL,
        leader_renew_interval = LEADER_RENEW_INTERVAL,
        drift_threshold = DRIFT_THRESHOLD,
        stale_threshold = STALE_THRESHOLD,
        redis_host = REDIS_HOST,
        redis_port = REDIS_PORT
    }
end

return _M
