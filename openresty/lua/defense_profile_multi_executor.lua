-- defense_profile_multi_executor.lua
-- Multi-profile orchestration layer with parallel execution
-- Executes multiple defense profiles concurrently and aggregates results

local _M = {}

local cjson = require "cjson.safe"

-- Lazy-load dependencies to avoid circular requires
local _single_executor
local _profile_store
local _defense_line_executor

local function get_single_executor()
    if not _single_executor then
        _single_executor = require "defense_profile_executor"
    end
    return _single_executor
end

local function get_profile_store()
    if not _profile_store then
        _profile_store = require "defense_profiles_store"
    end
    return _profile_store
end

local function get_defense_line_executor()
    if not _defense_line_executor then
        _defense_line_executor = require "defense_line_executor"
    end
    return _defense_line_executor
end

-- Aggregation strategies for binary decisions (blocked/allowed)
local AGGREGATION_STRATEGIES = {
    -- Block if ANY profile blocks (default - safety first)
    OR = function(results)
        for _, r in ipairs(results) do
            if r.result.action == "block" then
                return true
            end
        end
        return false
    end,

    -- Block only if ALL profiles block
    AND = function(results)
        if #results == 0 then
            return false
        end
        for _, r in ipairs(results) do
            if r.result.action ~= "block" then
                return false
            end
        end
        return true
    end,

    -- Block if majority (>50%) of profiles block
    MAJORITY = function(results)
        if #results == 0 then
            return false
        end
        local blocked_count = 0
        for _, r in ipairs(results) do
            if r.result.action == "block" then
                blocked_count = blocked_count + 1
            end
        end
        return blocked_count > (#results / 2)
    end
}

-- Score aggregation strategies
local SCORE_STRATEGIES = {
    -- Simple sum of all scores
    SUM = function(results)
        local total = 0
        for _, r in ipairs(results) do
            total = total + (r.result.score or 0)
        end
        return total
    end,

    -- Maximum score (worst case)
    MAX = function(results)
        local max_score = 0
        for _, r in ipairs(results) do
            local score = r.result.score or 0
            if score > max_score then
                max_score = score
            end
        end
        return max_score
    end,

    -- Weighted average based on profile weights
    WEIGHTED_AVG = function(results)
        local weighted_sum = 0
        local total_weight = 0
        for _, r in ipairs(results) do
            local weight = r.weight or 1
            weighted_sum = weighted_sum + ((r.result.score or 0) * weight)
            total_weight = total_weight + weight
        end
        if total_weight == 0 then
            return 0
        end
        return weighted_sum / total_weight
    end
}

-- Execute a single profile (for parallel execution)
local function execute_single_profile(profile_id, request_context)
    local store = get_profile_store()
    local executor = get_single_executor()

    -- Get profile from store
    local profile, err = store.get(profile_id)
    if not profile then
        ngx.log(ngx.ERR, "Failed to get profile '", profile_id, "': ", err)
        return {
            action = "allow",
            score = 0,
            flags = {"profile_error:" .. (err or "not_found")},
            details = {error = err, profile_id = profile_id}
        }
    end

    -- Check if profile is enabled
    if not profile.enabled then
        ngx.log(ngx.DEBUG, "Profile '", profile_id, "' is disabled")
        return {
            action = "allow",
            score = 0,
            flags = {"profile_disabled"},
            details = {profile_id = profile_id}
        }
    end

    -- Execute the profile
    return executor.execute(profile, request_context)
end

-- Execute profiles in parallel using ngx.thread
function _M.execute_parallel(config, request_context)
    local start_time = ngx.now()
    local threads = {}
    local results = {}
    local profile_attachments = config.profiles or {}

    -- If no profiles configured, return allow
    if #profile_attachments == 0 then
        return {
            action = "allow",
            score = 0,
            flags = {},
            details = {},
            blocked_by = {},
            profiles_executed = 0,
            execution_time_ms = 0
        }
    end

    -- Sort by priority (lower = first, for logging order)
    table.sort(profile_attachments, function(a, b)
        return (a.priority or 500) < (b.priority or 500)
    end)

    -- Spawn threads for all profiles
    for i, attachment in ipairs(profile_attachments) do
        local profile_id = attachment.id
        local co, err = ngx.thread.spawn(execute_single_profile, profile_id, request_context)
        if co then
            threads[i] = {
                thread = co,
                profile_id = profile_id,
                weight = attachment.weight or 1,
                priority = attachment.priority or 500
            }
        else
            ngx.log(ngx.ERR, "Failed to spawn thread for profile '", profile_id, "': ", err)
            -- Add error result
            table.insert(results, {
                profile_id = profile_id,
                weight = attachment.weight or 1,
                priority = attachment.priority or 500,
                result = {
                    action = "allow",
                    score = 0,
                    flags = {"thread_spawn_error"},
                    details = {error = err}
                }
            })
        end
    end

    -- Wait for all threads and collect results
    for i, t in pairs(threads) do
        local ok, result = ngx.thread.wait(t.thread)
        if ok and result then
            table.insert(results, {
                profile_id = t.profile_id,
                weight = t.weight,
                priority = t.priority,
                result = result
            })

            -- Short-circuit if enabled and this profile blocks
            if config.short_circuit and result.action == "block" then
                ngx.log(ngx.DEBUG, "Short-circuit triggered by profile '", t.profile_id, "'")
                -- Kill remaining threads
                for j, remaining in pairs(threads) do
                    if j > i then
                        ngx.thread.kill(remaining.thread)
                    end
                end
                break
            end
        else
            ngx.log(ngx.ERR, "Thread failed for profile '", t.profile_id, "'")
            table.insert(results, {
                profile_id = t.profile_id,
                weight = t.weight,
                priority = t.priority,
                result = {
                    action = "allow",
                    score = 0,
                    flags = {"thread_execution_error"},
                    details = {}
                }
            })
        end
    end

    -- Sort results by priority for consistent reporting
    table.sort(results, function(a, b)
        return a.priority < b.priority
    end)

    -- Aggregate results
    return _M.aggregate(results, config, start_time)
end

-- Execute profiles sequentially (fallback or when parallel not supported)
function _M.execute_sequential(config, request_context)
    local start_time = ngx.now()
    local results = {}
    local profile_attachments = config.profiles or {}

    -- If no profiles configured, return allow
    if #profile_attachments == 0 then
        return {
            action = "allow",
            score = 0,
            flags = {},
            details = {},
            blocked_by = {},
            profiles_executed = 0,
            execution_time_ms = 0
        }
    end

    -- Sort by priority (lower = first)
    table.sort(profile_attachments, function(a, b)
        return (a.priority or 500) < (b.priority or 500)
    end)

    -- Execute each profile
    for _, attachment in ipairs(profile_attachments) do
        local result = execute_single_profile(attachment.id, request_context)

        table.insert(results, {
            profile_id = attachment.id,
            weight = attachment.weight or 1,
            priority = attachment.priority or 500,
            result = result
        })

        -- Short-circuit if enabled and this profile blocks
        if config.short_circuit and result.action == "block" then
            ngx.log(ngx.DEBUG, "Short-circuit triggered by profile '", attachment.id, "'")
            break
        end
    end

    -- Aggregate results
    return _M.aggregate(results, config, start_time)
end

-- Aggregate results from multiple profiles
function _M.aggregate(results, config, start_time)
    local aggregation = config.aggregation or "OR"
    local score_aggregation = config.score_aggregation or "SUM"

    -- Get aggregation functions
    local binary_fn = AGGREGATION_STRATEGIES[aggregation] or AGGREGATION_STRATEGIES.OR
    local score_fn = SCORE_STRATEGIES[score_aggregation] or SCORE_STRATEGIES.SUM

    -- Aggregate binary decision
    local final_blocked = binary_fn(results)

    -- Aggregate score
    local final_score = score_fn(results)

    -- Collect all flags, details, and track which profiles blocked
    local all_flags = {}
    local all_details = {}
    local blocked_by = {}
    local action_configs = {}

    for _, r in ipairs(results) do
        -- Collect flags
        if r.result.flags then
            for _, flag in ipairs(r.result.flags) do
                table.insert(all_flags, r.profile_id .. ":" .. flag)
            end
        end

        -- Collect details
        if r.result.details then
            all_details[r.profile_id] = r.result.details
        end

        -- Track which profiles blocked
        if r.result.action == "block" then
            table.insert(blocked_by, r.profile_id)
        end

        -- Collect action configs (for tarpit delay, etc.)
        if r.result.action_config then
            action_configs[r.profile_id] = r.result.action_config
        end
    end

    -- Determine final action
    local final_action = "allow"
    local final_action_config = nil

    if final_blocked then
        final_action = "block"
        -- Use the first blocking profile's action config
        if #blocked_by > 0 then
            final_action_config = action_configs[blocked_by[1]]
        end
    end

    -- Build per-profile results for logging
    local profile_results = {}
    for _, r in ipairs(results) do
        profile_results[r.profile_id] = {
            action = r.result.action,
            score = r.result.score,
            flags = r.result.flags,
            execution_time_ms = r.result.execution_time_ms
        }
    end

    local execution_time_ms = (ngx.now() - start_time) * 1000

    return {
        action = final_action,
        action_config = final_action_config,
        score = final_score,
        flags = all_flags,
        details = all_details,
        blocked_by = blocked_by,
        profiles_executed = #results,
        profile_results = profile_results,
        aggregation = aggregation,
        score_aggregation = score_aggregation,
        execution_time_ms = execution_time_ms
    }
end

-- Main execution entry point
-- Chooses parallel or sequential based on environment/config
-- Also executes defense lines after base profile if configured
function _M.execute(config, request_context)
    -- Validate config
    if not config then
        return {
            action = "allow",
            score = 0,
            flags = {"no_config"},
            details = {},
            blocked_by = {},
            profiles_executed = 0,
            execution_time_ms = 0
        }
    end

    -- Check if enabled
    if config.enabled == false then
        return {
            action = "allow",
            score = 0,
            flags = {"profiles_disabled"},
            details = {},
            blocked_by = {},
            profiles_executed = 0,
            execution_time_ms = 0
        }
    end

    -- Execute base profiles
    local base_result
    if ngx.thread and ngx.thread.spawn then
        base_result = _M.execute_parallel(config, request_context)
    else
        ngx.log(ngx.WARN, "ngx.thread not available, using sequential execution")
        base_result = _M.execute_sequential(config, request_context)
    end

    -- If base profile blocks, return immediately (defense lines not evaluated)
    if base_result.action == "block" then
        return base_result
    end

    -- Check for defense lines in endpoint config
    local defense_lines = nil
    if request_context and request_context.endpoint_config then
        defense_lines = request_context.endpoint_config.defense_lines
    end

    -- If no defense lines, return base result
    if not defense_lines or #defense_lines == 0 then
        return base_result
    end

    -- Execute defense lines
    local line_executor = get_defense_line_executor()
    local lines_result = line_executor.execute(defense_lines, request_context)

    -- Log defense lines execution
    ngx.log(ngx.INFO, string.format(
        "DEFENSE_LINES: endpoint=%s lines_executed=%d action=%s score=%d blocked_by_line=%s",
        request_context.endpoint_id or "unknown",
        lines_result.defense_lines_executed or 0,
        lines_result.action,
        lines_result.score or 0,
        lines_result.blocked_by_line or "none"
    ))

    -- Merge results: if defense lines block, the final action is block
    if lines_result.action == "block" then
        -- Combine flags from base and defense lines
        local all_flags = {}
        for _, flag in ipairs(base_result.flags or {}) do
            table.insert(all_flags, flag)
        end
        for _, flag in ipairs(lines_result.flags or {}) do
            table.insert(all_flags, flag)
        end

        return {
            action = "block",
            action_config = lines_result.action_config or base_result.action_config,
            score = base_result.score + lines_result.score,
            flags = all_flags,
            details = {
                base_profile = base_result.details,
                defense_lines = lines_result.details
            },
            blocked_by = {"defense_line:" .. (lines_result.blocked_by_line or "unknown")},
            profiles_executed = base_result.profiles_executed,
            defense_lines_executed = lines_result.defense_lines_executed,
            profile_results = base_result.profile_results,
            line_results = lines_result.line_results,
            aggregation = base_result.aggregation,
            score_aggregation = base_result.score_aggregation,
            execution_time_ms = base_result.execution_time_ms + lines_result.execution_time_ms
        }
    end

    -- Both base profile and defense lines passed
    -- Combine flags
    local all_flags = {}
    for _, flag in ipairs(base_result.flags or {}) do
        table.insert(all_flags, flag)
    end
    for _, flag in ipairs(lines_result.flags or {}) do
        table.insert(all_flags, flag)
    end

    return {
        action = "allow",
        action_config = base_result.action_config,
        score = base_result.score + lines_result.score,
        flags = all_flags,
        details = {
            base_profile = base_result.details,
            defense_lines = lines_result.details
        },
        blocked_by = base_result.blocked_by,
        profiles_executed = base_result.profiles_executed,
        defense_lines_executed = lines_result.defense_lines_executed,
        profile_results = base_result.profile_results,
        line_results = lines_result.line_results,
        aggregation = base_result.aggregation,
        score_aggregation = base_result.score_aggregation,
        execution_time_ms = base_result.execution_time_ms + lines_result.execution_time_ms
    }
end

-- Get default config for endpoints without explicit profile configuration
function _M.get_default_config()
    return {
        enabled = true,
        profiles = {
            {id = "balanced-web", priority = 100, weight = 1}
        },
        aggregation = "OR",
        score_aggregation = "SUM",
        short_circuit = true
    }
end

-- Validate defense profile attachment configuration
function _M.validate_config(config)
    local errors = {}

    if type(config) ~= "table" then
        return false, {"Config must be a table"}
    end

    if config.profiles then
        if type(config.profiles) ~= "table" then
            table.insert(errors, "profiles must be an array")
        else
            for i, p in ipairs(config.profiles) do
                if type(p) ~= "table" then
                    table.insert(errors, "Profile " .. i .. " must be an object")
                elseif not p.id then
                    table.insert(errors, "Profile " .. i .. " missing 'id' field")
                elseif type(p.id) ~= "string" then
                    table.insert(errors, "Profile " .. i .. " 'id' must be a string")
                end

                if p.priority and type(p.priority) ~= "number" then
                    table.insert(errors, "Profile " .. i .. " 'priority' must be a number")
                end

                if p.weight and (type(p.weight) ~= "number" or p.weight < 0 or p.weight > 1) then
                    table.insert(errors, "Profile " .. i .. " 'weight' must be a number between 0 and 1")
                end
            end
        end
    end

    if config.aggregation then
        if not AGGREGATION_STRATEGIES[config.aggregation] then
            table.insert(errors, "Invalid aggregation strategy: " .. tostring(config.aggregation) ..
                ". Must be one of: OR, AND, MAJORITY")
        end
    end

    if config.score_aggregation then
        if not SCORE_STRATEGIES[config.score_aggregation] then
            table.insert(errors, "Invalid score_aggregation strategy: " .. tostring(config.score_aggregation) ..
                ". Must be one of: SUM, MAX, WEIGHTED_AVG")
        end
    end

    if #errors > 0 then
        return false, errors
    end

    return true, nil
end

-- Return module
return _M
