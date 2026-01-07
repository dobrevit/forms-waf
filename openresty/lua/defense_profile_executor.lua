-- defense_profile_executor.lua
-- DAG-based defense profile execution engine
-- Executes defense nodes in a directed acyclic graph with parallel execution support

local _M = {}

local cjson = require "cjson.safe"

-- Forward declarations for functions used before definition
local execute_single_node

-- Node result structure
-- {
--   score = number (0-100),
--   blocked = boolean,
--   allowed = boolean,
--   flags = {"flag1", "flag2"},
--   details = {...}
-- }

-- Standardized result constructors
function _M.result_score(score, flags, details)
    return {
        score = score or 0,
        blocked = false,
        allowed = false,
        flags = flags or {},
        details = details or {}
    }
end

function _M.result_blocked(reason, flags, details)
    return {
        score = 0,
        blocked = true,
        allowed = false,
        flags = flags or {},
        details = details or {},
        block_reason = reason
    }
end

function _M.result_allowed(reason, flags, details)
    return {
        score = 0,
        blocked = false,
        allowed = true,
        flags = flags or {},
        details = details or {},
        allow_reason = reason
    }
end

-- Defense mechanism registry
-- Each defense returns a standardized result
local DEFENSE_REGISTRY = {}

-- Register a defense mechanism
function _M.register_defense(name, handler)
    DEFENSE_REGISTRY[name] = handler
end

-- Get registered defense handler
function _M.get_defense(name)
    return DEFENSE_REGISTRY[name]
end

-- List all registered defenses
function _M.list_defenses()
    local names = {}
    for name, _ in pairs(DEFENSE_REGISTRY) do
        table.insert(names, name)
    end
    table.sort(names)
    return names
end

-- Observation mechanism registry
-- Observations don't affect scoring/blocking, they just observe/record
local OBSERVATION_REGISTRY = {}

-- Register an observation mechanism
function _M.register_observation(name, handler)
    OBSERVATION_REGISTRY[name] = handler
end

-- Get registered observation handler
function _M.get_observation(name)
    return OBSERVATION_REGISTRY[name]
end

-- List all registered observations
function _M.list_observations()
    local names = {}
    for name, _ in pairs(OBSERVATION_REGISTRY) do
        table.insert(names, name)
    end
    table.sort(names)
    return names
end

-- Operator implementations
local OPERATORS = {}

-- Sum operator: aggregate scores from multiple inputs
OPERATORS["sum"] = function(inputs, config)
    local total_score = 0
    local all_flags = {}
    local all_details = {}

    for _, input in ipairs(inputs) do
        if input.score then
            total_score = total_score + input.score
        end
        if input.flags then
            for _, flag in ipairs(input.flags) do
                table.insert(all_flags, flag)
            end
        end
        if input.details then
            for k, v in pairs(input.details) do
                all_details[k] = v
            end
        end
    end

    return {
        score = total_score,
        blocked = false,
        allowed = false,
        flags = all_flags,
        details = all_details
    }
end

-- Threshold branch operator: route based on score ranges
-- config.ranges = [{min, max, output}, ...]
OPERATORS["threshold_branch"] = function(inputs, config)
    local total_score = 0
    for _, input in ipairs(inputs) do
        if input.score then
            total_score = total_score + input.score
        end
    end

    local ranges = config.ranges or {}
    for _, range in ipairs(ranges) do
        local min_val = range.min or 0
        local max_val = range.max

        if total_score >= min_val and (max_val == nil or total_score < max_val) then
            return {
                branch = range.output,
                score = total_score,
                range = range
            }
        end
    end

    -- No range matched, use default
    return {
        branch = config.default_output or "continue",
        score = total_score
    }
end

-- AND operator: all inputs must be true
OPERATORS["and"] = function(inputs, config)
    local all_true = true
    local all_flags = {}

    for _, input in ipairs(inputs) do
        -- Binary check: blocked or allowed counts as "true"
        local is_true = input.blocked or input.allowed or (input.score and input.score > 0)
        if not is_true then
            all_true = false
        end
        if input.flags then
            for _, flag in ipairs(input.flags) do
                table.insert(all_flags, flag)
            end
        end
    end

    return {
        result = all_true,
        flags = all_flags
    }
end

-- OR operator: any input can be true
OPERATORS["or"] = function(inputs, config)
    local any_true = false
    local all_flags = {}

    for _, input in ipairs(inputs) do
        local is_true = input.blocked or input.allowed or (input.score and input.score > 0)
        if is_true then
            any_true = true
        end
        if input.flags then
            for _, flag in ipairs(input.flags) do
                table.insert(all_flags, flag)
            end
        end
    end

    return {
        result = any_true,
        flags = all_flags
    }
end

-- Max operator: take maximum score
OPERATORS["max"] = function(inputs, config)
    local max_score = 0
    local all_flags = {}

    for _, input in ipairs(inputs) do
        if input.score and input.score > max_score then
            max_score = input.score
        end
        if input.flags then
            for _, flag in ipairs(input.flags) do
                table.insert(all_flags, flag)
            end
        end
    end

    return {
        score = max_score,
        flags = all_flags
    }
end

-- Min operator: take minimum score
OPERATORS["min"] = function(inputs, config)
    local min_score = nil
    local all_flags = {}

    for _, input in ipairs(inputs) do
        if input.score then
            if min_score == nil or input.score < min_score then
                min_score = input.score
            end
        end
        if input.flags then
            for _, flag in ipairs(input.flags) do
                table.insert(all_flags, flag)
            end
        end
    end

    return {
        score = min_score or 0,
        flags = all_flags
    }
end

-- Execute an operator node
local function execute_operator(node, inputs)
    local operator_func = OPERATORS[node.operator]
    if not operator_func then
        ngx.log(ngx.ERR, "Unknown operator: ", node.operator)
        return nil, "Unknown operator: " .. node.operator
    end

    return operator_func(inputs, node.config or {})
end

-- Action implementations
local ACTIONS = {}

-- Allow action: pass request through
-- In monitoring mode, when a defense triggers a block, we set final_action="block" but
-- continue processing to collect metrics from remaining defenses. Without this guard,
-- subsequent defenses or the allow action node would overwrite the block decision,
-- causing monitoring metrics to incorrectly show "allowed" instead of "monitored".
ACTIONS["allow"] = function(context, config)
    -- Preserve would-block state in monitoring mode (don't overwrite block with allow)
    if not (context.is_monitoring_mode and context.final_action == "block") then
        context.final_action = "allow"
    end
    context.action_config = config
    return true
end

-- Block action: return 403
ACTIONS["block"] = function(context, config)
    context.final_action = "block"
    context.action_config = config
    context.block_reason = config.reason or "defense_profile_block"
    return true
end

-- Tarpit action: delay then block
ACTIONS["tarpit"] = function(context, config)
    context.final_action = "tarpit"
    context.action_config = config
    context.tarpit_delay = config.delay_seconds or 10
    context.tarpit_then = config.then_action or "block"
    return true
end

-- CAPTCHA action: serve challenge
ACTIONS["captcha"] = function(context, config)
    context.final_action = "captcha"
    context.action_config = config
    return true
end

-- Flag action: mark for review, continue flow
ACTIONS["flag"] = function(context, config)
    table.insert(context.flags, "profile_flag:" .. (config.reason or "flagged"))
    context.score = context.score + (config.score or 0)
    -- Flag doesn't terminate, returns false to continue
    return false
end

-- Monitor action: log but don't block
ACTIONS["monitor"] = function(context, config)
    context.final_action = "monitor"
    context.action_config = config
    return true
end

-- Build execution graph from profile
-- Returns: {nodes_by_id, edges, start_node_id, parallel_groups}
local function build_execution_graph(profile)
    local graph = profile.graph
    if not graph or not graph.nodes then
        return nil, "Invalid profile: missing graph or nodes"
    end

    local nodes_by_id = {}
    local edges = {}  -- {from_node_id -> [{output_name, to_node_id}]}
    local reverse_edges = {}  -- {to_node_id -> [{from_node_id, output_name}]}
    local start_node_id = nil

    -- Index nodes by ID
    for _, node in ipairs(graph.nodes) do
        nodes_by_id[node.id] = node
        if node.type == "start" then
            start_node_id = node.id
        end
    end

    -- Build edges from node outputs
    for _, node in ipairs(graph.nodes) do
        if node.outputs then
            edges[node.id] = edges[node.id] or {}
            for output_name, target_id in pairs(node.outputs) do
                table.insert(edges[node.id], {output = output_name, target = target_id})

                -- Build reverse edges
                reverse_edges[target_id] = reverse_edges[target_id] or {}
                table.insert(reverse_edges[target_id], {from = node.id, output = output_name})
            end
        end
    end

    -- Find parallel groups (nodes that can run concurrently)
    -- Nodes at the same depth level with no dependencies between them
    local parallel_groups = {}
    local visited = {}
    local depth = {}

    local function compute_depth(node_id, d)
        if visited[node_id] then
            return depth[node_id]
        end
        visited[node_id] = true
        depth[node_id] = d

        local node = nodes_by_id[node_id]
        if node and node.outputs then
            for _, edge in ipairs(edges[node_id] or {}) do
                compute_depth(edge.target, d + 1)
            end
        end

        return d
    end

    if start_node_id then
        compute_depth(start_node_id, 0)
    end

    -- Group nodes by depth
    for node_id, d in pairs(depth) do
        parallel_groups[d] = parallel_groups[d] or {}
        table.insert(parallel_groups[d], node_id)
    end

    return {
        nodes = nodes_by_id,
        edges = edges,
        reverse_edges = reverse_edges,
        start_node_id = start_node_id,
        parallel_groups = parallel_groups,
        depth = depth
    }
end

-- Execute a single defense node
local function execute_defense_node(node, request_context)
    local defense_name = node.defense
    if not defense_name then
        return nil, "Defense node missing 'defense' field"
    end

    local handler = DEFENSE_REGISTRY[defense_name]
    if not handler then
        ngx.log(ngx.WARN, "Defense not registered: ", defense_name)
        -- Return neutral result for unregistered defenses
        return _M.result_score(0, {}, {skipped = true, reason = "not_registered"})
    end

    -- Execute the defense
    local ok, result = pcall(handler, request_context, node.config or {})
    if not ok then
        ngx.log(ngx.ERR, "Defense ", defense_name, " error: ", result)
        return _M.result_score(0, {"defense_error:" .. defense_name}, {error = result})
    end

    return result
end

-- Execute nodes in parallel using ngx.thread
local function execute_parallel_nodes(node_ids, graph, request_context, node_results)
    -- Filter out already executed nodes
    local to_execute = {}
    for _, node_id in ipairs(node_ids) do
        if not node_results[node_id] then
            -- Check if all dependencies are satisfied
            local deps_satisfied = true
            local reverse = graph.reverse_edges[node_id] or {}
            for _, edge in ipairs(reverse) do
                if not node_results[edge.from] then
                    deps_satisfied = false
                    break
                end
            end
            if deps_satisfied then
                table.insert(to_execute, node_id)
            end
        end
    end

    if #to_execute == 0 then
        return
    end

    -- For single node, execute directly
    if #to_execute == 1 then
        local node_id = to_execute[1]
        local node = graph.nodes[node_id]
        local result = execute_single_node(node, graph, request_context, node_results)
        node_results[node_id] = result
        return
    end

    -- Spawn threads for parallel execution
    local threads = {}
    for _, node_id in ipairs(to_execute) do
        local node = graph.nodes[node_id]
        local co = ngx.thread.spawn(function()
            return execute_single_node(node, graph, request_context, node_results)
        end)
        table.insert(threads, {id = node_id, thread = co})
    end

    -- Wait for all threads
    for _, entry in ipairs(threads) do
        local ok, result = ngx.thread.wait(entry.thread)
        if ok then
            node_results[entry.id] = result
        else
            ngx.log(ngx.ERR, "Thread error for node ", entry.id, ": ", result)
            node_results[entry.id] = _M.result_score(0, {"thread_error"}, {error = result})
        end
    end
end

-- Execute a single node (any type)
execute_single_node = function(node, graph, request_context, node_results)
    if node.type == "start" then
        return {started = true}

    elseif node.type == "defense" then
        return execute_defense_node(node, request_context)

    elseif node.type == "operator" then
        -- Gather inputs from predecessor nodes
        local inputs = {}
        local reverse = graph.reverse_edges[node.id] or {}
        for _, edge in ipairs(reverse) do
            local result = node_results[edge.from]
            if result then
                table.insert(inputs, result)
            end
        end
        -- Also check explicit inputs array
        if node.inputs then
            for _, input_id in ipairs(node.inputs) do
                local result = node_results[input_id]
                if result and not inputs[result] then
                    table.insert(inputs, result)
                end
            end
        end
        return execute_operator(node, inputs)

    elseif node.type == "observation" then
        -- Execute observation node (doesn't affect scoring/blocking)
        local observation_handler = OBSERVATION_REGISTRY[node.observation]
        if not observation_handler then
            ngx.log(ngx.WARN, "Observation not registered: ", node.observation)
            return {observed = true, skipped = true}
        end

        local ok, result = pcall(observation_handler, request_context, node.config or {})
        if not ok then
            ngx.log(ngx.ERR, "Observation ", node.observation, " failed: ", result)
            return {observed = true, error = tostring(result)}
        end

        return {observed = true, result = result}

    elseif node.type == "action" then
        return {action = node.action, config = node.config}

    else
        ngx.log(ngx.WARN, "Unknown node type: ", node.type)
        return nil
    end
end

-- Main execution function
-- @param profile: Defense profile configuration
-- @param request_context: Request data (form_data, client_ip, headers, etc.)
-- @return: Execution result {action, score, flags, details}
function _M.execute(profile, request_context)
    local start_time = ngx.now()

    -- Build execution graph
    local graph, err = build_execution_graph(profile)
    if not graph then
        ngx.log(ngx.ERR, "Failed to build graph: ", err)
        return {
            action = profile.settings and profile.settings.default_action or "allow",
            score = 0,
            flags = {"profile_error:" .. (err or "unknown")},
            details = {error = err}
        }
    end

    -- Initialize execution context
    local exec_context = {
        score = 0,
        flags = {},
        details = {},
        final_action = nil,
        action_config = nil,
        would_block_reasons = {}  -- Track what would have blocked in monitoring mode
    }

    -- Node results cache
    local node_results = {}

    -- Check if we're in monitoring mode (continue execution even on blocks for full metrics)
    -- Use vhost_resolver.should_block() for proper mode handling (respects endpoint > vhost priority)
    local is_monitoring_mode = false
    if request_context and request_context.context then
        local vhost_resolver = require "vhost_resolver"
        -- should_block returns false for monitoring/passthrough modes
        local should_block = vhost_resolver.should_block(request_context.context)
        is_monitoring_mode = not should_block
    end

    -- Store monitoring mode in exec_context so action nodes can access it
    exec_context.is_monitoring_mode = is_monitoring_mode

    -- Execute starting from start node
    local current_node_id = graph.start_node_id
    local max_iterations = 100  -- Prevent infinite loops
    local iterations = 0

    while current_node_id and iterations < max_iterations do
        iterations = iterations + 1
        local node = graph.nodes[current_node_id]

        if not node then
            ngx.log(ngx.ERR, "Node not found: ", current_node_id)
            break
        end

        -- Execute the node
        local result = execute_single_node(node, graph, request_context, node_results)
        node_results[current_node_id] = result

        -- Accumulate results
        if result then
            -- Only accumulate score/flags from defense nodes (not operators, which aggregate)
            -- Operators like 'sum' already collect from their inputs, so we'd double-count
            if node.type == "defense" then
                if result.score then
                    exec_context.score = exec_context.score + result.score
                end
                if result.flags then
                    for _, flag in ipairs(result.flags) do
                        table.insert(exec_context.flags, flag)
                    end
                end
            end
            if result.details then
                for k, v in pairs(result.details) do
                    exec_context.details[k] = v
                end
            end

            -- Check for blocking result from defense
            if result.blocked then
                -- Record what would block (for both modes)
                local block_reason = result.block_reason or node.defense or "defense_block"
                table.insert(exec_context.would_block_reasons, block_reason)

                if is_monitoring_mode then
                    -- In monitoring mode: record the block but continue execution
                    -- to collect all metrics (hash, fingerprint, etc.)
                    table.insert(exec_context.flags, "would_block:" .. block_reason)
                    -- Set final_action to block (will be reported as "would block")
                    if not exec_context.final_action then
                        exec_context.final_action = "block"
                        exec_context.block_reason = block_reason
                    end
                    -- Follow the continue path instead of blocked path
                    local continue_output = node.outputs and node.outputs.continue
                    if continue_output then
                        current_node_id = continue_output
                        goto continue
                    end
                    -- No continue output - still try to continue to next logical node
                    -- (fall through to default next node handling below)
                else
                    -- In blocking mode: follow the blocked path
                    local block_output = node.outputs and node.outputs.blocked
                    if block_output then
                        current_node_id = block_output
                        goto continue
                    else
                        -- No explicit block output, use default block action
                        exec_context.final_action = "block"
                        exec_context.block_reason = block_reason
                        break
                    end
                end
            end

            -- Check for allow result from defense
            if result.allowed then
                local allow_output = node.outputs and node.outputs.allowed
                if allow_output then
                    current_node_id = allow_output
                    goto continue
                else
                    -- In monitoring mode, preserve would-block state (don't overwrite block with allow)
                    if not (is_monitoring_mode and exec_context.final_action == "block") then
                        exec_context.final_action = "allow"
                    end
                    exec_context.allow_reason = result.allow_reason
                    break
                end
            end

            -- Check for branch result from operator (threshold_branch)
            if result.branch then
                -- Look up the actual target node from the node's outputs
                local target = node.outputs and node.outputs[result.branch]
                if target then
                    current_node_id = target
                else
                    -- Fallback: use branch directly as node ID (legacy behavior)
                    current_node_id = result.branch
                end
                goto continue
            end
        end

        -- Handle action nodes
        if node.type == "action" then
            local action_func = ACTIONS[node.action]
            if action_func then
                local terminates = action_func(exec_context, node.config or {})
                if terminates then
                    break
                end
            else
                ngx.log(ngx.WARN, "Unknown action: ", node.action)
                break
            end
        end

        -- Move to next node (default: "next" or "continue" output)
        local next_node_id = nil
        if node.outputs then
            next_node_id = node.outputs["next"] or node.outputs["continue"]
        end
        current_node_id = next_node_id

        ::continue::
    end

    -- Check max execution time
    local elapsed_ms = (ngx.now() - start_time) * 1000
    local max_time = profile.settings and profile.settings.max_execution_time_ms or 100
    if elapsed_ms > max_time then
        ngx.log(ngx.WARN, "Profile execution exceeded max time: ", elapsed_ms, "ms > ", max_time, "ms")
        table.insert(exec_context.flags, "execution_slow")
    end

    -- Return final result
    return {
        action = exec_context.final_action or profile.settings and profile.settings.default_action or "allow",
        score = exec_context.score,
        flags = exec_context.flags,
        details = exec_context.details,
        block_reason = exec_context.block_reason,
        allow_reason = exec_context.allow_reason,
        tarpit_delay = exec_context.tarpit_delay,
        tarpit_then = exec_context.tarpit_then,
        action_config = exec_context.action_config,
        execution_time_ms = elapsed_ms,
        nodes_executed = iterations,
        would_block_reasons = exec_context.would_block_reasons,  -- What would have blocked (useful in monitoring mode)
        is_monitoring_mode = is_monitoring_mode
    }
end

-- Validate a profile's graph structure
-- @param profile: Defense profile to validate
-- @return: valid (bool), errors (table of strings)
function _M.validate_profile(profile)
    local errors = {}

    if not profile then
        return false, {"Profile is nil"}
    end

    if not profile.id or profile.id == "" then
        table.insert(errors, "Missing profile ID")
    end

    if not profile.name or profile.name == "" then
        table.insert(errors, "Missing profile name")
    end

    if not profile.graph then
        table.insert(errors, "Missing graph")
        return false, errors
    end

    if not profile.graph.nodes or #profile.graph.nodes == 0 then
        table.insert(errors, "Graph has no nodes")
        return false, errors
    end

    -- Build graph for validation
    local graph, err = build_execution_graph(profile)
    if not graph then
        table.insert(errors, "Failed to build graph: " .. (err or "unknown"))
        return false, errors
    end

    -- Check for start node
    if not graph.start_node_id then
        table.insert(errors, "Graph has no start node")
    end

    -- Check for at least one action node
    local has_action = false
    for _, node in ipairs(profile.graph.nodes) do
        if node.type == "action" then
            has_action = true
            break
        end
    end
    if not has_action then
        table.insert(errors, "Graph has no action nodes (need at least one terminal action)")
    end

    -- Check for invalid node references
    for _, node in ipairs(profile.graph.nodes) do
        if node.outputs then
            for output_name, target_id in pairs(node.outputs) do
                if not graph.nodes[target_id] then
                    table.insert(errors, string.format(
                        "Node '%s' output '%s' references non-existent node '%s'",
                        node.id, output_name, target_id
                    ))
                end
            end
        end

        -- Validate defense nodes reference registered defenses
        if node.type == "defense" then
            if not node.defense then
                table.insert(errors, string.format("Defense node '%s' missing 'defense' field", node.id))
            end
        end

        -- Validate operator nodes have valid operators
        if node.type == "operator" then
            if not node.operator then
                table.insert(errors, string.format("Operator node '%s' missing 'operator' field", node.id))
            elseif not OPERATORS[node.operator] then
                table.insert(errors, string.format("Operator node '%s' uses unknown operator '%s'", node.id, node.operator))
            end
        end

        -- Validate action nodes have valid actions
        if node.type == "action" then
            if not node.action then
                table.insert(errors, string.format("Action node '%s' missing 'action' field", node.id))
            elseif not ACTIONS[node.action] then
                table.insert(errors, string.format("Action node '%s' uses unknown action '%s'", node.id, node.action))
            end
        end
    end

    -- Check for cycles (simple DFS)
    local visiting = {}
    local visited = {}

    local function has_cycle(node_id, path)
        if visiting[node_id] then
            return true, path
        end
        if visited[node_id] then
            return false
        end

        visiting[node_id] = true
        table.insert(path, node_id)

        local node = graph.nodes[node_id]
        if node and node.outputs then
            for _, target_id in pairs(node.outputs) do
                local cycle, cycle_path = has_cycle(target_id, path)
                if cycle then
                    return true, cycle_path
                end
            end
        end

        visiting[node_id] = nil
        visited[node_id] = true
        table.remove(path)
        return false
    end

    if graph.start_node_id then
        local cycle, path = has_cycle(graph.start_node_id, {})
        if cycle then
            table.insert(errors, "Graph contains a cycle: " .. table.concat(path, " -> "))
        end
    end

    return #errors == 0, errors
end

-- Resolve profile inheritance
-- @param profile: Profile that may extend another
-- @param profile_loader: Function to load parent profile by ID
-- @param depth: Current inheritance depth (for cycle detection)
-- @return: Resolved profile, error
function _M.resolve_inheritance(profile, profile_loader, depth)
    depth = depth or 0
    local max_depth = 3

    if depth > max_depth then
        return nil, "Maximum inheritance depth exceeded"
    end

    if not profile.extends then
        return profile, nil
    end

    -- Load parent profile
    local parent, err = profile_loader(profile.extends)
    if not parent then
        return nil, "Failed to load parent profile '" .. profile.extends .. "': " .. (err or "not found")
    end

    -- Recursively resolve parent inheritance
    parent, err = _M.resolve_inheritance(parent, profile_loader, depth + 1)
    if not parent then
        return nil, err
    end

    -- Deep copy parent
    local resolved = cjson.decode(cjson.encode(parent))

    -- Override basic fields
    resolved.id = profile.id
    resolved.name = profile.name
    resolved.description = profile.description or resolved.description
    resolved.enabled = profile.enabled ~= nil and profile.enabled or resolved.enabled
    resolved.priority = profile.priority or resolved.priority
    resolved.extends = profile.extends

    -- Merge settings
    if profile.settings then
        resolved.settings = resolved.settings or {}
        for k, v in pairs(profile.settings) do
            resolved.settings[k] = v
        end
    end

    -- Apply node overrides
    if profile.graph and profile.graph.nodes then
        local parent_nodes_by_id = {}
        for i, node in ipairs(resolved.graph.nodes) do
            parent_nodes_by_id[node.id] = {node = node, index = i}
        end

        for _, child_node in ipairs(profile.graph.nodes) do
            if child_node.remove then
                -- Remove parent node
                local parent_entry = parent_nodes_by_id[child_node.id]
                if parent_entry then
                    table.remove(resolved.graph.nodes, parent_entry.index)
                    -- Rebuild index after removal
                    parent_nodes_by_id = {}
                    for i, node in ipairs(resolved.graph.nodes) do
                        parent_nodes_by_id[node.id] = {node = node, index = i}
                    end
                end
            elseif child_node.insert_after or child_node.insert_before then
                -- Insert new node relative to another
                local target_id = child_node.insert_after or child_node.insert_before
                local target_entry = parent_nodes_by_id[target_id]
                if target_entry then
                    local insert_idx = target_entry.index
                    if child_node.insert_after then
                        insert_idx = insert_idx + 1
                    end
                    -- Clean up insertion directives
                    local new_node = {}
                    for k, v in pairs(child_node) do
                        if k ~= "insert_after" and k ~= "insert_before" then
                            new_node[k] = v
                        end
                    end
                    table.insert(resolved.graph.nodes, insert_idx, new_node)
                    -- Rebuild index
                    parent_nodes_by_id = {}
                    for i, node in ipairs(resolved.graph.nodes) do
                        parent_nodes_by_id[node.id] = {node = node, index = i}
                    end
                end
            else
                -- Override existing node or add new
                local parent_entry = parent_nodes_by_id[child_node.id]
                if parent_entry then
                    -- Merge child node into parent
                    for k, v in pairs(child_node) do
                        parent_entry.node[k] = v
                    end
                else
                    -- Add as new node
                    table.insert(resolved.graph.nodes, child_node)
                end
            end
        end
    end

    return resolved, nil
end

-- Get defense metadata (for UI)
function _M.get_defense_metadata()
    return {
        ip_allowlist = {
            name = "IP Allowlist",
            description = "Check if IP is in allowlist",
            outputs = {"allowed", "continue"},
            output_types = {allowed = "binary", continue = "pass"}
        },
        geoip = {
            name = "GeoIP Check",
            description = "Geographic and ASN-based filtering",
            outputs = {"blocked", "continue"},
            output_types = {blocked = "binary", continue = "score"},
            config_schema = {
                blocked_countries = {type = "array", items = "string"},
                blocked_asns = {type = "array", items = "number"}
            }
        },
        ip_reputation = {
            name = "IP Reputation",
            description = "Check IP against reputation databases",
            outputs = {"blocked", "continue"},
            output_types = {blocked = "binary", continue = "score"}
        },
        timing_token = {
            name = "Timing Token",
            description = "Validate form fill timing",
            outputs = {"continue"},
            output_types = {continue = "score"},
            score_range = {min = 0, max = 40}
        },
        behavioral = {
            name = "Behavioral Tracking",
            description = "Detect anomalies in user behavior patterns",
            outputs = {"continue"},
            output_types = {continue = "score"},
            score_range = {min = 0, max = 15}
        },
        honeypot = {
            name = "Honeypot Fields",
            description = "Detect bots filling hidden fields",
            outputs = {"blocked", "continue"},
            output_types = {blocked = "binary", continue = "score"},
            config_schema = {
                action = {type = "enum", values = {"block", "flag"}},
                score = {type = "number", default = 50}
            }
        },
        keyword_filter = {
            name = "Keyword Filter",
            description = "Scan for blocked/flagged keywords",
            outputs = {"blocked", "continue"},
            output_types = {blocked = "binary", continue = "score"}
        },
        content_hash = {
            name = "Content Hash",
            description = "Check content hash against blocklist",
            outputs = {"blocked", "continue"},
            output_types = {blocked = "binary", continue = "pass"}
        },
        expected_fields = {
            name = "Expected Fields",
            description = "Validate form has expected fields only",
            outputs = {"blocked", "continue"},
            output_types = {blocked = "binary", continue = "score"},
            config_schema = {
                action = {type = "enum", values = {"block", "flag", "filter", "ignore"}}
            }
        },
        pattern_scan = {
            name = "Pattern Scanner",
            description = "Regex-based content scanning",
            outputs = {"continue"},
            output_types = {continue = "score"}
        },
        disposable_email = {
            name = "Disposable Email",
            description = "Detect disposable email addresses",
            outputs = {"blocked", "continue"},
            output_types = {blocked = "binary", continue = "score"},
            config_schema = {
                action = {type = "enum", values = {"block", "flag", "ignore"}}
            }
        },
        field_anomalies = {
            name = "Field Anomalies",
            description = "Detect bot-like field patterns",
            outputs = {"continue"},
            output_types = {continue = "score"}
        },
        fingerprint = {
            name = "Fingerprint Profiles",
            description = "Client fingerprinting and bot detection",
            outputs = {"blocked", "continue"},
            output_types = {blocked = "binary", continue = "score"}
        },
        header_consistency = {
            name = "Header Consistency",
            description = "Detect inconsistent browser headers",
            outputs = {"continue"},
            output_types = {continue = "score"}
        }
    }
end

-- Get operator metadata (for UI)
function _M.get_operator_metadata()
    return {
        sum = {
            name = "Sum",
            description = "Add scores from all inputs",
            input_type = "score",
            output_type = "score"
        },
        threshold_branch = {
            name = "Threshold Branch",
            description = "Route based on score ranges",
            input_type = "score",
            output_type = "branch",
            config_schema = {
                ranges = {
                    type = "array",
                    items = {
                        min = {type = "number"},
                        max = {type = "number", optional = true},
                        output = {type = "string"}
                    }
                }
            }
        },
        ["and"] = {
            name = "AND",
            description = "All inputs must be true",
            input_type = "binary",
            output_type = "binary"
        },
        ["or"] = {
            name = "OR",
            description = "Any input can be true",
            input_type = "binary",
            output_type = "binary"
        },
        max = {
            name = "Maximum",
            description = "Take highest score",
            input_type = "score",
            output_type = "score"
        },
        min = {
            name = "Minimum",
            description = "Take lowest score",
            input_type = "score",
            output_type = "score"
        }
    }
end

-- Get action metadata (for UI)
function _M.get_action_metadata()
    return {
        allow = {
            name = "Allow",
            description = "Pass request to backend",
            terminal = true
        },
        block = {
            name = "Block",
            description = "Return HTTP 403",
            terminal = true,
            config_schema = {
                reason = {type = "string"}
            }
        },
        tarpit = {
            name = "Tarpit",
            description = "Delay then reject with 429",
            terminal = true,
            config_schema = {
                delay_seconds = {type = "number", default = 10, min = 1, max = 60},
                then_action = {type = "enum", values = {"block", "allow"}, default = "block"}
            }
        },
        captcha = {
            name = "CAPTCHA",
            description = "Serve CAPTCHA challenge",
            terminal = true,
            config_schema = {
                provider = {type = "string", optional = true}
            }
        },
        flag = {
            name = "Flag",
            description = "Mark for review, continue flow",
            terminal = false,
            config_schema = {
                reason = {type = "string"},
                score = {type = "number", default = 0}
            }
        },
        monitor = {
            name = "Monitor",
            description = "Log but don't block",
            terminal = true
        }
    }
end

return _M
