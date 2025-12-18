-- vhost_matcher.lua
-- Matches incoming requests to virtual host configurations based on Host header
-- Supports exact hostnames, wildcard patterns (*.example.com), and default fallback

local _M = {}

local cjson = require "cjson.safe"

-- Shared dictionary for vhost configuration cache
local vhost_cache = ngx.shared.vhost_cache

-- Cache TTL in seconds
local CACHE_TTL = 60

-- Default vhost ID (used when no match found)
local DEFAULT_VHOST = "_default"

_M.DEFAULT_VHOST = DEFAULT_VHOST

-- Get cached vhost index
local function get_vhost_index()
    local cached = vhost_cache:get("vhost_index")
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Get cached exact host mappings
local function get_exact_hosts()
    local cached = vhost_cache:get("exact_hosts")
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Get cached wildcard patterns
local function get_wildcard_patterns()
    local cached = vhost_cache:get("wildcard_patterns")
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Normalize hostname (lowercase, remove port)
local function normalize_host(host)
    if not host then
        return nil
    end
    -- Remove port if present
    host = host:match("([^:]+)") or host
    -- Lowercase
    return host:lower()
end

-- Check if hostname matches wildcard pattern
-- Supports:
--   - Leading wildcards: *.example.com matches foo.example.com, a.b.example.com
--   - Middle wildcards: www.*.example.com matches www.foo.example.com, www.a.b.example.com
--   - Multi-level matching: * matches one or more subdomain levels
local function match_wildcard(hostname, pattern)
    if not hostname or not pattern then
        return false
    end

    -- Convert wildcard pattern to Lua pattern
    -- 1. Escape all dots first
    local lua_pattern = pattern:gsub("%.", "%%.")

    -- 2. Replace ALL * with .+ (matches one or more of any char including dots)
    -- This supports both leading wildcards (*.example.com) and
    -- middle wildcards (www.*.example.com)
    lua_pattern = lua_pattern:gsub("%*", ".+")

    -- 3. Anchor at start and end for exact matching
    lua_pattern = "^" .. lua_pattern .. "$"

    return hostname:match(lua_pattern) ~= nil
end

-- Match request to vhost by Host header
-- Returns: vhost_id or DEFAULT_VHOST
function _M.match(host)
    local normalized = normalize_host(host)

    if not normalized then
        return DEFAULT_VHOST, "no_host"
    end

    -- 1. Try exact match first (fastest)
    local exact_hosts = get_exact_hosts()
    if exact_hosts[normalized] then
        return exact_hosts[normalized], "exact"
    end

    -- 2. Try wildcard patterns (sorted by specificity)
    local wildcards = get_wildcard_patterns()
    for _, entry in ipairs(wildcards) do
        if match_wildcard(normalized, entry.pattern) then
            return entry.vhost_id, "wildcard"
        end
    end

    -- 3. Check for catch-all hostnames ("_" or "*")
    -- These are nginx-style catch-all patterns that match any unmatched host
    if exact_hosts["_"] then
        return exact_hosts["_"], "catchall"
    end
    if exact_hosts["*"] then
        return exact_hosts["*"], "catchall"
    end

    -- 4. Return default vhost
    return DEFAULT_VHOST, "default"
end

-- Get vhost configuration by ID
function _M.get_config(vhost_id)
    if not vhost_id then
        return nil
    end

    local cache_key = "config:" .. vhost_id
    local cached = vhost_cache:get(cache_key)

    if cached then
        return cjson.decode(cached)
    end

    return nil
end

-- Get default vhost configuration
function _M.get_default_config()
    return _M.get_config(DEFAULT_VHOST)
end

-- Check if vhost is enabled
function _M.is_enabled(vhost_id)
    local config = _M.get_config(vhost_id)
    if not config then
        return true  -- Default: enabled
    end
    return config.enabled ~= false
end

-- Get upstream servers for a vhost
function _M.get_upstream(vhost_id)
    local config = _M.get_config(vhost_id)
    if not config or not config.upstream then
        return nil
    end
    return config.upstream
end

-- Check if vhost should use HAProxy
function _M.use_haproxy(vhost_id)
    local config = _M.get_config(vhost_id)
    if not config or not config.routing then
        return true  -- Default: use HAProxy
    end
    return config.routing.use_haproxy ~= false
end

-- Get HAProxy backend name for vhost
function _M.get_haproxy_backend(vhost_id)
    local config = _M.get_config(vhost_id)
    if not config or not config.routing then
        return nil
    end
    return config.routing.haproxy_backend
end

-- Update cache from Redis data (called by redis_sync)
function _M.update_cache(cache_type, data, ttl)
    local actual_ttl = ttl or CACHE_TTL

    if cache_type == "vhost_index" then
        vhost_cache:set("vhost_index", data, actual_ttl)
    elseif cache_type == "exact_hosts" then
        vhost_cache:set("exact_hosts", data, actual_ttl)
    elseif cache_type == "wildcard_patterns" then
        vhost_cache:set("wildcard_patterns", data, actual_ttl)
    elseif cache_type:match("^config:") then
        vhost_cache:set(cache_type, data, actual_ttl)
    end
end

-- Store vhost configuration in cache
function _M.cache_config(vhost_id, config, ttl)
    local actual_ttl = ttl or CACHE_TTL
    local cache_key = "config:" .. vhost_id
    local json_data = cjson.encode(config)

    if json_data then
        vhost_cache:set(cache_key, json_data, actual_ttl)
        return true
    end

    return false
end

-- Get all cached vhost IDs
function _M.get_all_vhost_ids()
    return get_vhost_index()
end

-- Clear all vhost cache
function _M.clear_cache()
    vhost_cache:flush_all()
end

-- Get cache statistics
function _M.get_stats()
    local index = get_vhost_index()
    local exact = get_exact_hosts()
    local wildcards = get_wildcard_patterns()

    local exact_count = 0
    for _ in pairs(exact) do
        exact_count = exact_count + 1
    end

    return {
        vhosts = #index,
        exact_hosts = exact_count,
        wildcard_patterns = #wildcards
    }
end

-- Validate timing configuration
local function validate_timing_config(timing)
    local errors = {}

    -- enabled must be boolean if present
    if timing.enabled ~= nil and type(timing.enabled) ~= "boolean" then
        table.insert(errors, "enabled must be a boolean")
    end

    -- cookie_ttl must be positive number within range
    if timing.cookie_ttl ~= nil then
        local ttl = tonumber(timing.cookie_ttl)
        if not ttl or ttl < 1 or ttl > 86400 then
            table.insert(errors, "cookie_ttl must be between 1 and 86400 seconds")
        end
    end

    -- min_time_block must be non-negative within range
    if timing.min_time_block ~= nil then
        local val = tonumber(timing.min_time_block)
        if not val or val < 0 or val > 3600 then
            table.insert(errors, "min_time_block must be between 0 and 3600 seconds")
        end
    end

    -- min_time_flag must be >= min_time_block
    if timing.min_time_flag ~= nil then
        local val = tonumber(timing.min_time_flag)
        if not val or val < 0 or val > 3600 then
            table.insert(errors, "min_time_flag must be between 0 and 3600 seconds")
        end
        local block_val = tonumber(timing.min_time_block) or 2
        if val and val < block_val then
            table.insert(errors, "min_time_flag must be >= min_time_block")
        end
    end

    -- Score values must be within range
    local score_fields = {"score_no_cookie", "score_too_fast", "score_suspicious"}
    for _, field in ipairs(score_fields) do
        if timing[field] ~= nil then
            local val = tonumber(timing[field])
            if not val or val < 0 or val > 100 then
                table.insert(errors, field .. " must be between 0 and 100")
            end
        end
    end

    -- start_paths must be array of strings
    if timing.start_paths ~= nil then
        if type(timing.start_paths) ~= "table" then
            table.insert(errors, "start_paths must be an array")
        else
            for i, path in ipairs(timing.start_paths) do
                if type(path) ~= "string" or path == "" then
                    table.insert(errors, "start_paths[" .. i .. "] must be a non-empty string")
                    break
                end
            end
        end
    end

    -- end_paths must be array of strings
    if timing.end_paths ~= nil then
        if type(timing.end_paths) ~= "table" then
            table.insert(errors, "end_paths must be an array")
        else
            for i, path in ipairs(timing.end_paths) do
                if type(path) ~= "string" or path == "" then
                    table.insert(errors, "end_paths[" .. i .. "] must be a non-empty string")
                    break
                end
            end
        end
    end

    -- path_match_mode validation
    if timing.path_match_mode ~= nil then
        local valid_modes = {exact = true, prefix = true, regex = true}
        if not valid_modes[timing.path_match_mode] then
            table.insert(errors, "path_match_mode must be one of: exact, prefix, regex")
        end

        -- Validate regex patterns if regex mode
        if timing.path_match_mode == "regex" then
            local paths_to_check = {}
            if timing.start_paths then
                for _, p in ipairs(timing.start_paths) do
                    table.insert(paths_to_check, {field = "start_paths", pattern = p})
                end
            end
            if timing.end_paths then
                for _, p in ipairs(timing.end_paths) do
                    table.insert(paths_to_check, {field = "end_paths", pattern = p})
                end
            end

            for _, item in ipairs(paths_to_check) do
                local ok, err = pcall(ngx.re.match, "", item.pattern)
                if not ok then
                    table.insert(errors, item.field .. " contains invalid regex: " .. item.pattern)
                end
            end
        end
    end

    return errors
end

-- Validate behavioral tracking configuration
local function validate_behavioral_config(behavioral)
    local errors = {}

    -- enabled must be boolean if present
    if behavioral.enabled ~= nil and type(behavioral.enabled) ~= "boolean" then
        table.insert(errors, "enabled must be a boolean")
    end

    -- Validate flows array
    if behavioral.flows ~= nil then
        if type(behavioral.flows) ~= "table" then
            table.insert(errors, "flows must be an array")
        else
            for i, flow in ipairs(behavioral.flows) do
                local flow_prefix = "flows[" .. i .. "]."

                -- name is required
                if not flow.name or flow.name == "" then
                    table.insert(errors, flow_prefix .. "name is required")
                elseif type(flow.name) ~= "string" then
                    table.insert(errors, flow_prefix .. "name must be a string")
                elseif flow.name:match("[^a-zA-Z0-9_-]") then
                    table.insert(errors, flow_prefix .. "name must contain only alphanumeric characters, dashes, and underscores")
                end

                -- start_paths validation
                if flow.start_paths ~= nil then
                    if type(flow.start_paths) ~= "table" then
                        table.insert(errors, flow_prefix .. "start_paths must be an array")
                    else
                        for j, path in ipairs(flow.start_paths) do
                            if type(path) ~= "string" or path == "" then
                                table.insert(errors, flow_prefix .. "start_paths[" .. j .. "] must be a non-empty string")
                                break
                            end
                        end
                    end
                end

                -- start_methods validation
                if flow.start_methods ~= nil then
                    if type(flow.start_methods) ~= "table" then
                        table.insert(errors, flow_prefix .. "start_methods must be an array")
                    else
                        local valid_methods = {GET = true, POST = true, PUT = true, PATCH = true, DELETE = true, OPTIONS = true, HEAD = true}
                        for j, method in ipairs(flow.start_methods) do
                            if type(method) ~= "string" then
                                table.insert(errors, flow_prefix .. "start_methods[" .. j .. "] must be a string")
                                break
                            elseif not valid_methods[method:upper()] then
                                table.insert(errors, flow_prefix .. "start_methods[" .. j .. "] must be a valid HTTP method")
                                break
                            end
                        end
                    end
                end

                -- end_paths validation
                if flow.end_paths ~= nil then
                    if type(flow.end_paths) ~= "table" then
                        table.insert(errors, flow_prefix .. "end_paths must be an array")
                    else
                        for j, path in ipairs(flow.end_paths) do
                            if type(path) ~= "string" or path == "" then
                                table.insert(errors, flow_prefix .. "end_paths[" .. j .. "] must be a non-empty string")
                                break
                            end
                        end
                    end
                end

                -- end_methods validation
                if flow.end_methods ~= nil then
                    if type(flow.end_methods) ~= "table" then
                        table.insert(errors, flow_prefix .. "end_methods must be an array")
                    else
                        local valid_methods = {GET = true, POST = true, PUT = true, PATCH = true, DELETE = true, OPTIONS = true, HEAD = true}
                        for j, method in ipairs(flow.end_methods) do
                            if type(method) ~= "string" then
                                table.insert(errors, flow_prefix .. "end_methods[" .. j .. "] must be a string")
                                break
                            elseif not valid_methods[method:upper()] then
                                table.insert(errors, flow_prefix .. "end_methods[" .. j .. "] must be a valid HTTP method")
                                break
                            end
                        end
                    end
                end

                -- path_match_mode validation
                if flow.path_match_mode ~= nil then
                    local valid_modes = {exact = true, prefix = true, regex = true}
                    if not valid_modes[flow.path_match_mode] then
                        table.insert(errors, flow_prefix .. "path_match_mode must be one of: exact, prefix, regex")
                    end

                    -- Validate regex patterns if regex mode
                    if flow.path_match_mode == "regex" then
                        local paths_to_check = {}
                        if flow.start_paths then
                            for _, p in ipairs(flow.start_paths) do
                                table.insert(paths_to_check, {field = flow_prefix .. "start_paths", pattern = p})
                            end
                        end
                        if flow.end_paths then
                            for _, p in ipairs(flow.end_paths) do
                                table.insert(paths_to_check, {field = flow_prefix .. "end_paths", pattern = p})
                            end
                        end

                        for _, item in ipairs(paths_to_check) do
                            local ok, _ = pcall(ngx.re.match, "", item.pattern)
                            if not ok then
                                table.insert(errors, item.field .. " contains invalid regex: " .. item.pattern)
                            end
                        end
                    end
                end
            end
        end
    end

    -- Validate tracking settings
    if behavioral.tracking ~= nil then
        if type(behavioral.tracking) ~= "table" then
            table.insert(errors, "tracking must be an object")
        else
            local bool_fields = {"fill_duration", "submission_counts", "unique_ips", "avg_spam_score"}
            for _, field in ipairs(bool_fields) do
                if behavioral.tracking[field] ~= nil and type(behavioral.tracking[field]) ~= "boolean" then
                    table.insert(errors, "tracking." .. field .. " must be a boolean")
                end
            end
        end
    end

    -- Validate baselines settings
    if behavioral.baselines ~= nil then
        if type(behavioral.baselines) ~= "table" then
            table.insert(errors, "baselines must be an object")
        else
            if behavioral.baselines.learning_period_days ~= nil then
                local val = tonumber(behavioral.baselines.learning_period_days)
                if not val or val < 1 or val > 90 then
                    table.insert(errors, "baselines.learning_period_days must be between 1 and 90")
                end
            end
            if behavioral.baselines.min_samples ~= nil then
                local val = tonumber(behavioral.baselines.min_samples)
                if not val or val < 10 or val > 10000 then
                    table.insert(errors, "baselines.min_samples must be between 10 and 10000")
                end
            end
        end
    end

    -- Validate anomaly_detection settings
    if behavioral.anomaly_detection ~= nil then
        if type(behavioral.anomaly_detection) ~= "table" then
            table.insert(errors, "anomaly_detection must be an object")
        else
            local ad = behavioral.anomaly_detection

            if ad.enabled ~= nil and type(ad.enabled) ~= "boolean" then
                table.insert(errors, "anomaly_detection.enabled must be a boolean")
            end

            if ad.std_dev_threshold ~= nil then
                local val = tonumber(ad.std_dev_threshold)
                if not val or val < 0.5 or val > 10 then
                    table.insert(errors, "anomaly_detection.std_dev_threshold must be between 0.5 and 10")
                end
            end

            if ad.action ~= nil then
                local valid_actions = {flag = true, score = true}
                if not valid_actions[ad.action] then
                    table.insert(errors, "anomaly_detection.action must be one of: flag, score")
                end
            end

            if ad.score_addition ~= nil then
                local val = tonumber(ad.score_addition)
                if not val or val < 0 or val > 100 then
                    table.insert(errors, "anomaly_detection.score_addition must be between 0 and 100")
                end
            end
        end
    end

    return errors
end

-- Validate vhost configuration
function _M.validate_config(config)
    local errors = {}

    -- Required: id
    if not config.id or config.id == "" then
        table.insert(errors, "id is required")
    elseif config.id:match("[^a-zA-Z0-9_-]") then
        table.insert(errors, "id must contain only alphanumeric characters, dashes, and underscores")
    end

    -- Required: at least one hostname (except for _default vhost which can have empty hostnames)
    if config.id ~= "_default" then
        if not config.hostnames or type(config.hostnames) ~= "table" or #config.hostnames == 0 then
            table.insert(errors, "at least one hostname is required")
        end
    end

    -- Validate hostname format if hostnames are provided
    if config.hostnames and type(config.hostnames) == "table" then
        for _, hostname in ipairs(config.hostnames) do
            if type(hostname) ~= "string" or hostname == "" then
                table.insert(errors, "each hostname must be a non-empty string")
                break
            end
        end
    end

    -- Helper to validate upstream config
    local function validate_upstream(upstream, location)
        if not upstream.servers or type(upstream.servers) ~= "table" then
            table.insert(errors, location .. ".servers must be an array")
        elseif #upstream.servers == 0 then
            table.insert(errors, location .. ".servers must have at least one server")
        else
            for _, server in ipairs(upstream.servers) do
                if type(server) ~= "string" or not server:match("^[a-zA-Z0-9._-]+:%d+$") then
                    if type(server) ~= "string" or not server:match("^[a-zA-Z0-9._-]+$") then
                        table.insert(errors, "invalid server format: " .. tostring(server) .. " (expected host:port or hostname)")
                    end
                end
            end
        end

        -- Validate upstream type
        if upstream.type then
            local valid_types = {roundrobin = true, least_conn = true, ip_hash = true}
            if not valid_types[upstream.type] then
                table.insert(errors, "invalid upstream type: must be roundrobin, least_conn, or ip_hash")
            end
        end
    end

    -- Validate upstream if provided at top level (legacy)
    if config.upstream then
        validate_upstream(config.upstream, "upstream")
    end

    -- Validate routing
    if config.routing then
        -- Only validate routing.upstream when NOT using HAProxy
        -- When use_haproxy is true or unset (default), upstream servers are optional
        if config.routing.use_haproxy == false then
            -- Direct routing - upstream is required
            local upstream = config.routing.upstream or config.upstream
            if not upstream then
                table.insert(errors, "upstream configuration required when not using HAProxy")
            elseif upstream.servers and #upstream.servers > 0 then
                -- Validate the upstream config only if servers are provided
                validate_upstream(upstream, "routing.upstream")
            else
                table.insert(errors, "routing.upstream.servers must have at least one server when not using HAProxy")
            end
        end
        -- When use_haproxy is true/unset, upstream config is ignored (HAProxy handles routing)
    end

    -- Validate WAF settings
    if config.waf then
        if config.waf.default_mode then
            local valid_modes = {blocking = true, monitoring = true, passthrough = true, strict = true}
            if not valid_modes[config.waf.default_mode] then
                table.insert(errors, "invalid waf.default_mode: must be blocking, monitoring, passthrough, or strict")
            end
        end
    end

    -- Validate timing configuration if provided
    if config.timing then
        local timing_errors = validate_timing_config(config.timing)
        for _, err in ipairs(timing_errors) do
            table.insert(errors, "timing." .. err)
        end
    end

    -- Validate behavioral tracking configuration if provided
    if config.behavioral then
        local behavioral_errors = validate_behavioral_config(config.behavioral)
        for _, err in ipairs(behavioral_errors) do
            table.insert(errors, "behavioral." .. err)
        end
    end

    return #errors == 0, errors
end

-- Select upstream server (simple round-robin for now)
-- For production, consider using lua-resty-upstream-healthcheck
local upstream_counters = {}

function _M.select_upstream_server(vhost_id)
    local config = _M.get_config(vhost_id)
    if not config then
        return nil
    end

    -- Upstream can be under routing.upstream or at top level (legacy)
    local upstream = (config.routing and config.routing.upstream) or config.upstream
    if not upstream or not upstream.servers then
        return nil
    end

    local servers = upstream.servers
    if #servers == 0 then
        return nil
    end

    if #servers == 1 then
        return servers[1]
    end

    -- Simple round-robin selection
    local counter_key = vhost_id or "default"
    upstream_counters[counter_key] = (upstream_counters[counter_key] or 0) + 1
    local index = ((upstream_counters[counter_key] - 1) % #servers) + 1

    return servers[index]
end

-- Build proxy URL for vhost
function _M.build_proxy_url(vhost_id)
    local server = _M.select_upstream_server(vhost_id)
    if not server then
        return nil
    end

    -- Add port if not present
    if not server:match(":%d+$") then
        server = server .. ":80"
    end

    return "http://" .. server
end

return _M
