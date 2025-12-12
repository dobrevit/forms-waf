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

-- Check if hostname matches wildcard pattern (e.g., *.example.com)
local function match_wildcard(hostname, pattern)
    if not hostname or not pattern then
        return false
    end

    -- Convert wildcard pattern to Lua pattern
    -- *.example.com -> [^.]+%.example%.com$
    local lua_pattern = pattern:gsub("%.", "%%.")  -- Escape dots
    lua_pattern = lua_pattern:gsub("^%*", "[^.]+") -- Replace leading * with match
    lua_pattern = lua_pattern .. "$"

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

    -- 3. Return default vhost
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

-- Validate vhost configuration
function _M.validate_config(config)
    local errors = {}

    -- Required: id
    if not config.id or config.id == "" then
        table.insert(errors, "id is required")
    elseif config.id:match("[^a-zA-Z0-9_-]") then
        table.insert(errors, "id must contain only alphanumeric characters, dashes, and underscores")
    end

    -- Required: at least one hostname
    if not config.hostnames or type(config.hostnames) ~= "table" or #config.hostnames == 0 then
        table.insert(errors, "at least one hostname is required")
    else
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
        -- Validate routing.upstream if provided
        if config.routing.upstream then
            validate_upstream(config.routing.upstream, "routing.upstream")
        end

        -- Check upstream is required when not using HAProxy
        local upstream = config.routing.upstream or config.upstream
        if config.routing.use_haproxy == false and not upstream then
            table.insert(errors, "upstream configuration required when not using HAProxy")
        end
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
