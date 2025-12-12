-- endpoint_matcher.lua
-- Matches incoming requests to endpoint configurations
-- Supports exact paths, prefix patterns, and regex matching

local _M = {}

local cjson = require "cjson.safe"

-- Shared dictionary for endpoint configuration cache
local endpoint_cache = ngx.shared.endpoint_cache

-- Cache TTL in seconds
local CACHE_TTL = 60

-- Match types (in priority order)
local MATCH_TYPE = {
    EXACT = "exact",
    PREFIX = "prefix",
    REGEX = "regex",
    NONE = "none"
}

_M.MATCH_TYPE = MATCH_TYPE

-- Processing modes
local MODE = {
    BLOCKING = "blocking",      -- Active WAF protection (default)
    MONITORING = "monitoring",  -- Log but don't block
    PASSTHROUGH = "passthrough", -- Skip all WAF checks
    STRICT = "strict"           -- Lower thresholds, stricter rules
}

_M.MODE = MODE

-- Get cached endpoint index (list of all endpoint IDs with priority)
local function get_endpoint_index()
    local cached = endpoint_cache:get("endpoint_index")
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Get cached exact path mappings
local function get_exact_paths()
    local cached = endpoint_cache:get("exact_paths")
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Get cached prefix patterns
local function get_prefix_patterns()
    local cached = endpoint_cache:get("prefix_patterns")
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Get cached regex patterns
local function get_regex_patterns()
    local cached = endpoint_cache:get("regex_patterns")
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- ============================================================================
-- Vhost-specific cache functions
-- ============================================================================

-- Get cached vhost-specific endpoint index
local function get_vhost_endpoint_index(vhost_id)
    if not vhost_id or vhost_id == "" then
        return {}
    end
    local cache_key = "vhost_endpoint_index:" .. vhost_id
    local cached = endpoint_cache:get(cache_key)
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Get cached vhost-specific exact path mappings
local function get_vhost_exact_paths(vhost_id)
    if not vhost_id or vhost_id == "" then
        return {}
    end
    local cache_key = "vhost_exact_paths:" .. vhost_id
    local cached = endpoint_cache:get(cache_key)
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Get cached vhost-specific prefix patterns
local function get_vhost_prefix_patterns(vhost_id)
    if not vhost_id or vhost_id == "" then
        return {}
    end
    local cache_key = "vhost_prefix_patterns:" .. vhost_id
    local cached = endpoint_cache:get(cache_key)
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Get cached vhost-specific regex patterns
local function get_vhost_regex_patterns(vhost_id)
    if not vhost_id or vhost_id == "" then
        return {}
    end
    local cache_key = "vhost_regex_patterns:" .. vhost_id
    local cached = endpoint_cache:get(cache_key)
    if cached then
        return cjson.decode(cached)
    end
    return {}
end

-- Normalize path for matching (remove trailing slash, lowercase)
local function normalize_path(path)
    if not path then
        return "/"
    end
    -- Remove trailing slash (except for root)
    if #path > 1 and path:sub(-1) == "/" then
        path = path:sub(1, -2)
    end
    return path
end

-- Check if method matches endpoint configuration
local function method_matches(endpoint_methods, request_method)
    if not endpoint_methods or #endpoint_methods == 0 then
        -- No method restriction, matches all
        return true
    end

    for _, method in ipairs(endpoint_methods) do
        if method == "*" or method:upper() == request_method:upper() then
            return true
        end
    end

    return false
end

-- Check if content type matches endpoint configuration
local function content_type_matches(endpoint_content_types, request_content_type)
    if not endpoint_content_types or #endpoint_content_types == 0 then
        -- No content type restriction
        return true
    end

    if not request_content_type then
        return false
    end

    for _, ct in ipairs(endpoint_content_types) do
        if ct == "*" or request_content_type:find(ct, 1, true) then
            return true
        end
    end

    return false
end

-- Match request against exact paths
-- Returns: endpoint_id or nil
local function match_exact(path, method)
    local exact_paths = get_exact_paths()

    -- Try exact path + method first
    local key = path .. ":" .. method:upper()
    if exact_paths[key] then
        return exact_paths[key]
    end

    -- Try exact path with wildcard method
    key = path .. ":*"
    if exact_paths[key] then
        return exact_paths[key]
    end

    return nil
end

-- Match request against prefix patterns
-- Returns: endpoint_id or nil
local function match_prefix(path, method)
    local prefix_patterns = get_prefix_patterns()

    -- Prefix patterns are sorted by length (longest first) for specificity
    for _, pattern in ipairs(prefix_patterns) do
        local prefix = pattern.prefix
        local endpoint_method = pattern.method or "*"

        -- Check if path starts with prefix
        if path:sub(1, #prefix) == prefix then
            -- Check method
            if endpoint_method == "*" or endpoint_method:upper() == method:upper() then
                return pattern.endpoint_id
            end
        end
    end

    return nil
end

-- Match request against regex patterns
-- Returns: endpoint_id or nil
local function match_regex(path, method)
    local regex_patterns = get_regex_patterns()

    for _, pattern in ipairs(regex_patterns) do
        local regex = pattern.pattern
        local endpoint_method = pattern.method or "*"

        -- Check regex match
        local match, err = ngx.re.match(path, regex, "jo")
        if match then
            -- Check method
            if endpoint_method == "*" or endpoint_method:upper() == method:upper() then
                return pattern.endpoint_id
            end
        elseif err then
            ngx.log(ngx.WARN, "Regex match error for pattern '", regex, "': ", err)
        end
    end

    return nil
end

-- ============================================================================
-- Vhost-specific matching functions
-- ============================================================================

-- Match request against vhost-specific exact paths
-- Returns: endpoint_id or nil
local function match_vhost_exact(path, method, vhost_id)
    local exact_paths = get_vhost_exact_paths(vhost_id)

    -- Try exact path + method first
    local key = path .. ":" .. method:upper()
    if exact_paths[key] then
        return exact_paths[key]
    end

    -- Try exact path with wildcard method
    key = path .. ":*"
    if exact_paths[key] then
        return exact_paths[key]
    end

    return nil
end

-- Match request against vhost-specific prefix patterns
-- Returns: endpoint_id or nil
local function match_vhost_prefix(path, method, vhost_id)
    local prefix_patterns = get_vhost_prefix_patterns(vhost_id)

    -- Prefix patterns are sorted by length (longest first) for specificity
    for _, pattern in ipairs(prefix_patterns) do
        local prefix = pattern.prefix
        local endpoint_method = pattern.method or "*"

        -- Check if path starts with prefix
        if path:sub(1, #prefix) == prefix then
            -- Check method
            if endpoint_method == "*" or endpoint_method:upper() == method:upper() then
                return pattern.endpoint_id
            end
        end
    end

    return nil
end

-- Match request against vhost-specific regex patterns
-- Returns: endpoint_id or nil
local function match_vhost_regex(path, method, vhost_id)
    local regex_patterns = get_vhost_regex_patterns(vhost_id)

    for _, pattern in ipairs(regex_patterns) do
        local regex = pattern.pattern
        local endpoint_method = pattern.method or "*"

        -- Check regex match
        local match, err = ngx.re.match(path, regex, "jo")
        if match then
            -- Check method
            if endpoint_method == "*" or endpoint_method:upper() == method:upper() then
                return pattern.endpoint_id
            end
        elseif err then
            ngx.log(ngx.WARN, "Regex match error for pattern '", regex, "': ", err)
        end
    end

    return nil
end

-- Main matching function
-- Returns: endpoint_id, match_type
function _M.match(path, method)
    local normalized_path = normalize_path(path)
    local request_method = method or ngx.req.get_method()

    -- 1. Try exact match first (fastest, O(1) lookup)
    local endpoint_id = match_exact(normalized_path, request_method)
    if endpoint_id then
        return endpoint_id, MATCH_TYPE.EXACT
    end

    -- 2. Try prefix match (sorted by specificity)
    endpoint_id = match_prefix(normalized_path, request_method)
    if endpoint_id then
        return endpoint_id, MATCH_TYPE.PREFIX
    end

    -- 3. Try regex match (most expensive, checked last)
    endpoint_id = match_regex(normalized_path, request_method)
    if endpoint_id then
        return endpoint_id, MATCH_TYPE.REGEX
    end

    -- 4. No match found
    return nil, MATCH_TYPE.NONE
end

-- Vhost-aware matching function
-- Tries vhost-specific endpoints first, then falls back to global
-- Returns: endpoint_id, match_type, scope ("vhost" or "global" or nil)
function _M.match_with_vhost(path, method, vhost_id)
    local normalized_path = normalize_path(path)
    local request_method = method or ngx.req.get_method()

    -- 1. Try vhost-specific endpoints first (if vhost_id provided)
    if vhost_id and vhost_id ~= "" then
        -- 1a. Try vhost-specific exact match
        local endpoint_id = match_vhost_exact(normalized_path, request_method, vhost_id)
        if endpoint_id then
            return endpoint_id, MATCH_TYPE.EXACT, "vhost"
        end

        -- 1b. Try vhost-specific prefix match
        endpoint_id = match_vhost_prefix(normalized_path, request_method, vhost_id)
        if endpoint_id then
            return endpoint_id, MATCH_TYPE.PREFIX, "vhost"
        end

        -- 1c. Try vhost-specific regex match
        endpoint_id = match_vhost_regex(normalized_path, request_method, vhost_id)
        if endpoint_id then
            return endpoint_id, MATCH_TYPE.REGEX, "vhost"
        end
    end

    -- 2. Fall back to global endpoints
    local endpoint_id, match_type = _M.match(path, method)
    if endpoint_id then
        return endpoint_id, match_type, "global"
    end

    -- 3. No match found
    return nil, MATCH_TYPE.NONE, nil
end

-- Get endpoint configuration by ID
-- Returns: endpoint config table or nil
function _M.get_config(endpoint_id)
    if not endpoint_id then
        return nil
    end

    local cache_key = "config:" .. endpoint_id
    local cached = endpoint_cache:get(cache_key)

    if cached then
        return cjson.decode(cached)
    end

    return nil
end

-- Check if an endpoint is enabled
function _M.is_enabled(endpoint_id)
    local config = _M.get_config(endpoint_id)
    if not config then
        return true  -- Default: enabled if no config
    end
    return config.enabled ~= false
end

-- Get endpoint mode
function _M.get_mode(endpoint_id)
    local config = _M.get_config(endpoint_id)
    if not config then
        return MODE.BLOCKING  -- Default mode
    end
    return config.mode or MODE.BLOCKING
end

-- Update cache from Redis data (called by redis_sync)
function _M.update_cache(cache_type, data, ttl)
    local actual_ttl = ttl or CACHE_TTL

    if cache_type == "endpoint_index" then
        endpoint_cache:set("endpoint_index", data, actual_ttl)
    elseif cache_type == "exact_paths" then
        endpoint_cache:set("exact_paths", data, actual_ttl)
    elseif cache_type == "prefix_patterns" then
        endpoint_cache:set("prefix_patterns", data, actual_ttl)
    elseif cache_type == "regex_patterns" then
        endpoint_cache:set("regex_patterns", data, actual_ttl)
    elseif cache_type:match("^config:") then
        endpoint_cache:set(cache_type, data, actual_ttl)
    elseif cache_type:match("^vhost_endpoint_index:") then
        endpoint_cache:set(cache_type, data, actual_ttl)
    elseif cache_type:match("^vhost_exact_paths:") then
        endpoint_cache:set(cache_type, data, actual_ttl)
    elseif cache_type:match("^vhost_prefix_patterns:") then
        endpoint_cache:set(cache_type, data, actual_ttl)
    elseif cache_type:match("^vhost_regex_patterns:") then
        endpoint_cache:set(cache_type, data, actual_ttl)
    end
end

-- Store endpoint configuration in cache
function _M.cache_config(endpoint_id, config, ttl)
    local actual_ttl = ttl or CACHE_TTL
    local cache_key = "config:" .. endpoint_id
    local json_data = cjson.encode(config)

    if json_data then
        endpoint_cache:set(cache_key, json_data, actual_ttl)
        return true
    end

    return false
end

-- Get all cached endpoint IDs
function _M.get_all_endpoint_ids()
    return get_endpoint_index()
end

-- Clear all endpoint cache
function _M.clear_cache()
    endpoint_cache:flush_all()
end

-- Get cache statistics
function _M.get_stats()
    local index = get_endpoint_index()
    local exact = get_exact_paths()
    local prefixes = get_prefix_patterns()
    local regexes = get_regex_patterns()

    local exact_count = 0
    for _ in pairs(exact) do
        exact_count = exact_count + 1
    end

    return {
        endpoints = #index,
        exact_paths = exact_count,
        prefix_patterns = #prefixes,
        regex_patterns = #regexes
    }
end

-- Validate endpoint configuration
function _M.validate_config(config)
    local errors = {}

    -- Required: id
    if not config.id or config.id == "" then
        table.insert(errors, "id is required")
    elseif config.id:match("[^a-zA-Z0-9_-]") then
        table.insert(errors, "id must contain only alphanumeric characters, dashes, and underscores")
    end

    -- Required: at least one path matching rule
    if not config.matching then
        table.insert(errors, "matching configuration is required")
    else
        local has_paths = config.matching.paths and #config.matching.paths > 0
        local has_prefix = config.matching.path_prefix and config.matching.path_prefix ~= ""
        local has_regex = config.matching.path_regex and config.matching.path_regex ~= ""

        if not has_paths and not has_prefix and not has_regex then
            table.insert(errors, "at least one path matching rule is required (paths, path_prefix, or path_regex)")
        end

        -- Validate regex if provided
        if has_regex then
            local ok, err = pcall(ngx.re.match, "", config.matching.path_regex)
            if not ok then
                table.insert(errors, "invalid regex pattern: " .. tostring(err))
            end
        end
    end

    -- Validate mode if provided
    if config.mode then
        local valid_modes = {blocking = true, monitoring = true, passthrough = true, strict = true}
        if not valid_modes[config.mode] then
            table.insert(errors, "invalid mode: must be one of blocking, monitoring, passthrough, strict")
        end
    end

    -- Validate thresholds if provided
    if config.thresholds then
        if config.thresholds.spam_score_block then
            local score = tonumber(config.thresholds.spam_score_block)
            if not score or score < 1 or score > 1000 then
                table.insert(errors, "spam_score_block must be between 1 and 1000")
            end
        end
        if config.thresholds.spam_score_flag then
            local score = tonumber(config.thresholds.spam_score_flag)
            if not score or score < 1 or score > 1000 then
                table.insert(errors, "spam_score_flag must be between 1 and 1000")
            end
        end
        if config.thresholds.ip_rate_limit then
            local limit = tonumber(config.thresholds.ip_rate_limit)
            if not limit or limit < 1 or limit > 10000 then
                table.insert(errors, "ip_rate_limit must be between 1 and 10000")
            end
        end
    end

    return #errors == 0, errors
end

return _M
