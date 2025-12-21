-- fingerprint_profiles.lua
-- Customizable fingerprint profiles for client detection and fingerprint generation
-- Supports built-in and custom profiles with configurable matching conditions and actions

local _M = {}

local cjson = require "cjson.safe"
local resty_sha256 = require "resty.sha256"
local resty_string = require "resty.string"

-- LRU cache for compiled regex patterns
local lrucache = require "resty.lrucache"
local regex_cache, err = lrucache.new(100)
if not regex_cache then
    ngx.log(ngx.ERR, "Failed to create regex cache: ", err)
end

-- Shared dictionary for profile data
local config_cache = ngx.shared.config_cache

-- Cache keys
local CACHE_KEY_PROFILES = "fingerprint_profiles:all"
local CACHE_KEY_PROFILE_PREFIX = "fingerprint_profiles:config:"

-- Built-in profiles definitions
-- These are initialized in Redis if no profiles exist
-- Priority: lower number = higher priority (evaluated first)
local BUILTIN_PROFILES = {
    -- Priority 50: Known good bots (search engines) - ignore WAF checks
    {
        id = "known-bot",
        name = "Known Bot",
        description = "Known search engine and service crawlers (Googlebot, Bingbot, etc.)",
        enabled = true,
        builtin = true,
        priority = 50,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "matches", pattern = "(?i)(googlebot|bingbot|slurp|duckduckbot|baiduspider|yandexbot|facebookexternalhit|twitterbot|linkedinbot|applebot)" },
            },
            match_mode = "any"
        },
        fingerprint_headers = {
            headers = {"User-Agent"},
            normalize = true,
            max_length = 100,
            include_field_names = true
        },
        action = "ignore",
        score = 0,
        rate_limiting = {
            enabled = false
        }
    },
    -- Priority 100: Modern browsers with full headers
    {
        id = "modern-browser",
        name = "Modern Browser",
        description = "Standard desktop/laptop browser with full header set",
        enabled = true,
        builtin = true,
        priority = 100,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "present" },
                { header = "Accept-Language", condition = "present" },
                { header = "Accept-Encoding", condition = "matches", pattern = "gzip" },
            },
            match_mode = "all"
        },
        fingerprint_headers = {
            headers = {"User-Agent", "Accept-Language", "Accept-Encoding"},
            normalize = true,
            max_length = 100,
            include_field_names = true
        },
        action = "allow",
        score = 0,
        rate_limiting = {
            enabled = true
        }
    },
    -- Priority 120: Headless browsers / automation tools
    {
        id = "headless-browser",
        name = "Headless Browser",
        description = "Headless Chrome, Puppeteer, Playwright, PhantomJS automation",
        enabled = true,
        builtin = true,
        priority = 120,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "matches", pattern = "(?i)(headlesschrome|phantomjs|puppeteer|playwright|selenium|webdriver)" },
            },
            match_mode = "any"
        },
        fingerprint_headers = {
            headers = {"User-Agent", "Accept-Language"},
            normalize = true,
            max_length = 100,
            include_field_names = true
        },
        action = "flag",
        score = 25,
        rate_limiting = {
            enabled = true,
            fingerprint_rate_limit = 10
        }
    },
    -- Priority 150: Suspicious bots (curl, wget, scripts)
    {
        id = "suspicious-bot",
        name = "Suspicious Bot",
        description = "Command-line tools and scripting libraries (curl, wget, python-requests, etc.)",
        enabled = true,
        builtin = true,
        priority = 150,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "matches", pattern = "(?i)(curl|wget|python-requests|python-urllib|java|httpclient|okhttp|axios|node-fetch|go-http-client|ruby|perl|libwww)" },
            },
            match_mode = "any"
        },
        fingerprint_headers = {
            headers = {"User-Agent"},
            normalize = true,
            max_length = 100,
            include_field_names = true
        },
        action = "flag",
        score = 30,
        rate_limiting = {
            enabled = true,
            fingerprint_rate_limit = 5
        }
    },
    -- Priority 200: Legacy browsers with minimal headers
    {
        id = "legacy-browser",
        name = "Legacy Browser",
        description = "Older browsers or browsers with reduced header set",
        enabled = true,
        builtin = true,
        priority = 200,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "present" },
                { header = "Accept-Language", condition = "absent" },
            },
            match_mode = "all"
        },
        fingerprint_headers = {
            headers = {"User-Agent"},
            normalize = true,
            max_length = 100,
            include_field_names = true
        },
        action = "allow",
        score = 5,
        rate_limiting = {
            enabled = true
        }
    },
    -- Priority 300: No User-Agent at all (highly suspicious)
    {
        id = "no-user-agent",
        name = "No User-Agent",
        description = "Requests missing User-Agent header entirely",
        enabled = true,
        builtin = true,
        priority = 300,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "absent" },
            },
            match_mode = "all"
        },
        fingerprint_headers = {
            headers = {},
            normalize = true,
            include_field_names = true
        },
        action = "flag",
        score = 40,
        rate_limiting = {
            enabled = true,
            fingerprint_rate_limit = 3
        }
    }
}

-- Export built-in profiles for initialization
_M.BUILTIN_PROFILES = BUILTIN_PROFILES

-- Get or compile a regex pattern (cached)
local function get_compiled_pattern(pattern)
    if not pattern or pattern == "" then
        return nil
    end

    if regex_cache then
        local cached = regex_cache:get(pattern)
        if cached then
            return cached
        end
    end

    -- Test compile the pattern
    local _, err = ngx.re.match("test", pattern, "jo")
    if err then
        ngx.log(ngx.WARN, "Invalid regex pattern: ", pattern, " error: ", err)
        return nil
    end

    -- Cache and return the pattern string (ngx.re will compile internally)
    if regex_cache then
        regex_cache:set(pattern, pattern)
    end

    return pattern
end

-- Get header value from nginx variables
local function get_header_value(ngx_vars, header_name)
    -- Convert header name to nginx variable format
    -- e.g., "User-Agent" -> "http_user_agent"
    local var_name = "http_" .. header_name:lower():gsub("-", "_")
    return ngx_vars[var_name]
end

-- Check a single condition against request headers
local function check_condition(condition, ngx_vars)
    local header_value = get_header_value(ngx_vars, condition.header)

    if condition.condition == "present" then
        return header_value ~= nil and header_value ~= ""

    elseif condition.condition == "absent" then
        return header_value == nil or header_value == ""

    elseif condition.condition == "matches" then
        if not header_value or header_value == "" then
            return false
        end
        local pattern = get_compiled_pattern(condition.pattern)
        if not pattern then
            return false
        end
        local match = ngx.re.match(header_value, pattern, "jo")
        return match ~= nil

    elseif condition.condition == "not_matches" then
        if not header_value or header_value == "" then
            return true  -- No value, so it doesn't match the pattern
        end
        local pattern = get_compiled_pattern(condition.pattern)
        if not pattern then
            return true
        end
        local match = ngx.re.match(header_value, pattern, "jo")
        return match == nil
    end

    return false
end

-- Check if a profile matches the request
local function profile_matches(profile, ngx_vars)
    if not profile.enabled then
        return false
    end

    local conditions = profile.matching and profile.matching.conditions
    if not conditions or #conditions == 0 then
        -- No conditions = always match
        return true
    end

    local match_mode = profile.matching.match_mode or "all"

    for _, condition in ipairs(conditions) do
        local matched = check_condition(condition, ngx_vars)

        if match_mode == "any" and matched then
            return true
        end

        if match_mode == "all" and not matched then
            return false
        end
    end

    -- For "all" mode, we got here meaning all conditions matched
    -- For "any" mode, we got here meaning no conditions matched
    return match_mode == "all"
end

-- Get all profiles from cache
function _M.get_all_profiles()
    local cached = config_cache:get(CACHE_KEY_PROFILES)
    if cached then
        return cjson.decode(cached) or {}
    end
    return {}
end

-- Get a specific profile by ID
function _M.get_profile(id)
    local cached = config_cache:get(CACHE_KEY_PROFILE_PREFIX .. id)
    if cached then
        return cjson.decode(cached)
    end
    return nil
end

-- Cache a profile
function _M.cache_profile(id, profile, ttl)
    ttl = ttl or 120
    local json = cjson.encode(profile)
    if json then
        config_cache:set(CACHE_KEY_PROFILE_PREFIX .. id, json, ttl)
    end
end

-- Cache all profiles (sorted by priority)
function _M.cache_all_profiles(profiles, ttl)
    ttl = ttl or 120

    -- Sort by priority (lower = higher priority)
    table.sort(profiles, function(a, b)
        return (a.priority or 1000) < (b.priority or 1000)
    end)

    local json = cjson.encode(profiles)
    if json then
        config_cache:set(CACHE_KEY_PROFILES, json, ttl)
    end

    -- Also cache individual profiles
    for _, profile in ipairs(profiles) do
        _M.cache_profile(profile.id, profile, ttl)
    end
end

-- Match profiles against request headers
-- Returns: array of matched profiles (sorted by priority)
function _M.match_profiles(ngx_vars, profile_ids)
    local matched = {}

    -- Get profiles to check
    local profiles
    if profile_ids and #profile_ids > 0 then
        -- Use specific profiles
        profiles = {}
        for _, id in ipairs(profile_ids) do
            local profile = _M.get_profile(id)
            if profile then
                table.insert(profiles, profile)
            end
        end
    else
        -- Use all enabled profiles
        profiles = _M.get_all_profiles()
    end

    -- Check each profile
    for _, profile in ipairs(profiles) do
        if profile_matches(profile, ngx_vars) then
            table.insert(matched, profile)
        end
    end

    -- Sort by priority (lower = higher priority)
    table.sort(matched, function(a, b)
        return (a.priority or 1000) < (b.priority or 1000)
    end)

    return matched
end

-- Aggregate actions from matched profiles
-- Returns: { blocked, ignored, total_score, flags, fingerprint_profile, matched_profiles }
function _M.aggregate_actions(matched_profiles, no_match_config)
    local result = {
        blocked = false,
        ignored = false,
        total_score = 0,
        flags = {},
        fingerprint_profile = nil,
        matched_profile_ids = {},
        fingerprint_rate_limit = nil
    }

    -- Handle no profiles matched
    if #matched_profiles == 0 then
        if no_match_config then
            if no_match_config.no_match_action == "flag" then
                result.total_score = no_match_config.no_match_score or 15
                table.insert(result.flags, "fp_no_profile_match")
            end
            -- "use_default" and "allow" don't add score
        end
        return result
    end

    -- First matched profile (highest priority) determines fingerprint generation
    result.fingerprint_profile = matched_profiles[1]

    -- Get fingerprint rate limit from first profile
    if result.fingerprint_profile.rate_limiting then
        result.fingerprint_rate_limit = result.fingerprint_profile.rate_limiting.fingerprint_rate_limit
    end

    -- Aggregate actions from all matched profiles
    for _, profile in ipairs(matched_profiles) do
        table.insert(result.matched_profile_ids, profile.id)

        if profile.action == "block" then
            result.blocked = true
            table.insert(result.flags, "fp_block:" .. profile.id)

        elseif profile.action == "flag" then
            result.total_score = result.total_score + (profile.score or 0)
            table.insert(result.flags, "fp_flag:" .. profile.id)

        elseif profile.action == "ignore" then
            result.ignored = true
            table.insert(result.flags, "fp_ignore:" .. profile.id)

        -- "allow" action: no score added, just uses profile for fingerprinting
        end
    end

    return result
end

-- Generate fingerprint using profile configuration
-- Falls back to legacy behavior if no profile provided
function _M.generate_fingerprint(form_data, ngx_vars, profile)
    local sha256 = resty_sha256:new()
    if not sha256 then
        return nil
    end

    -- Default configuration (legacy behavior)
    local config = {
        headers = {"User-Agent", "Accept-Language", "Accept-Encoding"},
        normalize = true,
        max_length = 100,
        include_field_names = true
    }

    -- Override with profile configuration if provided
    if profile and profile.fingerprint_headers then
        local fp_config = profile.fingerprint_headers
        if fp_config.headers then
            config.headers = fp_config.headers
        end
        if fp_config.normalize ~= nil then
            config.normalize = fp_config.normalize
        end
        if fp_config.max_length then
            config.max_length = fp_config.max_length
        end
        if fp_config.include_field_names ~= nil then
            config.include_field_names = fp_config.include_field_names
        end
    end

    local components = {}

    -- Add configured headers to fingerprint
    for _, header_name in ipairs(config.headers) do
        local value = get_header_value(ngx_vars, header_name) or ""

        if config.normalize then
            value = value:lower():gsub("%s+", " ")
        end

        value = value:sub(1, config.max_length)
        table.insert(components, value)
    end

    -- Add form field names if configured
    if config.include_field_names and form_data then
        local fields = {}
        for field_name, _ in pairs(form_data) do
            if type(field_name) == "string" then
                table.insert(fields, field_name)
            end
        end
        table.sort(fields)
        table.insert(components, table.concat(fields, ","))
    end

    -- Generate hash
    sha256:update(table.concat(components, "|"))
    local digest = sha256:final()

    -- Return first 16 characters of hex hash
    return resty_string.to_hex(digest):sub(1, 16)
end

-- Process fingerprinting for a request
-- Main entry point that combines matching, action aggregation, and fingerprint generation
function _M.process_request(form_data, ngx_vars, fp_config)
    -- Default configuration
    fp_config = fp_config or {
        enabled = true,
        profiles = nil,
        no_match_action = "use_default",
        no_match_score = 15
    }

    -- Check if fingerprinting is disabled
    if fp_config.enabled == false then
        return {
            fingerprint = nil,
            profile_id = nil,
            matched_profile_ids = {},
            score = 0,
            flags = {},
            blocked = false,
            ignored = true,
            fingerprint_rate_limit = nil
        }
    end

    -- Match profiles against request
    local matched_profiles = _M.match_profiles(ngx_vars, fp_config.profiles)

    -- Aggregate actions
    local action_result = _M.aggregate_actions(matched_profiles, fp_config)

    -- Generate fingerprint (unless ignored)
    local fingerprint = nil
    if not action_result.ignored then
        fingerprint = _M.generate_fingerprint(form_data, ngx_vars, action_result.fingerprint_profile)
    end

    return {
        fingerprint = fingerprint,
        profile_id = action_result.fingerprint_profile and action_result.fingerprint_profile.id or nil,
        matched_profile_ids = action_result.matched_profile_ids,
        score = action_result.total_score,
        flags = action_result.flags,
        blocked = action_result.blocked,
        ignored = action_result.ignored,
        fingerprint_rate_limit = action_result.fingerprint_rate_limit
    }
end

return _M
