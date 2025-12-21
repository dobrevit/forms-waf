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
    -- Priority 45: Monitoring and uptime bots - ignore WAF checks
    {
        id = "monitoring-bot",
        name = "Monitoring Bot",
        description = "Uptime monitoring services (Pingdom, UptimeRobot, etc.)",
        enabled = true,
        builtin = true,
        priority = 45,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "matches", pattern = "(?i)(pingdom|uptimerobot|statuscake|newrelic|datadog|site24x7|freshping|nodeping|statuspage|pagerduty|opsgenie|deadmanssnitch|healthchecks\\.io|better.uptime|checkly)" },
            },
            match_mode = "any"
        },
        fingerprint_headers = {
            headers = {"User-Agent"},
            normalize = true,
            max_length = 100
        },
        action = "ignore",
        score = 0,
        rate_limiting = {
            enabled = false
        }
    },
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
            max_length = 100
        },
        action = "ignore",
        score = 0,
        rate_limiting = {
            enabled = false
        }
    },
    -- Priority 80: Modern browser navigation (Sec-Fetch headers present)
    {
        id = "browser-navigation",
        name = "Browser Navigation",
        description = "User-initiated browser navigation with Sec-Fetch-* headers",
        enabled = true,
        builtin = true,
        priority = 80,
        matching = {
            conditions = {
                { header = "Sec-Fetch-Mode", condition = "matches", pattern = "^navigate$" },
                { header = "Sec-Fetch-Dest", condition = "matches", pattern = "^(document|iframe)$" },
                { header = "Sec-Fetch-User", condition = "present" },
            },
            match_mode = "all"
        },
        fingerprint_headers = {
            headers = {"User-Agent", "Accept-Language", "Accept-Encoding", "Sec-Fetch-Site"},
            normalize = true,
            max_length = 100
        },
        action = "allow",
        score = 0,
        rate_limiting = {
            enabled = true
        }
    },
    -- Priority 85: Browser API/XHR fetch (Sec-Fetch with cors/no-cors)
    {
        id = "api-fetch",
        name = "API Fetch",
        description = "JavaScript fetch/XHR requests from browsers",
        enabled = true,
        builtin = true,
        priority = 85,
        matching = {
            conditions = {
                { header = "Sec-Fetch-Mode", condition = "matches", pattern = "^(cors|no-cors)$" },
                { header = "Sec-Fetch-Dest", condition = "matches", pattern = "^empty$" },
            },
            match_mode = "all"
        },
        fingerprint_headers = {
            headers = {"User-Agent", "Accept-Language", "Sec-Fetch-Site", "Origin"},
            normalize = true,
            max_length = 100
        },
        action = "allow",
        score = 0,
        rate_limiting = {
            enabled = true
        }
    },
    -- Priority 90: Mobile app native clients
    {
        id = "mobile-app",
        name = "Mobile App",
        description = "Native iOS/Android mobile application clients",
        enabled = true,
        builtin = true,
        priority = 90,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "matches", pattern = "(?i)(alamofire|cfnetwork|darwin|okhttp|retrofit|dalvik|android|" ..
                    -- iOS patterns
                    "ios|iphone|ipad|watchos|tvos|" ..
                    -- Mobile SDKs
                    "react.native|flutter|expo|cordova|ionic|capacitor|" ..
                    -- Native app patterns (app name followed by version)
                    "[a-z]+app\\/[0-9])" },
            },
            match_mode = "any"
        },
        fingerprint_headers = {
            headers = {"User-Agent", "Accept-Language"},
            normalize = true,
            max_length = 100
        },
        action = "allow",
        score = 0,
        rate_limiting = {
            enabled = true
        }
    },
    -- Priority 95: Cross-site form submission (suspicious)
    {
        id = "cross-site-form",
        name = "Cross-Site Form",
        description = "Form submission originating from a different site (potential CSRF)",
        enabled = true,
        builtin = true,
        priority = 95,
        matching = {
            conditions = {
                { header = "Sec-Fetch-Site", condition = "matches", pattern = "^cross-site$" },
                { header = "Sec-Fetch-Mode", condition = "matches", pattern = "^navigate$" },
            },
            match_mode = "all"
        },
        fingerprint_headers = {
            headers = {"User-Agent", "Origin", "Referer", "Sec-Fetch-Site"},
            normalize = true,
            max_length = 100
        },
        action = "flag",
        score = 20,
        rate_limiting = {
            enabled = true,
            fingerprint_rate_limit = 10
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
            max_length = 100
        },
        action = "allow",
        score = 0,
        rate_limiting = {
            enabled = true
        }
    },
    -- Priority 105: Fake modern browser (claims Chrome 80+ but no Sec-Fetch headers)
    {
        id = "fake-modern-browser",
        name = "Fake Modern Browser",
        description = "Claims to be Chrome 80+ but missing Sec-Fetch headers (bot spoofing)",
        enabled = true,
        builtin = true,
        priority = 105,
        matching = {
            conditions = {
                -- Chrome 80+ should have Sec-Fetch headers (introduced in Chrome 76)
                { header = "User-Agent", condition = "matches", pattern = "Chrome/([89][0-9]|1[0-2][0-9])" },
                { header = "Sec-Fetch-Mode", condition = "absent" },
            },
            match_mode = "all"
        },
        fingerprint_headers = {
            headers = {"User-Agent"},
            normalize = true,
            max_length = 100
        },
        action = "flag",
        score = 35,
        rate_limiting = {
            enabled = true,
            fingerprint_rate_limit = 8
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
            max_length = 100
        },
        action = "flag",
        score = 25,
        rate_limiting = {
            enabled = true,
            fingerprint_rate_limit = 10
        }
    },
    -- Priority 150: Suspicious bots (curl, wget, scripts, libraries)
    {
        id = "suspicious-bot",
        name = "Suspicious Bot",
        description = "Command-line tools, scripting libraries, and automated clients",
        enabled = true,
        builtin = true,
        priority = 150,
        matching = {
            conditions = {
                { header = "User-Agent", condition = "matches", pattern = "(?i)(curl|wget|" ..
                    -- Python libraries
                    "python-requests|python-urllib|aiohttp|httpx|urllib3|requests-html|scrapy|beautifulsoup|" ..
                    -- JavaScript/Node libraries
                    "axios|node-fetch|superagent|got|undici|cheerio|" ..
                    -- Java libraries
                    "java|httpclient|okhttp|apache-httpclient|spring-resttemplate|restassured|" ..
                    -- PHP libraries
                    "guzzle|guzzlehttp|symfony.*http|" ..
                    -- Go libraries
                    "go-http-client|fasthttp|go-resty|" ..
                    -- Rust libraries
                    "reqwest|hyper-client|" ..
                    -- Ruby/Perl
                    "ruby|perl|libwww|mechanize|httparty|" ..
                    -- Load testing tools
                    "jmeter|apache-jmeter|wrk|ab\\/|apachebench|bombardier|k6|locust|artillery|vegeta|" ..
                    -- API testing tools
                    "postman|insomnia|httpie|paw\\/|" ..
                    -- Generic patterns
                    "http-client|httpclient)" },
            },
            match_mode = "any"
        },
        fingerprint_headers = {
            headers = {"User-Agent"},
            normalize = true,
            max_length = 100
        },
        action = "flag",
        score = 30,
        rate_limiting = {
            enabled = true,
            fingerprint_rate_limit = 5
        }
    },
    -- Priority 160: Generic API clients (no browser headers)
    {
        id = "api-client",
        name = "API Client",
        description = "Generic API clients requesting JSON without browser headers",
        enabled = true,
        builtin = true,
        priority = 160,
        matching = {
            conditions = {
                { header = "Accept", condition = "matches", pattern = "application/json" },
                { header = "Accept-Language", condition = "absent" },
            },
            match_mode = "all"
        },
        fingerprint_headers = {
            headers = {"User-Agent", "Accept"},
            normalize = true,
            max_length = 100
        },
        action = "flag",
        score = 15,
        rate_limiting = {
            enabled = true,
            fingerprint_rate_limit = 15
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
            max_length = 100
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
            normalize = true
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
        max_length = 100
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

-- Classify request context based on headers
-- Helps detect mismatches between expected and actual request types
-- Returns: "navigation" | "api" | "asset" | "preflight" | "unknown"
function _M.classify_request_context(ngx_vars, content_type, method)
    -- Get Sec-Fetch headers (modern browsers)
    local sec_fetch_dest = get_header_value(ngx_vars, "Sec-Fetch-Dest")
    local sec_fetch_mode = get_header_value(ngx_vars, "Sec-Fetch-Mode")
    local accept = get_header_value(ngx_vars, "Accept") or ""

    -- CORS preflight check
    if method == "OPTIONS" then
        local origin = get_header_value(ngx_vars, "Origin")
        local access_control_request = get_header_value(ngx_vars, "Access-Control-Request-Method")
        if origin and access_control_request then
            return "preflight"
        end
    end

    -- If Sec-Fetch-Dest is present, use it (most reliable)
    if sec_fetch_dest then
        if sec_fetch_dest == "document" or sec_fetch_dest == "iframe" then
            return "navigation"
        elseif sec_fetch_dest == "empty" then
            -- Usually XHR/fetch API calls
            return "api"
        elseif sec_fetch_dest == "image" or sec_fetch_dest == "style" or
               sec_fetch_dest == "script" or sec_fetch_dest == "font" or
               sec_fetch_dest == "video" or sec_fetch_dest == "audio" then
            return "asset"
        end
    end

    -- If Sec-Fetch-Mode is present, use it
    if sec_fetch_mode then
        if sec_fetch_mode == "navigate" then
            return "navigation"
        elseif sec_fetch_mode == "cors" or sec_fetch_mode == "no-cors" then
            return "api"
        end
    end

    -- Fall back to Accept header analysis
    if accept:match("application/json") or accept:match("text/json") then
        return "api"
    elseif accept:match("text/html") then
        return "navigation"
    elseif accept:match("image/") or accept:match("text/css") or
           accept:match("application/javascript") or accept:match("font/") then
        return "asset"
    end

    -- Check Content-Type for request body type hints
    if content_type then
        if content_type:match("application/json") then
            return "api"
        elseif content_type:match("multipart/form%-data") or
               content_type:match("application/x%-www%-form%-urlencoded") then
            -- Form submissions are usually from navigation
            return "navigation"
        end
    end

    return "unknown"
end

-- Check for context mismatch (e.g., API headers on form submission endpoint)
-- Returns: { mismatch = bool, expected = string, actual = string, score = number }
function _M.check_context_mismatch(ngx_vars, endpoint_type, content_type, method)
    local actual = _M.classify_request_context(ngx_vars, content_type, method)

    -- Map endpoint types to expected request contexts
    local expected_map = {
        form = "navigation",
        api = "api",
        page = "navigation",
        asset = "asset",
    }

    local expected = expected_map[endpoint_type]
    if not expected then
        -- Unknown endpoint type, no mismatch check
        return { mismatch = false, expected = nil, actual = actual, score = 0 }
    end

    -- Check for mismatch
    if actual ~= "unknown" and actual ~= expected then
        -- Score based on severity
        local score = 10
        if endpoint_type == "form" and actual == "api" then
            -- API request to form endpoint is suspicious
            score = 15
        elseif endpoint_type == "api" and actual == "navigation" then
            -- Navigation request to API endpoint is unusual but less suspicious
            score = 5
        end

        return {
            mismatch = true,
            expected = expected,
            actual = actual,
            score = score,
            flag = "ctx_mismatch:" .. expected .. "/" .. actual
        }
    end

    return { mismatch = false, expected = expected, actual = actual, score = 0 }
end

return _M
