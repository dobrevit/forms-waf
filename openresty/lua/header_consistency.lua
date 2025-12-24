-- header_consistency.lua
-- UA/header consistency validation for bot detection
-- Uses lua-resty-woothee for accurate User-Agent parsing
-- Checks that browser headers match expected patterns for claimed browser

local _M = {}

-- Load woothee UA parser (installed via luarocks)
local woothee_ok, woothee = pcall(require, "resty.woothee")
if not woothee_ok then
    ngx.log(ngx.WARN, "lua-resty-woothee not available, header consistency checks disabled")
    woothee = nil
end

-- Map woothee browser names to our internal family names
local BROWSER_FAMILY_MAP = {
    ["Chrome"] = "chrome",
    ["Firefox"] = "firefox",
    ["Safari"] = "safari",
    ["Edge"] = "edge",
    ["Opera"] = "opera",
    ["Internet Explorer"] = "ie",
    ["Chromium"] = "chrome",
    ["Vivaldi"] = "chrome",  -- Chromium-based
    ["Brave"] = "chrome",    -- Chromium-based
    ["Samsung Internet"] = "chrome",  -- Chromium-based
    ["Yandex Browser"] = "chrome",    -- Chromium-based
}

-- Map woothee categories to our internal categories
local CATEGORY_MAP = {
    ["pc"] = "desktop",
    ["smartphone"] = "mobile",
    ["mobilephone"] = "mobile",
    ["crawler"] = "bot",
    ["appliance"] = "other",
    ["misc"] = "other",
    ["UNKNOWN"] = "unknown",
}

-- Expected header profiles per browser family
-- Based on actual browser behavior in 2024/2025
local BROWSER_EXPECTATIONS = {
    chrome = {
        -- Required headers for Chrome
        required = { "Accept-Language", "Accept-Encoding" },
        -- Modern required headers (Chrome 76+)
        modern_version = 76,
        modern_required = { "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-Dest" },
        -- Accept-Encoding should include modern compression
        encoding_pattern = "gzip",
        -- Accept header patterns for navigation
        accept_pattern = "text/html",
    },
    firefox = {
        required = { "Accept-Language", "Accept-Encoding" },
        -- Firefox added Sec-Fetch in v90
        modern_version = 90,
        modern_required = { "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-Dest" },
        encoding_pattern = "gzip",
        accept_pattern = "text/html",
    },
    safari = {
        required = { "Accept-Language", "Accept-Encoding" },
        -- Safari 15+ has Sec-Fetch
        modern_version = 15,
        modern_required = { "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-Dest" },
        encoding_pattern = "gzip",
        accept_pattern = "text/html",
    },
    edge = {
        -- Edge (Chromium) behaves like Chrome
        required = { "Accept-Language", "Accept-Encoding" },
        modern_version = 79,
        modern_required = { "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-Dest" },
        encoding_pattern = "gzip",
        accept_pattern = "text/html",
    },
    opera = {
        -- Opera (Chromium) behaves like Chrome
        required = { "Accept-Language", "Accept-Encoding" },
        modern_version = 66,
        modern_required = { "Sec-Fetch-Mode", "Sec-Fetch-Site", "Sec-Fetch-Dest" },
        encoding_pattern = "gzip",
        accept_pattern = "text/html",
    },
    ie = {
        -- Internet Explorer (legacy, minimal expectations)
        required = {},
        modern_version = nil,
        modern_required = {},
        encoding_pattern = nil,
        accept_pattern = nil,
    },
}

-- Suspicion scores for various inconsistencies
local SUSPICION_SCORES = {
    missing_required_header = 15,      -- Missing Accept-Language, etc.
    missing_sec_fetch = 30,            -- Modern browser without Sec-Fetch
    accept_encoding_mismatch = 10,     -- Unusual Accept-Encoding
    generic_accept = 20,               -- Browser with Accept: */*
    mobile_desktop_mismatch = 15,      -- Mobile UA with desktop behavior
}

-- Get header value from nginx variables
local function get_header(ngx_vars, header_name)
    local var_name = "http_" .. header_name:lower():gsub("-", "_")
    return ngx_vars[var_name]
end

-- Parse User-Agent using woothee
-- Returns: { family, category, version, os, os_version, vendor, raw_name }
function _M.parse_ua(ua)
    if not ua or ua == "" then
        return {
            family = "unknown",
            category = "unknown",
            version = nil,
            os = nil,
            os_version = nil,
            vendor = nil,
            raw_name = nil,
        }
    end

    -- If woothee not available, return unknown
    if not woothee then
        return {
            family = "unknown",
            category = "unknown",
            version = nil,
            os = ua,
            os_version = nil,
            vendor = nil,
            raw_name = nil,
        }
    end

    local result = woothee.parse(ua)

    -- Map browser name to family
    local family = BROWSER_FAMILY_MAP[result.name] or "unknown"

    -- Map category
    local category = CATEGORY_MAP[result.category] or "unknown"

    -- Extract numeric version
    local version = nil
    if result.version and result.version ~= "UNKNOWN" then
        version = tonumber(result.version:match("^(%d+)"))
    end

    return {
        family = family,
        category = category,
        version = version,
        os = result.os,
        os_version = result.os_version,
        vendor = result.vendor,
        raw_name = result.name,
    }
end

-- Check if UA is a known crawler
function _M.is_crawler(ua)
    if not woothee then
        return false
    end
    return woothee.is_crawler(ua)
end

-- Legacy compatibility: detect browser family from UA
function _M.detect_browser_family(ua)
    local parsed = _M.parse_ua(ua)
    return parsed.family, ua
end

-- Legacy compatibility: extract browser version
function _M.extract_version(ua, family)
    local parsed = _M.parse_ua(ua)
    return parsed.version
end

-- Check if UA claims to be a mobile device
function _M.is_mobile_ua(ua)
    local parsed = _M.parse_ua(ua)
    return parsed.category == "mobile"
end

-- Check header consistency and return suspicion score + flags
function _M.check_consistency(ngx_vars)
    local suspicion = 0
    local flags = {}

    local ua = get_header(ngx_vars, "User-Agent")
    if not ua or ua == "" then
        -- No UA is already handled by fingerprint profiles
        return 0, {}
    end

    -- Parse UA using woothee
    local parsed = _M.parse_ua(ua)

    -- Crawlers and unknown UAs don't need consistency checks
    if parsed.category == "bot" or parsed.family == "unknown" then
        return 0, {}
    end

    local expectations = BROWSER_EXPECTATIONS[parsed.family]
    if not expectations then
        return 0, {}
    end

    -- Check required headers
    for _, header in ipairs(expectations.required or {}) do
        local value = get_header(ngx_vars, header)
        if not value or value == "" then
            suspicion = suspicion + SUSPICION_SCORES.missing_required_header
            table.insert(flags, "hc_missing:" .. header:lower())
        end
    end

    -- Check modern headers for modern browser versions
    if expectations.modern_version and expectations.modern_required then
        if parsed.version and parsed.version >= expectations.modern_version then
            for _, header in ipairs(expectations.modern_required) do
                local value = get_header(ngx_vars, header)
                if not value or value == "" then
                    suspicion = suspicion + SUSPICION_SCORES.missing_sec_fetch
                    table.insert(flags, "hc_missing_modern:" .. header:lower())
                    -- Only count missing Sec-Fetch once (highest impact)
                    break
                end
            end
        end
    end

    -- Check Accept-Encoding pattern
    if expectations.encoding_pattern then
        local encoding = get_header(ngx_vars, "Accept-Encoding")
        if encoding then
            if not ngx.re.match(encoding, expectations.encoding_pattern, "ijo") then
                suspicion = suspicion + SUSPICION_SCORES.accept_encoding_mismatch
                table.insert(flags, "hc_encoding_mismatch")
            end
        end
    end

    -- Check for generic Accept header (browsers are specific)
    local accept = get_header(ngx_vars, "Accept")
    if accept then
        -- Check if Accept is just */* (typical of bots/scripts)
        if ngx.re.match(accept, "^\\s*\\*/\\*\\s*$", "jo") then
            suspicion = suspicion + SUSPICION_SCORES.generic_accept
            table.insert(flags, "hc_generic_accept")
        end
    end

    -- Check mobile UA vs headers mismatch
    if parsed.category == "mobile" then
        -- Mobile browsers should have Sec-CH-UA-Mobile or similar hints
        local sec_ch_mobile = get_header(ngx_vars, "Sec-CH-UA-Mobile")
        local sec_ch_platform = get_header(ngx_vars, "Sec-CH-UA-Platform")

        -- If claiming Chrome 90+ mobile, should have client hints
        if parsed.family == "chrome" and parsed.version and parsed.version >= 90 then
            if not sec_ch_mobile and not sec_ch_platform then
                -- Don't add score, but flag for monitoring
                -- Many legitimate mobile browsers may not send these
                table.insert(flags, "hc_mobile_no_hints")
            end
        end
    end

    return suspicion, flags
end

-- Full analysis result with detailed breakdown
function _M.analyze(ngx_vars)
    local ua = get_header(ngx_vars, "User-Agent")
    local parsed = _M.parse_ua(ua)
    local suspicion, flags = _M.check_consistency(ngx_vars)

    return {
        browser_family = parsed.family,
        browser_name = parsed.raw_name,
        browser_version = parsed.version,
        os = parsed.os,
        os_version = parsed.os_version,
        category = parsed.category,
        is_mobile = parsed.category == "mobile",
        is_crawler = parsed.category == "bot",
        suspicion_score = suspicion,
        flags = flags,
    }
end

return _M
