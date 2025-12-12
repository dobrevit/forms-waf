-- keyword_filter.lua
-- Redis-backed keyword filtering and pattern matching

local _M = {}

local form_parser = require "form_parser"

-- Shared dictionaries for caching
local keyword_cache = ngx.shared.keyword_cache
local hash_cache = ngx.shared.hash_cache

-- Cache TTL in seconds
local CACHE_TTL = 60

-- Default patterns for common spam indicators
local DEFAULT_PATTERNS = {
    -- URLs and links
    {pattern = "https?://[%w%.%-]+%.[%w]+", score = 10, flag = "url"},
    {pattern = "%[url[=%]]", score = 20, flag = "bbcode_url"},
    {pattern = "<a%s+href", score = 20, flag = "html_link"},

    -- Email addresses in content (often spam)
    {pattern = "[%w%.%-]+@[%w%.%-]+%.[%w]+", score = 5, flag = "email"},

    -- Excessive caps (shouting)
    {pattern = "[A-Z][A-Z][A-Z][A-Z][A-Z]+", score = 5, flag = "caps"},

    -- Phone numbers (often spam)
    {pattern = "%+?%d[%d%s%-%.]+%d%d%d", score = 3, flag = "phone"},

    -- Crypto wallet addresses
    {pattern = "0x[a-fA-F0-9]{40}", score = 15, flag = "eth_wallet"},
    {pattern = "[13][a-km-zA-HJ-NP-Z1-9]{25,34}", score = 15, flag = "btc_wallet"},

    -- Repetitive characters
    {pattern = "(.)%1%1%1%1+", score = 5, flag = "repetitive"},

    -- HTML/script injection attempts
    {pattern = "<script", score = 30, flag = "xss_script"},
    {pattern = "javascript:", score = 30, flag = "xss_js"},
    {pattern = "on%w+%s*=", score = 20, flag = "xss_event"},
}

-- Get blocked keywords from cache
local function get_blocked_keywords()
    local cached = keyword_cache:get("blocked_keywords")
    if cached then
        local keywords = {}
        for kw in cached:gmatch("[^|]+") do
            keywords[kw:lower()] = true
        end
        return keywords
    end
    return {}
end

-- Get flagged keywords from cache (keywords that add to spam score)
local function get_flagged_keywords()
    local cached = keyword_cache:get("flagged_keywords")
    if cached then
        local keywords = {}
        for entry in cached:gmatch("[^|]+") do
            local kw, score = entry:match("([^:]+):?(%d*)")
            if kw then
                keywords[kw:lower()] = tonumber(score) or 10
            end
        end
        return keywords
    end
    return {}
end

-- Get blocked hashes from cache
local function get_blocked_hashes()
    local cached = hash_cache:get("blocked_hashes")
    if cached then
        local hashes = {}
        for h in cached:gmatch("[^|]+") do
            hashes[h:lower()] = true
        end
        return hashes
    end
    return {}
end

-- Check if text contains a keyword (word boundary aware)
local function contains_keyword(text, keyword)
    if not text or not keyword then
        return false
    end

    -- Escape special Lua pattern characters in keyword
    local escaped = keyword:gsub("([%(%)%.%%%+%-%*%?%[%]%^%$])", "%%%1")

    -- Check with word boundaries
    local pattern = "%f[%w]" .. escaped .. "%f[%W]"

    return text:lower():find(pattern) ~= nil
end

-- Scan form data for keywords
function _M.scan(form_data)
    local result = {
        score = 0,
        blocked_keywords = {},
        flagged_keywords = {}
    }

    if not form_data then
        return result
    end

    -- Get combined text from form
    local combined_text = form_parser.get_combined_text(form_data)
    if not combined_text or combined_text == "" then
        return result
    end

    combined_text = combined_text:lower()

    -- Check blocked keywords
    local blocked = get_blocked_keywords()
    for keyword, _ in pairs(blocked) do
        if contains_keyword(combined_text, keyword) then
            table.insert(result.blocked_keywords, keyword)
        end
    end

    -- Check flagged keywords
    local flagged = get_flagged_keywords()
    for keyword, score in pairs(flagged) do
        if contains_keyword(combined_text, keyword) then
            table.insert(result.flagged_keywords, keyword)
            result.score = result.score + score
        end
    end

    return result
end

-- Check if a hash is blocked
function _M.is_hash_blocked(hash)
    if not hash then
        return false
    end

    local blocked = get_blocked_hashes()
    return blocked[hash:lower()] == true
end

-- Scan for patterns (regex-like matching)
function _M.pattern_scan(form_data)
    local result = {
        score = 0,
        flags = {}
    }

    if not form_data then
        return result
    end

    local combined_text = form_parser.get_combined_text(form_data)
    if not combined_text or combined_text == "" then
        return result
    end

    -- Check each pattern
    for _, pattern_def in ipairs(DEFAULT_PATTERNS) do
        local matches = {}
        for match in combined_text:gmatch(pattern_def.pattern) do
            table.insert(matches, match)
        end

        if #matches > 0 then
            -- Score increases with number of matches
            local pattern_score = pattern_def.score * math.min(#matches, 5)
            result.score = result.score + pattern_score
            table.insert(result.flags, pattern_def.flag .. ":" .. #matches)
        end
    end

    -- Check for excessive URL count
    local url_count = 0
    for _ in combined_text:gmatch("https?://") do
        url_count = url_count + 1
    end
    if url_count > 3 then
        result.score = result.score + (url_count - 3) * 10
        table.insert(result.flags, "many_urls:" .. url_count)
    end

    -- Check content length anomalies
    local text_length = #combined_text
    if text_length > 5000 then
        result.score = result.score + 10
        table.insert(result.flags, "long_content")
    end

    -- Check for very short submissions with URLs (often spam)
    if text_length < 100 and url_count > 0 then
        result.score = result.score + 15
        table.insert(result.flags, "short_with_url")
    end

    return result
end

-- Update cache from Redis data (called by redis_sync)
function _M.update_cache(cache_type, data)
    if cache_type == "blocked_keywords" then
        keyword_cache:set("blocked_keywords", data, CACHE_TTL * 2)
    elseif cache_type == "flagged_keywords" then
        keyword_cache:set("flagged_keywords", data, CACHE_TTL * 2)
    elseif cache_type == "blocked_hashes" then
        hash_cache:set("blocked_hashes", data, CACHE_TTL * 2)
    end
end

-- Get current cache stats
function _M.get_stats()
    return {
        blocked_keywords = keyword_cache:get("blocked_keywords") and "loaded" or "empty",
        flagged_keywords = keyword_cache:get("flagged_keywords") and "loaded" or "empty",
        blocked_hashes = hash_cache:get("blocked_hashes") and "loaded" or "empty",
    }
end

return _M
