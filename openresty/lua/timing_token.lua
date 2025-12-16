-- timing_token.lua
-- Form timing token implementation using encrypted cookies
-- Detects bot submissions that are too fast (instant) or missing timing context
--
-- How it works:
-- 1. On GET requests to form pages, we set an encrypted cookie with timestamp
-- 2. On POST submissions, we read the cookie, decrypt, and calculate time delta
-- 3. Score adjustments based on timing:
--    - No cookie: +30 (direct POST without loading form)
--    - < 2 seconds: +40 (too fast for human)
--    - < 5 seconds: +20 (suspiciously fast)
--    - > 5 seconds: +0 (normal)
-- 4. Cookie is stripped before forwarding to backend

local _M = {}

local resty_aes = require "resty.aes"
local resty_random = require "resty.random"
local resty_string = require "resty.string"
local cjson = require "cjson.safe"

-- Configuration defaults
local DEFAULT_CONFIG = {
    enabled = false,
    cookie_name = "_waf_timing",
    cookie_ttl = 3600,           -- 1 hour max validity
    secret_key = nil,            -- Must be set in config (32 bytes for AES-256)
    min_time_block = 2,          -- Seconds - below this = definite bot
    min_time_flag = 5,           -- Seconds - below this = suspicious
    score_no_cookie = 30,        -- Score when no timing cookie present
    score_too_fast = 40,         -- Score when submission < min_time_block
    score_suspicious = 20,       -- Score when submission < min_time_flag
    apply_to_methods = {"POST", "PUT", "PATCH"},  -- Methods to check
    set_on_methods = {"GET"},    -- Methods that set the cookie
}

-- Module-level config cache
local config_cache = nil
local config_cache_time = 0
local CONFIG_CACHE_TTL = 60  -- Refresh config every 60 seconds

-- Get configuration from Redis or defaults
local function get_config()
    local now = ngx.now()
    if config_cache and (now - config_cache_time) < CONFIG_CACHE_TTL then
        return config_cache
    end

    -- Try to load from Redis
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    if redis then
        local config_json = redis:get("waf:config:timing_token")
        if config_json and config_json ~= ngx.null then
            local parsed = cjson.decode(config_json)
            if parsed then
                -- Merge with defaults
                for k, v in pairs(DEFAULT_CONFIG) do
                    if parsed[k] == nil then
                        parsed[k] = v
                    end
                end
                config_cache = parsed
                config_cache_time = now
                return config_cache
            end
        end
    end

    -- Use defaults
    config_cache = DEFAULT_CONFIG
    config_cache_time = now
    return config_cache
end

-- Get or generate encryption key
local function get_encryption_key()
    local config = get_config()

    if config.secret_key and #config.secret_key >= 32 then
        return config.secret_key:sub(1, 32)
    end

    -- Try to get from shared dict (generated once per worker lifecycle)
    local shared = ngx.shared.waf_timing
    if shared then
        local key = shared:get("encryption_key")
        if key then
            return key
        end

        -- Generate new key
        local random_bytes = resty_random.bytes(32, true)
        if random_bytes then
            key = resty_string.to_hex(random_bytes):sub(1, 32)
            shared:set("encryption_key", key, 86400)  -- 24 hour TTL
            return key
        end
    end

    -- Fallback: use a deterministic key based on server info (less secure but functional)
    local fallback = ngx.md5(ngx.var.server_name .. ngx.var.server_addr .. "waf_timing_secret")
    return fallback
end

-- Encrypt timestamp data
local function encrypt_token(data)
    local key = get_encryption_key()
    local aes = resty_aes:new(key, nil, resty_aes.cipher(256, "cbc"))

    if not aes then
        ngx.log(ngx.WARN, "timing_token: failed to create AES cipher")
        return nil
    end

    local json_data = cjson.encode(data)
    if not json_data then
        return nil
    end

    local encrypted = aes:encrypt(json_data)
    if not encrypted then
        return nil
    end

    -- Base64 encode for cookie safety
    return ngx.encode_base64(encrypted)
end

-- Decrypt timestamp data
local function decrypt_token(token)
    if not token or token == "" then
        return nil
    end

    local key = get_encryption_key()
    local aes = resty_aes:new(key, nil, resty_aes.cipher(256, "cbc"))

    if not aes then
        return nil
    end

    -- Base64 decode
    local encrypted = ngx.decode_base64(token)
    if not encrypted then
        return nil
    end

    local decrypted = aes:decrypt(encrypted)
    if not decrypted then
        return nil
    end

    return cjson.decode(decrypted)
end

-- Check if timing token should be set for this request
function _M.should_set_token(context)
    local config = get_config()

    if not config.enabled then
        return false
    end

    -- Check if endpoint has timing enabled
    if context and context.endpoint then
        local security = context.endpoint.security or {}
        if security.timing_token_enabled == false then
            return false
        end
    end

    -- Check request method
    local method = ngx.req.get_method()
    for _, m in ipairs(config.set_on_methods) do
        if method == m then
            return true
        end
    end

    return false
end

-- Set timing token cookie on response
function _M.set_token()
    local config = get_config()

    local token_data = {
        ts = ngx.now(),
        path = ngx.var.uri,
        nonce = resty_string.to_hex(resty_random.bytes(8, true) or "")
    }

    local encrypted = encrypt_token(token_data)
    if not encrypted then
        ngx.log(ngx.WARN, "timing_token: failed to encrypt token")
        return
    end

    -- Set cookie with appropriate flags
    local cookie_value = string.format(
        "%s=%s; Path=/; Max-Age=%d; HttpOnly; SameSite=Lax",
        config.cookie_name,
        encrypted,
        config.cookie_ttl
    )

    -- Add Secure flag if HTTPS
    if ngx.var.scheme == "https" then
        cookie_value = cookie_value .. "; Secure"
    end

    ngx.header["Set-Cookie"] = cookie_value
end

-- Validate timing token and return score adjustment
-- Returns: { score = number, reason = string, elapsed = number or nil }
function _M.validate_token(context)
    local config = get_config()

    -- Feature disabled
    if not config.enabled then
        return { score = 0, reason = "disabled" }
    end

    -- Check if endpoint has timing enabled
    if context and context.endpoint then
        local security = context.endpoint.security or {}
        if security.timing_token_enabled == false then
            return { score = 0, reason = "endpoint_disabled" }
        end
    end

    -- Check request method
    local method = ngx.req.get_method()
    local should_check = false
    for _, m in ipairs(config.apply_to_methods) do
        if method == m then
            should_check = true
            break
        end
    end

    if not should_check then
        return { score = 0, reason = "method_exempt" }
    end

    -- Get cookie
    local cookie_header = ngx.var.http_cookie
    if not cookie_header then
        return {
            score = config.score_no_cookie,
            reason = "no_cookie",
            flag = "timing:no_cookie"
        }
    end

    -- Parse cookie value
    local cookie_pattern = config.cookie_name .. "=([^;]+)"
    local token = cookie_header:match(cookie_pattern)

    if not token then
        return {
            score = config.score_no_cookie,
            reason = "no_timing_cookie",
            flag = "timing:no_cookie"
        }
    end

    -- Decrypt and validate
    local token_data = decrypt_token(token)
    if not token_data or not token_data.ts then
        return {
            score = config.score_no_cookie,
            reason = "invalid_token",
            flag = "timing:invalid"
        }
    end

    -- Check token age (not expired)
    local now = ngx.now()
    local token_age = now - token_data.ts

    if token_age > config.cookie_ttl then
        return {
            score = config.score_no_cookie,
            reason = "token_expired",
            elapsed = token_age,
            flag = "timing:expired"
        }
    end

    -- Check if too fast
    if token_age < config.min_time_block then
        return {
            score = config.score_too_fast,
            reason = "too_fast",
            elapsed = token_age,
            flag = "timing:too_fast"
        }
    end

    if token_age < config.min_time_flag then
        return {
            score = config.score_suspicious,
            reason = "suspicious_fast",
            elapsed = token_age,
            flag = "timing:suspicious"
        }
    end

    -- Normal timing
    return {
        score = 0,
        reason = "ok",
        elapsed = token_age
    }
end

-- Strip timing cookie from request before forwarding to backend
function _M.strip_cookie()
    local config = get_config()
    local cookie_header = ngx.var.http_cookie

    if not cookie_header then
        return
    end

    -- Remove our timing cookie from the header
    local cookie_name = config.cookie_name
    local patterns = {
        cookie_name .. "=[^;]+;%s*",  -- Cookie followed by others
        ";%s*" .. cookie_name .. "=[^;]+",  -- Cookie preceded by others
        cookie_name .. "=[^;]+",  -- Only cookie
    }

    local new_cookie = cookie_header
    for _, pattern in ipairs(patterns) do
        new_cookie = new_cookie:gsub(pattern, "")
    end

    -- Clean up any double semicolons or leading/trailing semicolons
    new_cookie = new_cookie:gsub(";%s*;", ";"):gsub("^%s*;%s*", ""):gsub("%s*;%s*$", "")

    if new_cookie == "" then
        ngx.req.clear_header("Cookie")
    else
        ngx.req.set_header("Cookie", new_cookie)
    end
end

-- Get current configuration (for admin API)
function _M.get_config()
    return get_config()
end

-- Check if feature is enabled
function _M.is_enabled()
    local config = get_config()
    return config.enabled == true
end

return _M
