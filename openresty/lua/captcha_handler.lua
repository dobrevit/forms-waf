--[[
    CAPTCHA Handler Module
    Core CAPTCHA challenge and verification logic
]]

local cjson = require "cjson.safe"
local captcha_providers = require "captcha_providers"
local captcha_templates = require "captcha_templates"

local _M = {}

-- Shared dictionaries for caching
local config_cache = ngx.shared.config_cache
local captcha_cache = ngx.shared.endpoint_cache  -- Reuse existing shared dict

-- Default configuration
local DEFAULT_CONFIG = {
    enabled = false,
    default_provider = nil,
    trust_duration = 86400,      -- 24 hours
    challenge_ttl = 600,         -- 10 minutes
    fallback_action = "block",   -- block | allow | monitor
    cookie_name = "waf_trust",
    cookie_secure = true,
    cookie_httponly = true,
    cookie_samesite = "Strict",
    signing_secret = nil,        -- Set via Redis config
}

-- Cached configuration
local cached_config = nil
local cached_providers = {}

-- Redis connection helper
local function get_redis()
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeouts(1000, 1000, 1000)

    local host = os.getenv("REDIS_HOST") or "redis"
    local port = tonumber(os.getenv("REDIS_PORT")) or 6379

    local ok, err = red:connect(host, port)
    if not ok then
        ngx.log(ngx.ERR, "CAPTCHA: Failed to connect to Redis: ", err)
        return nil, err
    end

    return red
end

local function close_redis(red)
    if red then
        local ok, err = red:set_keepalive(10000, 100)
        if not ok then
            ngx.log(ngx.WARN, "CAPTCHA: Failed to set Redis keepalive: ", err)
        end
    end
end

-- Generate secure random token
local function generate_token()
    local resty_random = require "resty.random"
    local str = require "resty.string"

    local bytes = resty_random.bytes(32)
    if bytes then
        return str.to_hex(bytes)
    end

    -- Fallback to less secure method
    return ngx.md5(ngx.now() .. ngx.var.remote_addr .. math.random())
end

-- HMAC signature for trust tokens
local function sign_token(data, secret)
    local resty_hmac = require "resty.hmac"
    local str = require "resty.string"

    local hmac = resty_hmac:new(secret or "default-secret-change-me", resty_hmac.ALGOS.SHA256)
    if not hmac then
        return ngx.md5(data .. (secret or ""))
    end

    hmac:update(data)
    local digest = hmac:final()
    return str.to_hex(digest)
end

-- Verify token signature
local function verify_signature(data, signature, secret)
    local expected = sign_token(data, secret)
    return expected == signature
end

-- Update cached configuration
function _M.update_config(config)
    if type(config) == "string" then
        config = cjson.decode(config)
    end
    if config then
        cached_config = config
        ngx.log(ngx.DEBUG, "CAPTCHA config updated")
    end
end

-- Cache a provider configuration
function _M.cache_provider(provider_id, config)
    if type(config) == "string" then
        config = cjson.decode(config)
    end
    if config then
        cached_providers[provider_id] = config
        ngx.log(ngx.DEBUG, "CAPTCHA provider cached: ", provider_id)
    end
end

-- Clear all cached providers
function _M.clear_providers_cache()
    cached_providers = {}
    ngx.log(ngx.DEBUG, "CAPTCHA providers cache cleared")
end

-- Cache provider index list
local cached_provider_index = {}

-- Update provider index
function _M.update_provider_index(provider_ids)
    if type(provider_ids) == "table" then
        cached_provider_index = provider_ids
        ngx.log(ngx.DEBUG, "CAPTCHA provider index updated: ", #provider_ids, " providers")
    end
end

-- Get list of all provider IDs (ordered by priority)
function _M.get_provider_ids()
    return cached_provider_index
end

-- Get first enabled provider (highest priority)
function _M.get_default_provider()
    for _, provider_id in ipairs(cached_provider_index) do
        local provider = cached_providers[provider_id]
        if provider and provider.enabled then
            return provider
        end
    end
    return nil
end

-- Get global CAPTCHA configuration
function _M.get_config()
    if cached_config then
        return cached_config
    end

    -- Try to load from cache
    local config_json = config_cache:get("captcha:config")
    if config_json then
        cached_config = cjson.decode(config_json)
        return cached_config
    end

    return DEFAULT_CONFIG
end

-- Get provider by ID
function _M.get_provider(provider_id)
    if not provider_id then
        return nil
    end

    -- Check memory cache first
    if cached_providers[provider_id] then
        return cached_providers[provider_id]
    end

    -- Try shared dict cache
    local provider_json = captcha_cache:get("captcha:provider:" .. provider_id)
    if provider_json then
        local provider = cjson.decode(provider_json)
        if provider then
            cached_providers[provider_id] = provider
            return provider
        end
    end

    return nil
end

-- Get effective CAPTCHA configuration for endpoint
function _M.get_captcha_config(context)
    local global_config = _M.get_config()

    if not global_config or not global_config.enabled then
        return nil
    end

    -- Check endpoint-level CAPTCHA config
    local endpoint_captcha = nil
    if context and context.endpoint and context.endpoint.captcha then
        endpoint_captcha = context.endpoint.captcha
    end

    -- If endpoint explicitly disables CAPTCHA
    if endpoint_captcha and endpoint_captcha.enabled == false then
        return nil
    end

    -- Merge configurations (endpoint overrides global)
    local config = {
        enabled = endpoint_captcha and endpoint_captcha.enabled or global_config.enabled,
        provider = endpoint_captcha and endpoint_captcha.provider or global_config.default_provider,
        trigger = endpoint_captcha and endpoint_captcha.trigger or "on_block",
        spam_score_threshold = endpoint_captcha and endpoint_captcha.spam_score_threshold or 50,
        trust_duration = endpoint_captcha and endpoint_captcha.trust_duration or global_config.trust_duration,
        exempt_ips = endpoint_captcha and endpoint_captcha.exempt_ips or {},
        cookie_name = global_config.cookie_name,
        cookie_secure = global_config.cookie_secure,
        cookie_httponly = global_config.cookie_httponly,
        cookie_samesite = global_config.cookie_samesite,
        fallback_action = global_config.fallback_action,
        signing_secret = global_config.signing_secret,
    }

    -- Get provider configuration
    if config.provider then
        config.provider_config = _M.get_provider(config.provider)
    end

    return config
end

-- Check if IP is exempt from CAPTCHA
local function is_ip_exempt(client_ip, exempt_list)
    if not exempt_list or #exempt_list == 0 then
        return false
    end

    for _, exempt in ipairs(exempt_list) do
        -- Simple exact match or CIDR (basic implementation)
        if exempt == client_ip then
            return true
        end
        -- Basic /8, /16, /24 CIDR support
        if exempt:match("/%d+$") then
            local network, bits = exempt:match("^(.+)/(%d+)$")
            if network and bits then
                -- Very basic CIDR check - just prefix matching for common cases
                bits = tonumber(bits)
                if bits == 8 then
                    local prefix = network:match("^(%d+)%.")
                    local ip_prefix = client_ip:match("^(%d+)%.")
                    if prefix == ip_prefix then return true end
                elseif bits == 16 then
                    local prefix = network:match("^(%d+%.%d+)%.")
                    local ip_prefix = client_ip:match("^(%d+%.%d+)%.")
                    if prefix == ip_prefix then return true end
                elseif bits == 24 then
                    local prefix = network:match("^(%d+%.%d+%.%d+)%.")
                    local ip_prefix = client_ip:match("^(%d+%.%d+%.%d+)%.")
                    if prefix == ip_prefix then return true end
                end
            end
        end
    end

    return false
end

-- Generate trust token hash (for cookie and Redis key)
local function generate_trust_hash(client_ip, endpoint_id, config)
    local data = client_ip .. ":" .. (endpoint_id or "*")
    return ngx.md5(data .. (config.signing_secret or ""))
end

-- Check if request has valid trust token
function _M.has_valid_trust(context, client_ip)
    local config = _M.get_captcha_config(context)
    if not config then
        return false
    end

    -- Check IP exemption first
    if is_ip_exempt(client_ip, config.exempt_ips) then
        ngx.log(ngx.DEBUG, "CAPTCHA: IP exempt: ", client_ip)
        return true
    end

    local cookie_name = config.cookie_name or "waf_trust"
    local cookie_value = ngx.var["cookie_" .. cookie_name]

    if not cookie_value or cookie_value == "" then
        return false
    end

    -- Parse cookie: base64(json).signature
    local encoded, signature = cookie_value:match("^(.+)%.([^%.]+)$")
    if not encoded or not signature then
        ngx.log(ngx.DEBUG, "CAPTCHA: Invalid cookie format")
        return false
    end

    -- Verify signature
    if not verify_signature(encoded, signature, config.signing_secret) then
        ngx.log(ngx.DEBUG, "CAPTCHA: Invalid cookie signature")
        return false
    end

    -- Decode token data
    local token_json = ngx.decode_base64(encoded)
    if not token_json then
        ngx.log(ngx.DEBUG, "CAPTCHA: Failed to decode cookie")
        return false
    end

    local token_data = cjson.decode(token_json)
    if not token_data then
        ngx.log(ngx.DEBUG, "CAPTCHA: Failed to parse cookie JSON")
        return false
    end

    -- Check expiration
    if token_data.expires_at and token_data.expires_at < ngx.now() then
        ngx.log(ngx.DEBUG, "CAPTCHA: Token expired")
        return false
    end

    -- Check IP match (optional security)
    if token_data.ip and token_data.ip ~= client_ip then
        ngx.log(ngx.DEBUG, "CAPTCHA: IP mismatch: ", token_data.ip, " vs ", client_ip)
        return false
    end

    -- Check endpoint scope
    local endpoint_id = context and context.endpoint and context.endpoint.id
    if token_data.endpoint_id and token_data.endpoint_id ~= "*" then
        if token_data.endpoint_id ~= endpoint_id then
            ngx.log(ngx.DEBUG, "CAPTCHA: Endpoint mismatch")
            return false
        end
    end

    -- Verify token exists in Redis (not revoked)
    local red, err = get_redis()
    if red then
        local redis_key = "waf:captcha:trust:" .. token_data.hash
        local exists = red:exists(redis_key)
        close_redis(red)

        if exists ~= 1 then
            ngx.log(ngx.DEBUG, "CAPTCHA: Token not in Redis (revoked?)")
            return false
        end
    end

    ngx.log(ngx.DEBUG, "CAPTCHA: Valid trust token found")
    return true
end

-- Store challenge data in Redis
local function store_challenge(challenge_token, data)
    local red, err = get_redis()
    if not red then
        ngx.log(ngx.ERR, "CAPTCHA: Cannot store challenge: ", err)
        return false
    end

    local config = _M.get_config()
    local ttl = config.challenge_ttl or 600

    local json_data = cjson.encode(data)
    local key = "waf:captcha:challenges:" .. challenge_token

    red:setex(key, ttl, json_data)
    close_redis(red)

    return true
end

-- Get challenge data from Redis
local function get_challenge(challenge_token)
    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local key = "waf:captcha:challenges:" .. challenge_token
    local json_data = red:get(key)
    close_redis(red)

    if not json_data or json_data == ngx.null then
        return nil, "Challenge not found or expired"
    end

    return cjson.decode(json_data)
end

-- Delete challenge from Redis
local function delete_challenge(challenge_token)
    local red, err = get_redis()
    if not red then
        return
    end

    local key = "waf:captcha:challenges:" .. challenge_token
    red:del(key)
    close_redis(red)
end

-- Issue trust token and store in Redis
local function issue_trust_token(client_ip, endpoint_id, config)
    local trust_duration = config.trust_duration or 86400
    local now = ngx.now()

    local hash = generate_trust_hash(client_ip, endpoint_id, config)

    local token_data = {
        hash = hash,
        issued_at = now,
        expires_at = now + trust_duration,
        endpoint_id = endpoint_id or "*",
        ip = client_ip,
    }

    -- Store in Redis
    local red, err = get_redis()
    if red then
        local key = "waf:captcha:trust:" .. hash
        red:setex(key, trust_duration, cjson.encode(token_data))
        close_redis(red)
    end

    -- Create signed cookie value
    local token_json = cjson.encode(token_data)
    local encoded = ngx.encode_base64(token_json)
    local signature = sign_token(encoded, config.signing_secret)

    return encoded .. "." .. signature, token_data
end

-- Set trust cookie on response
local function set_trust_cookie(cookie_value, config)
    local cookie_name = config.cookie_name or "waf_trust"
    local trust_duration = config.trust_duration or 86400

    local cookie_parts = {
        cookie_name .. "=" .. cookie_value,
        "Path=/",
        "Max-Age=" .. trust_duration,
    }

    if config.cookie_secure then
        table.insert(cookie_parts, "Secure")
    end

    if config.cookie_httponly then
        table.insert(cookie_parts, "HttpOnly")
    end

    if config.cookie_samesite then
        table.insert(cookie_parts, "SameSite=" .. config.cookie_samesite)
    end

    local cookie_header = table.concat(cookie_parts, "; ")
    ngx.header["Set-Cookie"] = cookie_header
end

-- Serve CAPTCHA challenge page
function _M.serve_challenge(context, form_data, block_reason, client_ip)
    local config = _M.get_captcha_config(context)
    if not config or not config.provider_config then
        ngx.log(ngx.ERR, "CAPTCHA: No provider configured")
        -- Fall back to configured action
        return _M.handle_fallback(config)
    end

    local provider = config.provider_config

    -- Generate challenge token
    local challenge_token = generate_token()

    -- Store challenge data
    local challenge_data = {
        form_data = form_data,
        endpoint_id = context and context.endpoint and context.endpoint.id,
        vhost_id = context and context.vhost and context.vhost.id,
        block_reason = block_reason,
        provider_id = config.provider,
        client_ip = client_ip,
        original_uri = ngx.var.request_uri,
        original_method = ngx.req.get_method(),
        original_host = ngx.var.host,
        created_at = ngx.now(),
    }

    if not store_challenge(challenge_token, challenge_data) then
        ngx.log(ngx.ERR, "CAPTCHA: Failed to store challenge")
        return _M.handle_fallback(config)
    end

    -- Render challenge page
    local html = captcha_templates.render_challenge_page(provider, challenge_token, {
        title = "Security Check",
        message = "Please complete this quick verification to continue.",
    })

    ngx.status = ngx.HTTP_OK
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store, no-cache, must-revalidate"
    ngx.header["Pragma"] = "no-cache"
    ngx.say(html)

    return ngx.exit(ngx.HTTP_OK)
end

-- Handle CAPTCHA verification (called from /captcha/verify endpoint)
function _M.handle_verification()
    ngx.req.read_body()

    local args, err = ngx.req.get_post_args()
    if not args then
        ngx.log(ngx.ERR, "CAPTCHA: Failed to read POST args: ", err)
        return _M.serve_error("Invalid request")
    end

    local challenge_token = args.challenge_token
    local captcha_response = args.captcha_response

    if not challenge_token or challenge_token == "" then
        return _M.serve_error("Missing challenge token")
    end

    if not captcha_response or captcha_response == "" then
        return _M.serve_error("Please complete the verification")
    end

    -- Get challenge data
    local challenge, err = get_challenge(challenge_token)
    if not challenge then
        return _M.serve_error("Challenge expired or invalid. Please try again.")
    end

    -- Get provider
    local provider = _M.get_provider(challenge.provider_id)
    if not provider then
        ngx.log(ngx.ERR, "CAPTCHA: Provider not found: ", challenge.provider_id)
        return _M.serve_error("Configuration error")
    end

    -- Verify with provider
    local client_ip = challenge.client_ip or ngx.var.remote_addr
    local verified, verify_err = captcha_providers.verify(provider, captcha_response, client_ip)

    if not verified then
        ngx.log(ngx.WARN, "CAPTCHA verification failed: ", verify_err)
        -- Don't delete challenge - let user retry
        return _M.serve_error("Verification failed. Please try again.")
    end

    ngx.log(ngx.INFO, "CAPTCHA verification successful for IP: ", client_ip)

    -- Delete challenge
    delete_challenge(challenge_token)

    -- Issue trust token
    local config = _M.get_config()
    local trust_value, token_data = issue_trust_token(client_ip, challenge.endpoint_id, config)

    -- Set cookie
    set_trust_cookie(trust_value, config)

    -- Redirect back to original URL
    -- The cookie will allow the request through on retry
    local redirect_url = challenge.original_uri or "/"

    ngx.header["Location"] = redirect_url
    ngx.status = ngx.HTTP_MOVED_TEMPORARILY
    ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
end

-- Serve error page
function _M.serve_error(message)
    local html = captcha_templates.render_error_page(message, "javascript:history.back()")

    ngx.status = ngx.HTTP_OK
    ngx.header["Content-Type"] = "text/html; charset=utf-8"
    ngx.header["Cache-Control"] = "no-store"
    ngx.say(html)

    return ngx.exit(ngx.HTTP_OK)
end

-- Handle fallback when CAPTCHA can't be served
function _M.handle_fallback(config)
    local action = config and config.fallback_action or "block"

    if action == "allow" then
        ngx.log(ngx.WARN, "CAPTCHA fallback: allowing request")
        -- Continue to next phase (don't exit)
        return
    elseif action == "monitor" then
        ngx.log(ngx.WARN, "CAPTCHA fallback: monitoring (would block)")
        return
    else
        -- Default: block
        ngx.log(ngx.WARN, "CAPTCHA fallback: blocking request")
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Request blocked",
            reason = "captcha_unavailable",
        }))
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

-- Check if CAPTCHA should be triggered based on trigger mode
function _M.should_challenge(context, blocked, spam_score)
    local config = _M.get_captcha_config(context)
    if not config or not config.enabled then
        return false
    end

    local trigger = config.trigger or "on_block"

    if trigger == "always" then
        return true
    elseif trigger == "on_block" then
        return blocked
    elseif trigger == "on_flag" then
        local threshold = config.spam_score_threshold or 50
        return spam_score >= threshold
    end

    return false
end

return _M
