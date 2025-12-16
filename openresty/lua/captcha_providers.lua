--[[
    CAPTCHA Providers Module
    Handles verification with different CAPTCHA providers:
    - Cloudflare Turnstile
    - Google reCAPTCHA v2
    - Google reCAPTCHA v3
    - hCaptcha
]]

local http = require "resty.http"
local cjson = require "cjson.safe"

local _M = {}

-- Proxy configuration from environment
local HTTP_PROXY = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
local HTTPS_PROXY = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
local NO_PROXY = os.getenv("NO_PROXY") or os.getenv("no_proxy") or ""

-- Parse NO_PROXY into a lookup table
local no_proxy_hosts = {}
for host in NO_PROXY:gmatch("[^,]+") do
    local h = host:match("^%s*(.-)%s*$")  -- trim whitespace
    if h and h ~= "" then
        no_proxy_hosts[h:lower()] = true
    end
end

-- Check if a host should bypass proxy
local function should_bypass_proxy(host)
    if not host then return true end
    host = host:lower()

    -- Direct match
    if no_proxy_hosts[host] then return true end

    -- Wildcard match (e.g., .example.com matches sub.example.com)
    for pattern, _ in pairs(no_proxy_hosts) do
        if pattern:sub(1, 1) == "." then
            -- Wildcard pattern
            if host:sub(-#pattern) == pattern or host == pattern:sub(2) then
                return true
            end
        end
    end

    return false
end

-- Get proxy URL for a given target URL
local function get_proxy_for_url(url)
    if url:match("^https://") then
        return HTTPS_PROXY
    else
        return HTTP_PROXY
    end
end

-- Provider verification URLs
local VERIFY_URLS = {
    turnstile = "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    recaptcha_v2 = "https://www.google.com/recaptcha/api/siteverify",
    recaptcha_v3 = "https://www.google.com/recaptcha/api/siteverify",
    hcaptcha = "https://hcaptcha.com/siteverify",
}

-- HTTP POST to verification endpoint
local function http_post(url, params)
    local httpc = http.new()
    httpc:set_timeout(5000)  -- 5 second timeout

    -- Build form body
    local body_parts = {}
    for k, v in pairs(params) do
        if v then
            table.insert(body_parts, ngx.escape_uri(k) .. "=" .. ngx.escape_uri(tostring(v)))
        end
    end
    local body = table.concat(body_parts, "&")

    -- Build request options
    local request_opts = {
        method = "POST",
        body = body,
        headers = {
            ["Content-Type"] = "application/x-www-form-urlencoded",
        },
        ssl_verify = true,
    }

    -- Add proxy support if configured
    local host = url:match("https?://([^/:]+)")
    if host and not should_bypass_proxy(host) then
        local proxy_url = get_proxy_for_url(url)
        if proxy_url then
            -- Parse proxy URL
            local proxy_host, proxy_port = proxy_url:match("https?://([^/:]+):?(%d*)")
            if proxy_host then
                proxy_port = tonumber(proxy_port) or 80
                ngx.log(ngx.DEBUG, "Using proxy ", proxy_host, ":", proxy_port, " for ", url)

                -- Connect through proxy
                local ok, conn_err = httpc:connect(proxy_host, proxy_port)
                if not ok then
                    ngx.log(ngx.ERR, "Failed to connect to proxy: ", conn_err)
                    return nil, "Proxy connection failed: " .. conn_err
                end

                -- For HTTPS, use CONNECT tunnel
                if url:match("^https://") then
                    local target_host = url:match("https://([^/]+)")
                    local res, err = httpc:request({
                        method = "CONNECT",
                        path = target_host,
                        headers = {
                            ["Host"] = target_host,
                        },
                    })
                    if not res or res.status ~= 200 then
                        ngx.log(ngx.ERR, "CONNECT tunnel failed: ", err or res.status)
                        return nil, "Proxy CONNECT failed"
                    end

                    -- Upgrade to TLS
                    local ok, ssl_err = httpc:ssl_handshake(nil, host, true)
                    if not ok then
                        ngx.log(ngx.ERR, "SSL handshake through proxy failed: ", ssl_err)
                        return nil, "SSL handshake failed: " .. ssl_err
                    end
                end

                -- Make the actual request
                local path = url:match("https?://[^/]+(.*)") or "/"
                request_opts.path = path
                request_opts.headers["Host"] = host

                local res, err = httpc:request(request_opts)
                if not res then
                    ngx.log(ngx.ERR, "CAPTCHA verification request failed through proxy: ", err)
                    return nil, err
                end

                -- Read body
                local body_data, read_err = res:read_body()
                if not body_data then
                    ngx.log(ngx.ERR, "Failed to read response body: ", read_err)
                    return nil, "Failed to read response"
                end

                httpc:set_keepalive()

                local data, decode_err = cjson.decode(body_data)
                if not data then
                    ngx.log(ngx.ERR, "CAPTCHA response decode failed: ", decode_err, " body: ", body_data)
                    return nil, "Invalid response from CAPTCHA provider"
                end

                return data
            end
        end
    end

    -- Direct connection (no proxy)
    local res, err = httpc:request_uri(url, request_opts)

    if not res then
        ngx.log(ngx.ERR, "CAPTCHA verification request failed: ", err)
        return nil, err
    end

    local data, decode_err = cjson.decode(res.body)
    if not data then
        ngx.log(ngx.ERR, "CAPTCHA response decode failed: ", decode_err, " body: ", res.body)
        return nil, "Invalid response from CAPTCHA provider"
    end

    return data
end

-- Verify Cloudflare Turnstile
local function verify_turnstile(secret, response, ip)
    local result, err = http_post(VERIFY_URLS.turnstile, {
        secret = secret,
        response = response,
        remoteip = ip,
    })

    if not result then
        return false, err
    end

    if result.success then
        ngx.log(ngx.DEBUG, "Turnstile verification successful")
        return true
    else
        local error_codes = result["error-codes"] or {}
        ngx.log(ngx.WARN, "Turnstile verification failed: ", table.concat(error_codes, ", "))
        return false, table.concat(error_codes, ", ")
    end
end

-- Verify Google reCAPTCHA v2
local function verify_recaptcha_v2(secret, response, ip)
    local result, err = http_post(VERIFY_URLS.recaptcha_v2, {
        secret = secret,
        response = response,
        remoteip = ip,
    })

    if not result then
        return false, err
    end

    if result.success then
        ngx.log(ngx.DEBUG, "reCAPTCHA v2 verification successful")
        return true
    else
        local error_codes = result["error-codes"] or {}
        ngx.log(ngx.WARN, "reCAPTCHA v2 verification failed: ", table.concat(error_codes, ", "))
        return false, table.concat(error_codes, ", ")
    end
end

-- Verify Google reCAPTCHA v3 (with score threshold)
local function verify_recaptcha_v3(secret, response, ip, min_score, expected_action)
    local result, err = http_post(VERIFY_URLS.recaptcha_v3, {
        secret = secret,
        response = response,
        remoteip = ip,
    })

    if not result then
        return false, err
    end

    if not result.success then
        local error_codes = result["error-codes"] or {}
        ngx.log(ngx.WARN, "reCAPTCHA v3 verification failed: ", table.concat(error_codes, ", "))
        return false, table.concat(error_codes, ", ")
    end

    -- Check score threshold
    local score = result.score or 0
    local threshold = min_score or 0.5

    if score < threshold then
        ngx.log(ngx.WARN, "reCAPTCHA v3 score too low: ", score, " < ", threshold)
        return false, "Score too low: " .. score
    end

    -- Optionally check action
    if expected_action and result.action ~= expected_action then
        ngx.log(ngx.WARN, "reCAPTCHA v3 action mismatch: expected ", expected_action, " got ", result.action)
        return false, "Action mismatch"
    end

    ngx.log(ngx.DEBUG, "reCAPTCHA v3 verification successful, score: ", score)
    return true, nil, { score = score, action = result.action }
end

-- Verify hCaptcha
local function verify_hcaptcha(secret, response, ip, sitekey)
    local params = {
        secret = secret,
        response = response,
        remoteip = ip,
    }

    -- hCaptcha optionally accepts sitekey for additional validation
    if sitekey then
        params.sitekey = sitekey
    end

    local result, err = http_post(VERIFY_URLS.hcaptcha, params)

    if not result then
        return false, err
    end

    if result.success then
        ngx.log(ngx.DEBUG, "hCaptcha verification successful")
        return true
    else
        local error_codes = result["error-codes"] or {}
        ngx.log(ngx.WARN, "hCaptcha verification failed: ", table.concat(error_codes, ", "))
        return false, table.concat(error_codes, ", ")
    end
end

-- Main verification function
-- provider_config: { type, secret_key, site_key, options }
-- captcha_response: token from CAPTCHA widget
-- client_ip: client's IP address
function _M.verify(provider_config, captcha_response, client_ip)
    if not provider_config then
        return false, "No provider configuration"
    end

    if not captcha_response or captcha_response == "" then
        return false, "No CAPTCHA response provided"
    end

    local provider_type = provider_config.type
    local secret = provider_config.secret_key
    local options = provider_config.options or {}

    if not secret or secret == "" then
        return false, "Provider secret key not configured"
    end

    if provider_type == "turnstile" then
        return verify_turnstile(secret, captcha_response, client_ip)

    elseif provider_type == "recaptcha_v2" then
        return verify_recaptcha_v2(secret, captcha_response, client_ip)

    elseif provider_type == "recaptcha_v3" then
        return verify_recaptcha_v3(
            secret,
            captcha_response,
            client_ip,
            options.min_score,
            options.action
        )

    elseif provider_type == "hcaptcha" then
        return verify_hcaptcha(secret, captcha_response, client_ip, provider_config.site_key)

    else
        return false, "Unknown provider type: " .. tostring(provider_type)
    end
end

-- Test provider connectivity (for admin UI)
function _M.test_provider(provider_config)
    -- Use provider's test keys if available, otherwise just check URL reachability
    local httpc = http.new()
    httpc:set_timeout(5000)

    local url = VERIFY_URLS[provider_config.type]
    if not url then
        return false, "Unknown provider type"
    end

    -- Try a request with empty response (will fail validation but proves connectivity)
    local result, err = http_post(url, {
        secret = provider_config.secret_key or "test",
        response = "test",
    })

    if result then
        -- Got a response (even if verification failed, connection works)
        return true, "Provider is reachable"
    else
        return false, err
    end
end

-- Get provider JavaScript snippet for embedding in HTML
function _M.get_script_tag(provider_type)
    local scripts = {
        turnstile = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>',
        recaptcha_v2 = '<script src="https://www.google.com/recaptcha/api.js" async defer></script>',
        recaptcha_v3 = '<script src="https://www.google.com/recaptcha/api.js?render={SITE_KEY}"></script>',
        hcaptcha = '<script src="https://js.hcaptcha.com/1/api.js" async defer></script>',
    }
    return scripts[provider_type]
end

-- Get provider widget HTML
function _M.get_widget_html(provider_type, site_key, options)
    options = options or {}
    local theme = options.theme or "auto"
    local size = options.size or "normal"

    local widgets = {
        turnstile = string.format(
            '<div class="cf-turnstile" data-sitekey="%s" data-callback="onCaptchaSuccess" data-theme="%s" data-size="%s"></div>',
            site_key, theme, size
        ),
        recaptcha_v2 = string.format(
            '<div class="g-recaptcha" data-sitekey="%s" data-callback="onCaptchaSuccess" data-theme="%s" data-size="%s"></div>',
            site_key, theme, size
        ),
        recaptcha_v3 = string.format(
            '<input type="hidden" id="captchaResponse" name="captcha_response"><script>grecaptcha.ready(function(){grecaptcha.execute("%s",{action:"%s"}).then(function(token){document.getElementById("captchaResponse").value=token;onCaptchaSuccess(token);});});</script>',
            site_key, options.action or "submit"
        ),
        hcaptcha = string.format(
            '<div class="h-captcha" data-sitekey="%s" data-callback="onCaptchaSuccess" data-theme="%s" data-size="%s"></div>',
            site_key, theme, size
        ),
    }
    return widgets[provider_type]
end

return _M
