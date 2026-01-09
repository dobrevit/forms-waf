--[[
    CAPTCHA Providers Module
    Handles verification with different CAPTCHA providers:
    - Cloudflare Turnstile
    - Google reCAPTCHA v2
    - Google reCAPTCHA v3
    - hCaptcha
]]

local http_utils = require "http_utils"
local cjson = require "cjson.safe"

local _M = {}

-- Provider verification URLs
local VERIFY_URLS = {
    turnstile = "https://challenges.cloudflare.com/turnstile/v0/siteverify",
    recaptcha_v2 = "https://www.google.com/recaptcha/api/siteverify",
    recaptcha_v3 = "https://www.google.com/recaptcha/api/siteverify",
    hcaptcha = "https://hcaptcha.com/siteverify",
}

-- HTTP POST to verification endpoint (with proxy support via http_utils)
local function http_post(url, params)
    local res, err = http_utils.post_form(url, params, {
        timeout = 5000,
        ssl_verify = true,
    })

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
