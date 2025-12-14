--[[
    CAPTCHA Templates Module
    HTML templates for CAPTCHA challenge pages
]]

local _M = {}

-- Provider-specific script tags
local SCRIPTS = {
    turnstile = '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>',
    recaptcha_v2 = '<script src="https://www.google.com/recaptcha/api.js" async defer></script>',
    recaptcha_v3 = '<script src="https://www.google.com/recaptcha/api.js?render=%s"></script>',
    hcaptcha = '<script src="https://js.hcaptcha.com/1/api.js" async defer></script>',
}

-- Provider-specific widget HTML
local function get_widget(provider_type, site_key, options)
    options = options or {}
    local theme = options.theme or "auto"
    local size = options.size or "normal"

    if provider_type == "turnstile" then
        return string.format(
            '<div class="cf-turnstile" data-sitekey="%s" data-callback="onCaptchaSuccess" data-theme="%s" data-size="%s"></div>',
            site_key, theme, size
        )
    elseif provider_type == "recaptcha_v2" then
        return string.format(
            '<div class="g-recaptcha" data-sitekey="%s" data-callback="onCaptchaSuccess" data-theme="%s" data-size="%s"></div>',
            site_key, theme, size
        )
    elseif provider_type == "recaptcha_v3" then
        -- reCAPTCHA v3 is invisible, auto-executes
        local action = options.action or "submit"
        return string.format([[
            <div id="recaptcha-loading" class="captcha-loading">
                <div class="spinner"></div>
                <p>Verifying...</p>
            </div>
            <script>
                grecaptcha.ready(function() {
                    grecaptcha.execute('%s', {action: '%s'}).then(function(token) {
                        document.getElementById('captchaResponse').value = token;
                        onCaptchaSuccess(token);
                    });
                });
            </script>
        ]], site_key, action)
    elseif provider_type == "hcaptcha" then
        return string.format(
            '<div class="h-captcha" data-sitekey="%s" data-callback="onCaptchaSuccess" data-theme="%s" data-size="%s"></div>',
            site_key, theme, size
        )
    else
        return '<p class="error">Unknown CAPTCHA provider</p>'
    end
end

-- Get script tag for provider
local function get_script(provider_type, site_key)
    local script = SCRIPTS[provider_type]
    if not script then
        return ""
    end
    -- reCAPTCHA v3 needs site key in script URL
    if provider_type == "recaptcha_v3" then
        return string.format(script, site_key)
    end
    return script
end

-- Main challenge page template
function _M.render_challenge_page(provider, challenge_token, options)
    options = options or {}

    local site_key = provider.site_key
    local provider_type = provider.type
    local provider_options = provider.options or {}

    local script_tag = get_script(provider_type, site_key)
    local widget_html = get_widget(provider_type, site_key, provider_options)

    -- Custom branding
    local title = options.title or "Security Check"
    local message = options.message or "Please complete this quick verification to continue. This helps us protect against automated abuse."
    local brand_color = options.brand_color or "#667eea"
    local brand_gradient = options.brand_gradient or "linear-gradient(135deg, #667eea 0%, #764ba2 100%)"

    return string.format([[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>%s</title>
    %s
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: %s;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            line-height: 1.5;
        }

        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            padding: 40px;
            max-width: 420px;
            width: 100%%;
            text-align: center;
        }

        .icon {
            width: 64px;
            height: 64px;
            background: #f0f4ff;
            border-radius: 50%%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
        }

        .icon svg {
            width: 32px;
            height: 32px;
            color: %s;
        }

        h1 {
            font-size: 24px;
            font-weight: 600;
            color: #1a1a2e;
            margin-bottom: 12px;
        }

        .message {
            color: #666;
            margin-bottom: 24px;
            font-size: 15px;
        }

        .captcha-container {
            display: flex;
            justify-content: center;
            margin-bottom: 24px;
            min-height: 78px;
        }

        .captcha-loading {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 12px;
            color: #666;
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 3px solid #f3f3f3;
            border-top: 3px solid %s;
            border-radius: 50%%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0%% { transform: rotate(0deg); }
            100%% { transform: rotate(360deg); }
        }

        .error-message {
            color: #dc2626;
            font-size: 14px;
            margin-top: 12px;
            padding: 12px;
            background: #fef2f2;
            border-radius: 8px;
            display: none;
        }

        .error-message.show {
            display: block;
        }

        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(255, 255, 255, 0.9);
            display: none;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            gap: 16px;
            z-index: 1000;
        }

        .loading-overlay.show {
            display: flex;
        }

        .loading-overlay p {
            color: #666;
            font-size: 16px;
        }

        .footer {
            margin-top: 24px;
            padding-top: 16px;
            border-top: 1px solid #eee;
            font-size: 12px;
            color: #999;
        }

        .footer a {
            color: #666;
            text-decoration: none;
        }

        .footer a:hover {
            text-decoration: underline;
        }

        /* Provider-specific styles */
        .cf-turnstile, .g-recaptcha, .h-captcha {
            display: inline-block;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
            </svg>
        </div>

        <h1>%s</h1>
        <p class="message">%s</p>

        <form id="captchaForm" action="/captcha/verify" method="POST">
            <input type="hidden" name="challenge_token" value="%s">
            <input type="hidden" name="captcha_response" id="captchaResponse">

            <div class="captcha-container">
                %s
            </div>

            <div class="error-message" id="errorMsg"></div>
        </form>

        <div class="footer">
            Protected by Forms WAF
        </div>
    </div>

    <div class="loading-overlay" id="loadingOverlay">
        <div class="spinner"></div>
        <p>Verifying, please wait...</p>
    </div>

    <script>
        function onCaptchaSuccess(token) {
            document.getElementById('captchaResponse').value = token;
            document.getElementById('loadingOverlay').classList.add('show');

            // Small delay to show loading state
            setTimeout(function() {
                document.getElementById('captchaForm').submit();
            }, 300);
        }

        function onCaptchaError(error) {
            var errorEl = document.getElementById('errorMsg');
            errorEl.textContent = 'Verification failed. Please try again.';
            errorEl.classList.add('show');
        }

        function onCaptchaExpired() {
            var errorEl = document.getElementById('errorMsg');
            errorEl.textContent = 'Challenge expired. Please complete the verification again.';
            errorEl.classList.add('show');
        }
    </script>
</body>
</html>
]], title, script_tag, brand_gradient, brand_color, brand_color, title, message, challenge_token, widget_html)
end

-- Render error page (for failed verification)
function _M.render_error_page(error_message, retry_url)
    return string.format([[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title>Verification Failed</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            padding: 40px;
            max-width: 420px;
            width: 100%%;
            text-align: center;
        }
        .icon {
            width: 64px;
            height: 64px;
            background: #fef2f2;
            border-radius: 50%%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
        }
        .icon svg { width: 32px; height: 32px; color: #dc2626; }
        h1 { font-size: 24px; color: #1a1a2e; margin-bottom: 12px; }
        p { color: #666; margin-bottom: 24px; }
        .btn {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 12px 24px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 500;
            transition: background 0.2s;
        }
        .btn:hover { background: #5a67d8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>
        <h1>Verification Failed</h1>
        <p>%s</p>
        <a href="%s" class="btn">Try Again</a>
    </div>
</body>
</html>
]], error_message or "We couldn't verify your response. Please try again.", retry_url or "javascript:history.back()")
end

-- Render success page (optional, usually we redirect)
function _M.render_success_page(redirect_url, message)
    return string.format([[
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <meta http-equiv="refresh" content="2;url=%s">
    <title>Verification Successful</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            padding: 40px;
            max-width: 420px;
            width: 100%%;
            text-align: center;
        }
        .icon {
            width: 64px;
            height: 64px;
            background: #f0fdf4;
            border-radius: 50%%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 24px;
        }
        .icon svg { width: 32px; height: 32px; color: #22c55e; }
        h1 { font-size: 24px; color: #1a1a2e; margin-bottom: 12px; }
        p { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                      d="M5 13l4 4L19 7"/>
            </svg>
        </div>
        <h1>Verification Successful</h1>
        <p>%s</p>
    </div>
</body>
</html>
]], redirect_url or "/", message or "Redirecting you back...")
end

return _M
