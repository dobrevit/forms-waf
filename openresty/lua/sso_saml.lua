-- sso_saml.lua
-- SAML authentication module using OIDC bridge approach
-- SAML providers are configured with OIDC settings pointing to a SAML-to-OIDC bridge (Keycloak/Dex)

local _M = {}

local cjson = require "cjson.safe"
local redis = require "resty.redis"
local sso_oidc = require "sso_oidc"

-- Redis configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil

-- Redis keys
local PROVIDER_KEY_PREFIX = "waf:auth:providers:config:"

-- Get Redis connection
local function get_redis()
    local red = redis:new()
    red:set_timeout(2000)

    local ok, err = red:connect(REDIS_HOST, REDIS_PORT)
    if not ok then
        return nil, err
    end

    if REDIS_PASSWORD and REDIS_PASSWORD ~= "" then
        local res, err = red:auth(REDIS_PASSWORD)
        if not res then
            red:close()
            return nil, err
        end
    end

    return red
end

local function close_redis(red)
    if red then
        red:set_keepalive(10000, 100)
    end
end

-- Get provider configuration from Redis
function _M.get_provider(provider_id)
    local red, err = get_redis()
    if not red then
        return nil, "Redis error: " .. (err or "unknown")
    end

    local provider_json = red:get(PROVIDER_KEY_PREFIX .. provider_id)
    close_redis(red)

    if not provider_json or provider_json == ngx.null then
        return nil, "Provider not found: " .. provider_id
    end

    local provider = cjson.decode(provider_json)
    if not provider then
        return nil, "Invalid provider data"
    end

    return provider
end

-- Authenticate via SAML (using OIDC bridge)
-- SAML authentication works by redirecting to an OIDC bridge (Keycloak/Dex)
-- that handles the SAML flow and returns an OIDC token
function _M.authenticate(provider_id)
    local provider, err = _M.get_provider(provider_id)
    if not provider then
        return nil, err
    end

    if not provider.enabled then
        return nil, "Provider is disabled"
    end

    if provider.type ~= "saml" then
        return nil, "Provider is not SAML type"
    end

    -- SAML providers must have OIDC configuration for the bridge
    if not provider.oidc then
        return nil, "SAML provider missing OIDC bridge configuration. " ..
            "SAML providers require an OIDC bridge (Keycloak/Dex) to be configured."
    end

    -- Delegate to OIDC module - the OIDC settings point to the SAML-to-OIDC bridge
    return sso_oidc.authenticate(provider_id)
end

-- Test SAML provider connection (tests the OIDC bridge)
function _M.test_provider(provider_id)
    local provider, err = _M.get_provider(provider_id)
    if not provider then
        return { success = false, message = err }
    end

    if provider.type ~= "saml" then
        return { success = false, message = "Provider is not SAML type" }
    end

    if not provider.oidc then
        return {
            success = false,
            message = "SAML provider missing OIDC bridge configuration. " ..
                "Configure the 'oidc' section with your SAML-to-OIDC bridge (Keycloak/Dex) settings."
        }
    end

    -- Test the OIDC bridge connection
    local result = sso_oidc.test_provider(provider_id)

    if result.success then
        result.message = "SAML-to-OIDC bridge connection successful"
        result.bridge_type = "oidc"
    end

    return result
end

return _M
