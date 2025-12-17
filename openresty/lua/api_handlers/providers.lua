-- api_handlers/providers.lua
-- Auth provider management API handlers

local _M = {}

local cjson = require "cjson.safe"
local utils = require "api_handlers.utils"
local sso_oidc = require "sso_oidc"
local sso_ldap = require "sso_ldap"
local sso_saml = require "sso_saml"

local PROVIDER_KEY_PREFIX = "waf:auth:providers:config:"
local ADMIN_COOKIE_NAME = os.getenv("WAF_ADMIN_COOKIE") or "waf_admin_session"

-- GET /api/auth/providers - List available providers for login page (public)
function _M.list_public()
    local providers, err = sso_oidc.list_providers()
    if not providers then
        return utils.error_response(err, 500)
    end

    -- Also indicate if local auth is enabled
    local local_auth_enabled = os.getenv("WAF_LOCAL_AUTH") ~= "false"

    return utils.json_response({
        providers = providers,
        local_auth_enabled = local_auth_enabled,
    })
end

-- GET /api/auth/providers/config - List all provider configs (admin only)
function _M.list_config()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local keys = red:keys(PROVIDER_KEY_PREFIX .. "*")
    local providers = {}

    if keys and type(keys) == "table" then
        for _, key in ipairs(keys) do
            local provider_json = red:get(key)
            if provider_json and provider_json ~= ngx.null then
                local provider = cjson.decode(provider_json)
                if provider then
                    -- Mask sensitive fields
                    if provider.oidc and provider.oidc.client_secret then
                        provider.oidc.client_secret = "***masked***"
                    end
                    if provider.ldap and provider.ldap.bind_password then
                        provider.ldap.bind_password = "***masked***"
                    end
                    table.insert(providers, provider)
                end
            end
        end
    end

    utils.close_redis(red)

    -- Sort by priority
    table.sort(providers, function(a, b)
        return (a.priority or 100) < (b.priority or 100)
    end)

    return utils.json_response({ providers = providers })
end

-- POST /api/auth/providers/config - Create new provider
function _M.create()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate required fields
    if not data.id or data.id == "" then
        return utils.error_response("Provider ID is required")
    end

    if not data.id:match("^[a-zA-Z0-9_-]+$") then
        return utils.error_response("Provider ID can only contain letters, numbers, underscores, and hyphens")
    end

    if not data.name or data.name == "" then
        return utils.error_response("Provider name is required")
    end

    if not data.type then
        return utils.error_response("Provider type is required")
    end

    if data.type ~= "oidc" and data.type ~= "ldap" and data.type ~= "saml" then
        return utils.error_response("Invalid provider type. Must be: oidc, ldap, or saml")
    end

    -- Validate type-specific configuration
    if data.type == "oidc" then
        if not data.oidc then
            return utils.error_response("OIDC configuration is required")
        end
        if not data.oidc.issuer and not data.oidc.discovery then
            return utils.error_response("OIDC issuer or discovery URL is required")
        end
        if not data.oidc.client_id then
            return utils.error_response("OIDC client_id is required")
        end
        if not data.oidc.client_secret then
            return utils.error_response("OIDC client_secret is required")
        end
    elseif data.type == "ldap" then
        if not data.ldap then
            return utils.error_response("LDAP configuration is required")
        end
        if not data.ldap.host then
            return utils.error_response("LDAP host is required")
        end
        if not data.ldap.base_dn then
            return utils.error_response("LDAP base_dn is required")
        end
    elseif data.type == "saml" then
        -- SAML uses OIDC bridge approach - requires OIDC configuration
        if not data.oidc then
            return utils.error_response("SAML provider requires OIDC bridge configuration. " ..
                "Configure the 'oidc' section with your SAML-to-OIDC bridge (Keycloak/Dex) settings.")
        end
        if not data.oidc.issuer and not data.oidc.discovery then
            return utils.error_response("OIDC bridge issuer or discovery URL is required")
        end
        if not data.oidc.client_id then
            return utils.error_response("OIDC bridge client_id is required")
        end
        if not data.oidc.client_secret then
            return utils.error_response("OIDC bridge client_secret is required")
        end
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if provider already exists
    local existing = red:get(PROVIDER_KEY_PREFIX .. data.id)
    if existing and existing ~= ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider already exists: " .. data.id, 409)
    end

    -- Set defaults
    data.enabled = data.enabled ~= false
    data.priority = data.priority or 100
    data.created_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
    data.updated_at = data.created_at

    -- Default role mapping
    if not data.role_mapping then
        data.role_mapping = {
            default_role = "viewer",
            default_vhosts = {"*"},
            claim_name = "groups",
            sync_on_login = true,
            mappings = {},
        }
    end

    -- Save provider
    local ok, err = red:set(PROVIDER_KEY_PREFIX .. data.id, cjson.encode(data))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to create provider: " .. (err or "unknown"), 500)
    end

    -- Mask sensitive fields in response
    local response = cjson.decode(cjson.encode(data))
    if response.oidc and response.oidc.client_secret then
        response.oidc.client_secret = "***masked***"
    end

    return utils.json_response({ created = true, provider = response }, 201)
end

-- GET /api/auth/providers/config/{id} - Get provider config
function _M.get(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local provider_json = red:get(PROVIDER_KEY_PREFIX .. provider_id)
    utils.close_redis(red)

    if not provider_json or provider_json == ngx.null then
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local provider = cjson.decode(provider_json)
    if not provider then
        return utils.error_response("Invalid provider data", 500)
    end

    -- Mask sensitive fields
    if provider.oidc and provider.oidc.client_secret then
        provider.oidc.client_secret = "***masked***"
    end
    if provider.ldap and provider.ldap.bind_password then
        provider.ldap.bind_password = "***masked***"
    end

    return utils.json_response({ provider = provider })
end

-- PUT /api/auth/providers/config/{id} - Update provider
function _M.update(provider_id)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local provider_json = red:get(PROVIDER_KEY_PREFIX .. provider_id)
    if not provider_json or provider_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local provider = cjson.decode(provider_json)
    if not provider then
        utils.close_redis(red)
        return utils.error_response("Invalid provider data", 500)
    end

    -- Update fields
    if data.name ~= nil then
        provider.name = data.name
    end

    if data.enabled ~= nil then
        provider.enabled = data.enabled
    end

    if data.priority ~= nil then
        provider.priority = data.priority
    end

    if data.icon ~= nil then
        provider.icon = data.icon
    end

    -- Update OIDC config
    if data.oidc ~= nil and provider.type == "oidc" then
        provider.oidc = provider.oidc or {}
        if data.oidc.issuer ~= nil then
            provider.oidc.issuer = data.oidc.issuer
        end
        if data.oidc.discovery ~= nil then
            provider.oidc.discovery = data.oidc.discovery
        end
        if data.oidc.client_id ~= nil then
            provider.oidc.client_id = data.oidc.client_id
        end
        -- Only update client_secret if not masked
        if data.oidc.client_secret ~= nil and data.oidc.client_secret ~= "***masked***" then
            provider.oidc.client_secret = data.oidc.client_secret
        end
        if data.oidc.scopes ~= nil then
            provider.oidc.scopes = data.oidc.scopes
        end
        if data.oidc.ssl_verify ~= nil then
            provider.oidc.ssl_verify = data.oidc.ssl_verify
        end
        if data.oidc.use_pkce ~= nil then
            provider.oidc.use_pkce = data.oidc.use_pkce
        end
    end

    -- Update LDAP config
    if data.ldap ~= nil and provider.type == "ldap" then
        provider.ldap = provider.ldap or {}
        if data.ldap.host ~= nil then
            provider.ldap.host = data.ldap.host
        end
        if data.ldap.port ~= nil then
            provider.ldap.port = data.ldap.port
        end
        if data.ldap.use_ssl ~= nil then
            provider.ldap.use_ssl = data.ldap.use_ssl
        end
        if data.ldap.ssl_verify ~= nil then
            provider.ldap.ssl_verify = data.ldap.ssl_verify
        end
        if data.ldap.timeout ~= nil then
            provider.ldap.timeout = data.ldap.timeout
        end
        if data.ldap.base_dn ~= nil then
            provider.ldap.base_dn = data.ldap.base_dn
        end
        if data.ldap.user_base_dn ~= nil then
            provider.ldap.user_base_dn = data.ldap.user_base_dn
        end
        if data.ldap.user_dn_template ~= nil then
            provider.ldap.user_dn_template = data.ldap.user_dn_template
        end
        if data.ldap.user_filter ~= nil then
            provider.ldap.user_filter = data.ldap.user_filter
        end
        if data.ldap.group_base_dn ~= nil then
            provider.ldap.group_base_dn = data.ldap.group_base_dn
        end
        if data.ldap.group_filter ~= nil then
            provider.ldap.group_filter = data.ldap.group_filter
        end
        if data.ldap.group_attribute ~= nil then
            provider.ldap.group_attribute = data.ldap.group_attribute
        end
        if data.ldap.bind_dn ~= nil then
            provider.ldap.bind_dn = data.ldap.bind_dn
        end
        -- Only update bind_password if not masked
        if data.ldap.bind_password ~= nil and data.ldap.bind_password ~= "***masked***" then
            provider.ldap.bind_password = data.ldap.bind_password
        end
    end

    -- Update role mapping
    if data.role_mapping ~= nil then
        provider.role_mapping = provider.role_mapping or {}
        if data.role_mapping.default_role ~= nil then
            provider.role_mapping.default_role = data.role_mapping.default_role
        end
        if data.role_mapping.default_vhosts ~= nil then
            provider.role_mapping.default_vhosts = data.role_mapping.default_vhosts
        end
        if data.role_mapping.claim_name ~= nil then
            provider.role_mapping.claim_name = data.role_mapping.claim_name
        end
        if data.role_mapping.sync_on_login ~= nil then
            provider.role_mapping.sync_on_login = data.role_mapping.sync_on_login
        end
        if data.role_mapping.mappings ~= nil then
            provider.role_mapping.mappings = data.role_mapping.mappings
        end
    end

    provider.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")

    -- Save provider
    local ok, err = red:set(PROVIDER_KEY_PREFIX .. provider_id, cjson.encode(provider))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to update provider: " .. (err or "unknown"), 500)
    end

    -- Mask sensitive fields in response
    if provider.oidc and provider.oidc.client_secret then
        provider.oidc.client_secret = "***masked***"
    end

    return utils.json_response({ updated = true, provider = provider })
end

-- DELETE /api/auth/providers/config/{id} - Delete provider
function _M.delete(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if provider exists
    local provider_json = red:get(PROVIDER_KEY_PREFIX .. provider_id)
    if not provider_json or provider_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    -- Delete provider
    red:del(PROVIDER_KEY_PREFIX .. provider_id)
    utils.close_redis(red)

    return utils.json_response({ deleted = true, provider_id = provider_id })
end

-- POST /api/auth/providers/config/{id}/test - Test provider connection
function _M.test(provider_id)
    -- First get the provider to determine its type
    local red, err = utils.get_redis()
    if not red then
        return utils.json_response({ success = false, message = "Redis error: " .. (err or "unknown") }, 500)
    end

    local provider_json = red:get(PROVIDER_KEY_PREFIX .. provider_id)
    utils.close_redis(red)

    if not provider_json or provider_json == ngx.null then
        return utils.json_response({ success = false, message = "Provider not found: " .. provider_id }, 404)
    end

    local provider = cjson.decode(provider_json)
    if not provider then
        return utils.json_response({ success = false, message = "Invalid provider data" }, 500)
    end

    local result
    if provider.type == "oidc" then
        result = sso_oidc.test_provider(provider_id)
    elseif provider.type == "ldap" then
        result = sso_ldap.test_provider(provider_id)
    elseif provider.type == "saml" then
        result = sso_saml.test_provider(provider_id)
    else
        result = { success = false, message = "Provider type '" .. provider.type .. "' does not support connection testing" }
    end

    local status = result.success and 200 or 400
    return utils.json_response(result, status)
end

-- POST /api/auth/providers/config/{id}/enable - Enable provider
function _M.enable(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local provider_json = red:get(PROVIDER_KEY_PREFIX .. provider_id)
    if not provider_json or provider_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local provider = cjson.decode(provider_json)
    if not provider then
        utils.close_redis(red)
        return utils.error_response("Invalid provider data", 500)
    end

    provider.enabled = true
    provider.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")

    local ok, err = red:set(PROVIDER_KEY_PREFIX .. provider_id, cjson.encode(provider))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to enable provider: " .. (err or "unknown"), 500)
    end

    return utils.json_response({ enabled = true, provider_id = provider_id })
end

-- POST /api/auth/providers/config/{id}/disable - Disable provider
function _M.disable(provider_id)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local provider_json = red:get(PROVIDER_KEY_PREFIX .. provider_id)
    if not provider_json or provider_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("Provider not found: " .. provider_id, 404)
    end

    local provider = cjson.decode(provider_json)
    if not provider then
        utils.close_redis(red)
        return utils.error_response("Invalid provider data", 500)
    end

    provider.enabled = false
    provider.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")

    local ok, err = red:set(PROVIDER_KEY_PREFIX .. provider_id, cjson.encode(provider))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to disable provider: " .. (err or "unknown"), 500)
    end

    return utils.json_response({ disabled = true, provider_id = provider_id })
end

-- GET /api/auth/sso/oidc/{provider_id} - Initiate OIDC login
function _M.initiate_oidc(provider_id)
    local result, err = sso_oidc.authenticate(provider_id)

    if err then
        -- Redirect to login page with error
        local login_url = "/login?error=" .. ngx.escape_uri(err)
        return ngx.redirect(login_url)
    end

    if result then
        -- Authentication successful - set cookie and redirect
        ngx.header["Set-Cookie"] = ADMIN_COOKIE_NAME .. "=" .. result.session_id ..
            "; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"

        -- Redirect to dashboard
        return ngx.redirect("/")
    end

    -- If no result and no error, the redirect to IdP is happening
    -- (handled by lua-resty-openidc internally)
end

-- GET /api/auth/callback/oidc - OIDC callback handler
function _M.oidc_callback()
    local result, err = sso_oidc.handle_callback()

    if err then
        -- Redirect to login page with error
        local login_url = "/login?error=" .. ngx.escape_uri(err)
        return ngx.redirect(login_url)
    end

    if result then
        -- Authentication successful - set cookie and redirect
        ngx.header["Set-Cookie"] = ADMIN_COOKIE_NAME .. "=" .. result.session_id ..
            "; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"

        -- Redirect to dashboard
        return ngx.redirect("/")
    end

    -- Should not reach here
    return ngx.redirect("/login?error=unknown")
end

-- GET /api/auth/sso/saml/{provider_id} - Initiate SAML login (via OIDC bridge)
function _M.initiate_saml(provider_id)
    local result, err = sso_saml.authenticate(provider_id)

    if err then
        -- Redirect to login page with error
        local login_url = "/login?error=" .. ngx.escape_uri(err)
        return ngx.redirect(login_url)
    end

    if result then
        -- Authentication successful - set cookie and redirect
        ngx.header["Set-Cookie"] = ADMIN_COOKIE_NAME .. "=" .. result.session_id ..
            "; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"

        -- Redirect to dashboard
        return ngx.redirect("/")
    end

    -- If no result and no error, the redirect to IdP is happening
    -- (handled by lua-resty-openidc internally via SAML bridge)
end

-- POST /api/auth/ldap/{provider_id} - Authenticate via LDAP
function _M.authenticate_ldap(provider_id)
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    if not data.username or data.username == "" then
        return utils.error_response("Username is required")
    end

    if not data.password or data.password == "" then
        return utils.error_response("Password is required")
    end

    local result, err = sso_ldap.authenticate(provider_id, data.username, data.password)

    if err then
        return utils.error_response(err, 401)
    end

    if result then
        -- Authentication successful - set cookie
        ngx.header["Set-Cookie"] = ADMIN_COOKIE_NAME .. "=" .. result.session_id ..
            "; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400"

        return utils.json_response({
            authenticated = true,
            user = result.user,
        })
    end

    return utils.error_response("Authentication failed", 401)
end

-- Register handlers with main router
function _M.register(handlers, param_handlers)
    -- Public endpoints (no auth required)
    handlers["GET:/auth/providers"] = _M.list_public

    -- Admin endpoints for provider management
    handlers["GET:/auth/providers/config"] = _M.list_config
    handlers["POST:/auth/providers/config"] = _M.create

    -- SSO initiation and callback (no auth required)
    -- These need special routing in admin_api.lua

    param_handlers.auth_providers = {
        ["GET"] = _M.get,
        ["PUT"] = _M.update,
        ["DELETE"] = _M.delete,
        ["POST:test"] = _M.test,
        ["POST:enable"] = _M.enable,
        ["POST:disable"] = _M.disable,
    }
end

return _M
