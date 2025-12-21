-- admin_api.lua
-- Admin API for WAF management
-- Main router that delegates to specialized handler modules

local _M = {}

local cjson = require "cjson.safe"
local admin_auth = require "admin_auth"
local rbac = require "rbac"

-- Import handler modules
local users_handler = require "api_handlers.users"
local providers_handler = require "api_handlers.providers"
local system_handler = require "api_handlers.system"
local timing_handler = require "api_handlers.timing"
local hashes_handler = require "api_handlers.hashes"
local whitelist_handler = require "api_handlers.whitelist"
local keywords_handler = require "api_handlers.keywords"
local config_handler = require "api_handlers.config"
local webhooks_handler = require "api_handlers.webhooks"
local geoip_handler = require "api_handlers.geoip"
local reputation_handler = require "api_handlers.reputation"
local bulk_handler = require "api_handlers.bulk"
local captcha_handler = require "api_handlers.captcha"
local endpoints_handler = require "api_handlers.endpoints"
local vhosts_handler = require "api_handlers.vhosts"
local behavioral_handler = require "api_handlers.behavioral"
local cluster_handler = require "api_handlers.cluster"
local fingerprint_profiles_handler = require "api_handlers.fingerprint_profiles"

-- Configuration
local REQUIRE_AUTH = os.getenv("WAF_ADMIN_AUTH") ~= "false"  -- Default: require auth

-- Response helpers
local function json_response(data, status)
    ngx.status = status or 200
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode(data))
    return ngx.exit(ngx.status)
end

local function error_response(message, status)
    return json_response({error = message}, status or 400)
end

-- Route handlers
local handlers = {}

-- Register handlers from modules
local function register_handlers(module)
    if module.handlers then
        for route, handler in pairs(module.handlers) do
            handlers[route] = handler
        end
    end
end

-- Register all handler modules
register_handlers(system_handler)
register_handlers(timing_handler)
register_handlers(hashes_handler)
register_handlers(whitelist_handler)
register_handlers(keywords_handler)
register_handlers(config_handler)
register_handlers(webhooks_handler)
register_handlers(geoip_handler)
register_handlers(reputation_handler)
register_handlers(bulk_handler)
register_handlers(captcha_handler)
register_handlers(endpoints_handler)
register_handlers(vhosts_handler)
register_handlers(behavioral_handler)
register_handlers(cluster_handler)
register_handlers(fingerprint_profiles_handler)

-- ==================== User Management Endpoints ====================
-- Delegated to api_handlers/users.lua module

handlers["GET:/users"] = users_handler.list
handlers["POST:/users"] = users_handler.create

local user_handlers = {
    ["GET"] = users_handler.get,
    ["PUT"] = users_handler.update,
    ["DELETE"] = users_handler.delete,
    ["POST:reset-password"] = users_handler.reset_password,
}

-- ==================== Auth Provider Endpoints ====================
-- Delegated to api_handlers/providers.lua module

-- Public endpoint (no auth required - handled specially in handle_request)
handlers["GET:/auth/providers"] = providers_handler.list_public

-- Admin endpoints for provider management
handlers["GET:/auth/providers/config"] = providers_handler.list_config
handlers["POST:/auth/providers/config"] = providers_handler.create

-- SSO flow endpoints (no auth required - handled specially)
handlers["GET:/auth/callback/oidc"] = providers_handler.oidc_callback

local auth_provider_handlers = {
    ["GET"] = providers_handler.get,
    ["PUT"] = providers_handler.update,
    ["DELETE"] = providers_handler.delete,
    ["POST:test"] = providers_handler.test,
    ["POST:enable"] = providers_handler.enable,
    ["POST:disable"] = providers_handler.disable,
}

-- SSO initiation handlers (provider-specific)
local sso_handlers = {
    ["GET:oidc"] = providers_handler.initiate_oidc,
    ["GET:saml"] = providers_handler.initiate_saml,
    ["POST:ldap"] = providers_handler.authenticate_ldap,
}

-- Main request handler
function _M.handle_request()
    local method = ngx.req.get_method()
    local uri = ngx.var.uri

    -- Extract path - support both /api/ and /waf-admin/ prefixes
    local path = uri:match("/api(/.*)")
    if not path then
        path = uri:match("/waf%-admin(/.*)")
    end
    if not path then
        path = "/"
    end

    -- Check authentication (skip for public/SSO endpoints)
    local skip_auth = false
    local skip_rbac = false

    -- Public endpoints that don't require authentication
    if path == "/auth/providers" or
       path:match("^/auth/callback/") or
       path:match("^/auth/sso/") then
        skip_auth = true
        skip_rbac = true
    end

    if REQUIRE_AUTH and not skip_auth then
        -- Auth endpoints are handled separately in admin_auth.lua via nginx routing
        -- All requests here should be authenticated
        admin_auth.check_auth()

        -- Check RBAC permissions (unless skipped)
        if not skip_rbac then
            rbac.check_request()
        end
    end

    -- Try exact handler first
    local handler_key = method .. ":" .. path
    local handler = handlers[handler_key]

    if handler then
        return handler()
    end

    -- Check for parameterized endpoint routes: /endpoints/{id} or /endpoints/{id}/action
    local endpoint_id, endpoint_action = path:match("^/endpoints/([a-zA-Z0-9_-]+)/?([a-z]*)$")

    if endpoint_id then
        -- Route to appropriate endpoint handler
        if endpoint_action and endpoint_action ~= "" then
            -- Action route: /endpoints/{id}/enable, /endpoints/{id}/disable
            local action_handler = endpoints_handler.resource_handlers[method .. ":" .. endpoint_action]
            if action_handler then
                return action_handler(endpoint_id)
            end
        else
            -- CRUD route: GET/PUT/DELETE /endpoints/{id}
            local crud_handler = endpoints_handler.resource_handlers[method]
            if crud_handler then
                return crud_handler(endpoint_id)
            end
        end
    end

    -- Check for parameterized vhost routes: /vhosts/{id} or /vhosts/{id}/action
    local vhost_id, vhost_action = path:match("^/vhosts/([a-zA-Z0-9_-]+)/?([a-z]*)$")

    if vhost_id then
        -- Route to appropriate vhost handler
        if vhost_action and vhost_action ~= "" then
            -- Action route: /vhosts/{id}/enable, /vhosts/{id}/disable
            local action_handler = vhosts_handler.resource_handlers[method .. ":" .. vhost_action]
            if action_handler then
                return action_handler(vhost_id)
            end
        else
            -- CRUD route: GET/PUT/DELETE /vhosts/{id}
            local crud_handler = vhosts_handler.resource_handlers[method]
            if crud_handler then
                return crud_handler(vhost_id)
            end
        end
    end

    -- Check for parameterized CAPTCHA provider routes: /captcha/providers/{id} or /captcha/providers/{id}/action
    local provider_id, provider_action = path:match("^/captcha/providers/([a-zA-Z0-9_-]+)/?([a-z]*)$")

    if provider_id then
        -- Route to appropriate CAPTCHA provider handler
        if provider_action and provider_action ~= "" then
            -- Action route: /captcha/providers/{id}/test, /captcha/providers/{id}/enable, /captcha/providers/{id}/disable
            local action_handler = captcha_handler.resource_handlers[method .. ":" .. provider_action]
            if action_handler then
                return action_handler(provider_id)
            end
        else
            -- CRUD route: GET/PUT/DELETE /captcha/providers/{id}
            local crud_handler = captcha_handler.resource_handlers[method]
            if crud_handler then
                return crud_handler(provider_id)
            end
        end
    end

    -- Check for parameterized user routes: /users/{username} or /users/{username}/action
    local user_username, user_action = path:match("^/users/([a-zA-Z0-9_.-]+)/?([a-z-]*)$")

    if user_username then
        -- Route to appropriate user handler
        if user_action and user_action ~= "" then
            -- Action route: /users/{username}/reset-password
            local action_handler = user_handlers[method .. ":" .. user_action]
            if action_handler then
                return action_handler(user_username)
            end
        else
            -- CRUD route: GET/PUT/DELETE /users/{username}
            local crud_handler = user_handlers[method]
            if crud_handler then
                return crud_handler(user_username)
            end
        end
    end

    -- Check for parameterized auth provider routes: /auth/providers/config/{id} or /auth/providers/config/{id}/action
    local auth_provider_id, auth_provider_action = path:match("^/auth/providers/config/([a-zA-Z0-9_-]+)/?([a-z]*)$")

    if auth_provider_id then
        -- Route to appropriate auth provider handler
        if auth_provider_action and auth_provider_action ~= "" then
            -- Action route: /auth/providers/config/{id}/test, /auth/providers/config/{id}/enable, etc.
            local action_handler = auth_provider_handlers[method .. ":" .. auth_provider_action]
            if action_handler then
                return action_handler(auth_provider_id)
            end
        else
            -- CRUD route: GET/PUT/DELETE /auth/providers/config/{id}
            local crud_handler = auth_provider_handlers[method]
            if crud_handler then
                return crud_handler(auth_provider_id)
            end
        end
    end

    -- Check for SSO initiation routes: /auth/sso/{type}/{provider_id}
    local sso_type, sso_provider_id = path:match("^/auth/sso/([a-z]+)/([a-zA-Z0-9_-]+)$")

    if sso_type and sso_provider_id then
        local sso_handler = sso_handlers[method .. ":" .. sso_type]
        if sso_handler then
            return sso_handler(sso_provider_id)
        end
    end

    -- Check for parameterized fingerprint profile routes: /fingerprint-profiles/{id}
    local fp_profile_id = path:match("^/fingerprint%-profiles/([a-zA-Z0-9_-]+)$")

    if fp_profile_id then
        -- Route to appropriate fingerprint profile handler
        local fp_handler = fingerprint_profiles_handler.handlers[method .. ":/fingerprint-profiles/:id"]
        if fp_handler then
            return fp_handler({id = fp_profile_id})
        end
    end

    return error_response("Not found", 404)
end

return _M
