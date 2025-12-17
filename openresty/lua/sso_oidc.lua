-- sso_oidc.lua
-- OpenID Connect (OIDC) authentication module for SSO

local _M = {}

local cjson = require "cjson.safe"
local redis = require "resty.redis"

-- Redis configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil

-- Redis keys
local PROVIDER_KEY_PREFIX = "waf:auth:providers:config:"
local USER_KEY_PREFIX = "waf:admin:users:"
local SESSION_KEY_PREFIX = "waf:admin:sessions:"

-- Session configuration
local SESSION_TTL = tonumber(os.getenv("WAF_SESSION_TTL")) or 86400  -- 24 hours
local ADMIN_COOKIE_NAME = os.getenv("WAF_ADMIN_COOKIE") or "waf_admin_session"

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

-- Generate secure random string
local function generate_random_string(length)
    length = length or 32
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local result = {}
    for i = 1, length do
        local rand = math.random(1, #chars)
        table.insert(result, chars:sub(rand, rand))
    end
    return table.concat(result)
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

-- List all enabled OIDC providers (for login page)
function _M.list_providers()
    local red, err = get_redis()
    if not red then
        return nil, "Redis error: " .. (err or "unknown")
    end

    local keys = red:keys(PROVIDER_KEY_PREFIX .. "*")
    local providers = {}

    if keys and type(keys) == "table" then
        for _, key in ipairs(keys) do
            local provider_json = red:get(key)
            if provider_json and provider_json ~= ngx.null then
                local provider = cjson.decode(provider_json)
                if provider and provider.enabled and provider.type == "oidc" then
                    -- Return only public info for login page
                    table.insert(providers, {
                        id = provider.id,
                        name = provider.name,
                        type = provider.type,
                        icon = provider.icon,
                    })
                end
            end
        end
    end

    close_redis(red)

    -- Sort by priority
    table.sort(providers, function(a, b)
        return (a.priority or 100) < (b.priority or 100)
    end)

    return providers
end

-- Save provider configuration to Redis
function _M.save_provider(provider)
    if not provider or not provider.id then
        return nil, "Provider ID is required"
    end

    local red, err = get_redis()
    if not red then
        return nil, "Redis error: " .. (err or "unknown")
    end

    -- Set defaults
    provider.type = provider.type or "oidc"
    provider.enabled = provider.enabled ~= false
    provider.created_at = provider.created_at or os.date("!%Y-%m-%dT%H:%M:%SZ")
    provider.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")

    local ok, err = red:set(PROVIDER_KEY_PREFIX .. provider.id, cjson.encode(provider))
    close_redis(red)

    if not ok then
        return nil, "Failed to save provider: " .. (err or "unknown")
    end

    return provider
end

-- Delete provider configuration
function _M.delete_provider(provider_id)
    local red, err = get_redis()
    if not red then
        return nil, "Redis error: " .. (err or "unknown")
    end

    local deleted = red:del(PROVIDER_KEY_PREFIX .. provider_id)
    close_redis(red)

    return deleted > 0
end

-- Build OIDC configuration for lua-resty-openidc
local function build_oidc_config(provider)
    local redirect_uri = os.getenv("WAF_ADMIN_URL") or "http://localhost:8082"
    redirect_uri = redirect_uri .. "/api/auth/callback/oidc"

    local opts = {
        -- Discovery endpoint (if available)
        discovery = provider.oidc.discovery or (provider.oidc.issuer .. "/.well-known/openid-configuration"),

        -- Client credentials
        client_id = provider.oidc.client_id,
        client_secret = provider.oidc.client_secret,

        -- Redirect URI for callback
        redirect_uri = redirect_uri,

        -- Scopes to request
        scope = provider.oidc.scopes and table.concat(provider.oidc.scopes, " ") or "openid profile email",

        -- Token endpoint auth method
        token_endpoint_auth_method = provider.oidc.token_endpoint_auth_method or "client_secret_basic",

        -- SSL verification
        ssl_verify = provider.oidc.ssl_verify ~= false and "yes" or "no",

        -- Session options
        session_contents = { id_token = true, user = true, access_token = true },

        -- Logout
        logout_path = "/api/auth/logout",
        redirect_after_logout_uri = "/login",

        -- PKCE for added security
        use_pkce = provider.oidc.use_pkce ~= false,
    }

    -- Optional: specific endpoints (if not using discovery)
    if provider.oidc.authorization_endpoint then
        opts.authorization_endpoint = provider.oidc.authorization_endpoint
    end
    if provider.oidc.token_endpoint then
        opts.token_endpoint = provider.oidc.token_endpoint
    end
    if provider.oidc.userinfo_endpoint then
        opts.userinfo_endpoint = provider.oidc.userinfo_endpoint
    end
    if provider.oidc.jwks_uri then
        opts.jwks_uri = provider.oidc.jwks_uri
    end

    return opts
end

-- Map IdP claims to role and vhost scope
local function map_claims_to_role(provider, claims)
    local role_mapping = provider.role_mapping or {}
    local default_role = role_mapping.default_role or "viewer"
    local default_vhosts = role_mapping.default_vhosts or {"*"}

    -- Get the claim containing group/role information
    local claim_name = role_mapping.claim_name or "groups"
    local user_groups = claims[claim_name] or {}

    -- Ensure user_groups is a table
    if type(user_groups) == "string" then
        user_groups = { user_groups }
    end

    local mapped_role = default_role
    local mapped_vhosts = default_vhosts
    local highest_priority = 999

    -- Process role mappings
    local mappings = role_mapping.mappings or {}
    for _, mapping in ipairs(mappings) do
        local group_pattern = mapping.group
        local role = mapping.role
        local vhosts = mapping.vhosts or {"*"}
        local priority = mapping.priority or (role == "admin" and 1 or (role == "operator" and 2 or 3))

        -- Check if user has this group
        for _, user_group in ipairs(user_groups) do
            -- Support exact match or pattern match
            local matches = false
            if group_pattern:sub(1, 1) == "^" or group_pattern:sub(-1) == "$" then
                -- Regex pattern
                matches = ngx.re.match(user_group, group_pattern, "jo") ~= nil
            else
                -- Exact match
                matches = user_group == group_pattern
            end

            if matches and priority < highest_priority then
                mapped_role = role
                mapped_vhosts = vhosts
                highest_priority = priority
            end
        end
    end

    return mapped_role, mapped_vhosts
end

-- Just-In-Time (JIT) user provisioning
local function provision_user(provider, claims, role, vhost_scope)
    local red, err = get_redis()
    if not red then
        return nil, "Redis error: " .. (err or "unknown")
    end

    -- Determine username from claims
    local username = claims.preferred_username or claims.email or claims.sub
    if not username then
        close_redis(red)
        return nil, "Cannot determine username from claims"
    end

    -- Sanitize username
    username = username:gsub("[^a-zA-Z0-9_.-]", "_")

    -- Check if user exists
    local user_json = red:get(USER_KEY_PREFIX .. username)
    local user = nil

    if user_json and user_json ~= ngx.null then
        -- Update existing user
        user = cjson.decode(user_json)
        if user then
            -- Update SSO-related fields but preserve some local settings
            user.display_name = claims.name or claims.given_name or user.display_name
            user.email = claims.email or user.email
            user.last_login = os.date("!%Y-%m-%dT%H:%M:%SZ")

            -- Update role and vhost_scope from IdP (SSO is authoritative)
            if provider.role_mapping and provider.role_mapping.sync_on_login ~= false then
                user.role = role
                user.vhost_scope = vhost_scope
            end

            user.external_id = claims.sub
            user.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
        end
    else
        -- Create new user (JIT provisioning)
        user = {
            username = username,
            role = role,
            vhost_scope = vhost_scope,
            auth_provider = "oidc",
            provider_id = provider.id,
            external_id = claims.sub,
            display_name = claims.name or claims.given_name,
            email = claims.email,
            enabled = true,
            must_change_password = false,  -- No password for SSO users
            created_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            last_login = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
    end

    -- Save user
    local ok, err = red:set(USER_KEY_PREFIX .. username, cjson.encode(user))
    close_redis(red)

    if not ok then
        return nil, "Failed to save user: " .. (err or "unknown")
    end

    return user
end

-- Create session for authenticated user
local function create_session(user)
    local red, err = get_redis()
    if not red then
        return nil, "Redis error: " .. (err or "unknown")
    end

    local session_id = generate_random_string(32)
    local session_data = {
        username = user.username,
        role = user.role,
        vhost_scope = user.vhost_scope,
        auth_provider = user.auth_provider,
        provider_id = user.provider_id,
        created_at = ngx.time(),
        expires_at = ngx.time() + SESSION_TTL,
    }

    local ok, err = red:setex(
        SESSION_KEY_PREFIX .. session_id,
        SESSION_TTL,
        cjson.encode(session_data)
    )
    close_redis(red)

    if not ok then
        return nil, "Failed to create session: " .. (err or "unknown")
    end

    return session_id, session_data
end

-- Initiate OIDC authentication flow
function _M.authenticate(provider_id)
    -- Load provider configuration
    local provider, err = _M.get_provider(provider_id)
    if not provider then
        return nil, err
    end

    if not provider.enabled then
        return nil, "Provider is disabled"
    end

    if provider.type ~= "oidc" then
        return nil, "Provider is not OIDC type"
    end

    -- Try to load lua-resty-openidc
    local openidc_ok, openidc = pcall(require, "resty.openidc")
    if not openidc_ok then
        ngx.log(ngx.ERR, "lua-resty-openidc not available: ", openidc)
        return nil, "OIDC library not available"
    end

    -- Build OIDC configuration
    local opts = build_oidc_config(provider)

    -- Store provider_id in state for callback
    opts.state = provider_id .. ":" .. generate_random_string(16)

    -- Initiate authentication
    local res, err, target_url, session = openidc.authenticate(opts)

    if err then
        ngx.log(ngx.ERR, "OIDC authentication error: ", err)
        return nil, "Authentication failed: " .. err
    end

    -- If we get here with a result, authentication was successful
    if res then
        -- Map claims to role
        local role, vhost_scope = map_claims_to_role(provider, res.user or res.id_token)

        -- Provision/update user
        local user, err = provision_user(provider, res.user or res.id_token, role, vhost_scope)
        if not user then
            return nil, "User provisioning failed: " .. (err or "unknown")
        end

        -- Check if user is enabled
        if user.enabled == false then
            return nil, "User account is disabled"
        end

        -- Create session
        local session_id, session_data = create_session(user)
        if not session_id then
            return nil, "Failed to create session"
        end

        return {
            session_id = session_id,
            user = {
                username = user.username,
                role = user.role,
                vhost_scope = user.vhost_scope,
                auth_provider = user.auth_provider,
                display_name = user.display_name,
                email = user.email,
            }
        }
    end

    -- If no result, we're in the redirect phase
    return nil, nil  -- Redirect is happening
end

-- Handle OIDC callback
function _M.handle_callback()
    local args = ngx.req.get_uri_args()

    -- Check for error from IdP
    if args.error then
        ngx.log(ngx.ERR, "OIDC callback error: ", args.error, " - ", args.error_description)
        return nil, args.error_description or args.error
    end

    -- Extract provider_id from state
    local state = args.state or ""
    local provider_id = state:match("^([^:]+):")

    if not provider_id then
        return nil, "Invalid state parameter"
    end

    -- Load provider configuration
    local provider, err = _M.get_provider(provider_id)
    if not provider then
        return nil, err
    end

    -- Try to load lua-resty-openidc
    local openidc_ok, openidc = pcall(require, "resty.openidc")
    if not openidc_ok then
        return nil, "OIDC library not available"
    end

    -- Build OIDC configuration
    local opts = build_oidc_config(provider)

    -- Complete the authentication
    local res, err = openidc.authenticate(opts)

    if err then
        ngx.log(ngx.ERR, "OIDC callback authentication error: ", err)
        return nil, "Authentication failed: " .. err
    end

    if not res then
        return nil, "No authentication result"
    end

    -- Map claims to role
    local claims = res.user or res.id_token or {}
    local role, vhost_scope = map_claims_to_role(provider, claims)

    -- Provision/update user
    local user, err = provision_user(provider, claims, role, vhost_scope)
    if not user then
        return nil, "User provisioning failed: " .. (err or "unknown")
    end

    -- Check if user is enabled
    if user.enabled == false then
        return nil, "User account is disabled"
    end

    -- Create session
    local session_id, session_data = create_session(user)
    if not session_id then
        return nil, "Failed to create session"
    end

    return {
        session_id = session_id,
        user = {
            username = user.username,
            role = user.role,
            vhost_scope = user.vhost_scope,
            auth_provider = user.auth_provider,
            display_name = user.display_name,
            email = user.email,
        }
    }
end

-- Test provider connection (validates configuration)
function _M.test_provider(provider_id)
    local provider, err = _M.get_provider(provider_id)
    if not provider then
        return { success = false, message = err }
    end

    if provider.type ~= "oidc" then
        return { success = false, message = "Provider is not OIDC type" }
    end

    -- Try to fetch the discovery document
    local http = require "resty.http"
    local httpc = http.new()

    local discovery_url = provider.oidc.discovery or (provider.oidc.issuer .. "/.well-known/openid-configuration")

    local res, err = httpc:request_uri(discovery_url, {
        method = "GET",
        ssl_verify = provider.oidc.ssl_verify ~= false,
        timeout = 5000,
    })

    if not res then
        return { success = false, message = "Failed to reach discovery endpoint: " .. (err or "unknown") }
    end

    if res.status ~= 200 then
        return { success = false, message = "Discovery endpoint returned status " .. res.status }
    end

    local discovery = cjson.decode(res.body)
    if not discovery then
        return { success = false, message = "Invalid discovery document" }
    end

    -- Verify required fields
    if not discovery.authorization_endpoint then
        return { success = false, message = "Discovery missing authorization_endpoint" }
    end

    if not discovery.token_endpoint then
        return { success = false, message = "Discovery missing token_endpoint" }
    end

    return {
        success = true,
        message = "Provider configuration is valid",
        issuer = discovery.issuer,
        endpoints = {
            authorization = discovery.authorization_endpoint,
            token = discovery.token_endpoint,
            userinfo = discovery.userinfo_endpoint,
        }
    }
end

return _M
