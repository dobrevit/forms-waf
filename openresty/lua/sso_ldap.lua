-- sso_ldap.lua
-- LDAP authentication module for SSO

local _M = {}

local cjson = require "cjson.safe"
local redis = require "resty.redis"
local ldap_client = require "ldap_client"

-- Redis configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil

-- Redis keys
local PROVIDER_KEY_PREFIX = "waf:auth:providers:config:"
local USER_KEY_PREFIX = "waf:admin:users:"
local SESSION_KEY_PREFIX = "waf:admin:sessions:"

-- Session configuration
local SESSION_TTL = tonumber(os.getenv("WAF_SESSION_TTL")) or 86400

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

-- Build user DN from template
local function build_user_dn(provider, username)
    local user_dn_template = provider.ldap.user_dn_template
    if user_dn_template then
        return user_dn_template:gsub("{username}", username)
    end

    -- Default: uid=username,base_dn
    local base_dn = provider.ldap.base_dn or ""
    return "uid=" .. username .. "," .. base_dn
end

-- Build search filter for user
local function build_user_filter(provider, username)
    local filter_template = provider.ldap.user_filter or "(uid={username})"
    return filter_template:gsub("{username}", username)
end

-- Build search filter for groups
local function build_group_filter(provider, user_dn, username)
    local filter_template = provider.ldap.group_filter or "(member={user_dn})"
    local filter = filter_template:gsub("{user_dn}", user_dn)
    filter = filter:gsub("{username}", username)
    return filter
end

-- Map LDAP groups to role and vhost scope
local function map_groups_to_role(provider, groups)
    local role_mapping = provider.role_mapping or {}
    local default_role = role_mapping.default_role or "viewer"
    local default_vhosts = role_mapping.default_vhosts or {"*"}

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
        for _, user_group in ipairs(groups) do
            local matches = false

            -- Extract CN from group DN if needed
            local group_cn = user_group:match("^cn=([^,]+)") or user_group

            -- Support exact match or pattern match
            if group_pattern:sub(1, 1) == "^" or group_pattern:sub(-1) == "$" then
                matches = ngx.re.match(group_cn, group_pattern, "jo") ~= nil
            else
                matches = group_cn == group_pattern or user_group == group_pattern
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

-- Search for user's groups
local function get_user_groups(ldap, provider, user_dn, username)
    local groups = {}

    local group_base_dn = provider.ldap.group_base_dn or provider.ldap.base_dn
    if not group_base_dn then
        return groups
    end

    local group_filter = build_group_filter(provider, user_dn, username)
    local group_attr = provider.ldap.group_attribute or "cn"

    local results, err = ldap:search(group_base_dn, 2, group_filter, {group_attr})
    if not results then
        ngx.log(ngx.WARN, "LDAP group search failed: ", err)
        return groups
    end

    for _, entry in ipairs(results) do
        if entry.dn then
            table.insert(groups, entry.dn)
        end
    end

    return groups
end

-- Just-In-Time user provisioning
local function provision_user(provider, username, user_info, role, vhost_scope)
    local red, err = get_redis()
    if not red then
        return nil, "Redis error: " .. (err or "unknown")
    end

    -- Sanitize username
    local safe_username = username:gsub("[^a-zA-Z0-9_.-]", "_")

    -- Check if user exists
    local user_json = red:get(USER_KEY_PREFIX .. safe_username)
    local user = nil

    if user_json and user_json ~= ngx.null then
        -- Update existing user
        user = cjson.decode(user_json)
        if user then
            user.last_login = os.date("!%Y-%m-%dT%H:%M:%SZ")

            -- Update role and vhost_scope from LDAP (if sync enabled)
            if provider.role_mapping and provider.role_mapping.sync_on_login ~= false then
                user.role = role
                user.vhost_scope = vhost_scope
            end

            -- Update user info if available
            if user_info then
                user.display_name = user_info.display_name or user.display_name
                user.email = user_info.email or user.email
            end

            user.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
        end
    else
        -- Create new user (JIT provisioning)
        user = {
            username = safe_username,
            role = role,
            vhost_scope = vhost_scope,
            auth_provider = "ldap",
            provider_id = provider.id,
            display_name = user_info and user_info.display_name or username,
            email = user_info and user_info.email,
            enabled = true,
            must_change_password = false,
            created_at = os.date("!%Y-%m-%dT%H:%M:%SZ"),
            last_login = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        }
    end

    -- Save user
    local ok, err = red:set(USER_KEY_PREFIX .. safe_username, cjson.encode(user))
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

-- Authenticate user via LDAP
function _M.authenticate(provider_id, username, password)
    if not username or username == "" then
        return nil, "Username is required"
    end

    if not password or password == "" then
        return nil, "Password is required"
    end

    -- Load provider configuration
    local provider, err = _M.get_provider(provider_id)
    if not provider then
        return nil, err
    end

    if not provider.enabled then
        return nil, "Provider is disabled"
    end

    if provider.type ~= "ldap" then
        return nil, "Provider is not LDAP type"
    end

    local ldap_config = provider.ldap
    if not ldap_config then
        return nil, "LDAP configuration is missing"
    end

    -- Create LDAP client
    local ldap = ldap_client.new({
        host = ldap_config.host or "localhost",
        port = ldap_config.port or 389,
        use_ssl = ldap_config.use_ssl or ldap_config.port == 636,
        ssl_verify = ldap_config.ssl_verify ~= false,
        timeout = ldap_config.timeout or 5000,
    })

    -- Connect to LDAP server
    local ok, err = ldap:connect()
    if not ok then
        return nil, "Failed to connect to LDAP server: " .. (err or "unknown")
    end

    -- Determine authentication method
    local user_dn
    local bind_success = false

    if ldap_config.bind_dn and ldap_config.bind_password then
        -- Two-step authentication: bind as service account, then search and rebind as user
        local ok, err = ldap:bind(ldap_config.bind_dn, ldap_config.bind_password)
        if not ok then
            ldap:close()
            return nil, "Service account bind failed: " .. (err or "unknown")
        end

        -- Search for user DN
        local user_filter = build_user_filter(provider, username)
        local base_dn = ldap_config.user_base_dn or ldap_config.base_dn

        local results, err = ldap:search(base_dn, 2, user_filter, {"dn"})
        if not results or #results == 0 then
            ldap:close()
            return nil, "User not found"
        end

        user_dn = results[1].dn

        -- Rebind as user to verify password
        ldap:close()

        -- Reconnect for user bind
        ldap = ldap_client.new({
            host = ldap_config.host or "localhost",
            port = ldap_config.port or 389,
            use_ssl = ldap_config.use_ssl or ldap_config.port == 636,
            ssl_verify = ldap_config.ssl_verify ~= false,
            timeout = ldap_config.timeout or 5000,
        })

        ok, err = ldap:connect()
        if not ok then
            return nil, "Failed to reconnect: " .. (err or "unknown")
        end

        ok, err = ldap:bind(user_dn, password)
        if not ok then
            ldap:close()
            return nil, "Invalid credentials"
        end

        bind_success = true
    else
        -- Direct bind: build user DN from template and bind directly
        user_dn = build_user_dn(provider, username)

        local ok, err = ldap:bind(user_dn, password)
        if not ok then
            ldap:close()
            return nil, "Invalid credentials"
        end

        bind_success = true
    end

    if not bind_success then
        ldap:close()
        return nil, "Authentication failed"
    end

    -- Get user's groups for role mapping
    local groups = {}
    if ldap_config.group_base_dn then
        -- Need to rebind as service account to search groups (if configured)
        if ldap_config.bind_dn and ldap_config.bind_password then
            ldap:close()

            ldap = ldap_client.new({
                host = ldap_config.host or "localhost",
                port = ldap_config.port or 389,
                use_ssl = ldap_config.use_ssl or ldap_config.port == 636,
                ssl_verify = ldap_config.ssl_verify ~= false,
                timeout = ldap_config.timeout or 5000,
            })

            local ok, err = ldap:connect()
            if ok then
                ok, err = ldap:bind(ldap_config.bind_dn, ldap_config.bind_password)
                if ok then
                    groups = get_user_groups(ldap, provider, user_dn, username)
                end
            end
        else
            groups = get_user_groups(ldap, provider, user_dn, username)
        end
    end

    ldap:close()

    -- Map groups to role
    local role, vhost_scope = map_groups_to_role(provider, groups)

    -- Provision/update user
    local user, err = provision_user(provider, username, nil, role, vhost_scope)
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

-- Test LDAP provider connection
function _M.test_provider(provider_id)
    local provider, err = _M.get_provider(provider_id)
    if not provider then
        return { success = false, message = err }
    end

    if provider.type ~= "ldap" then
        return { success = false, message = "Provider is not LDAP type" }
    end

    local ldap_config = provider.ldap
    if not ldap_config then
        return { success = false, message = "LDAP configuration is missing" }
    end

    -- Create LDAP client
    local ldap = ldap_client.new({
        host = ldap_config.host or "localhost",
        port = ldap_config.port or 389,
        use_ssl = ldap_config.use_ssl or ldap_config.port == 636,
        ssl_verify = ldap_config.ssl_verify ~= false,
        timeout = ldap_config.timeout or 5000,
    })

    -- Try to connect
    local ok, err = ldap:connect()
    if not ok then
        return { success = false, message = "Connection failed: " .. (err or "unknown") }
    end

    -- If service account credentials provided, try to bind
    if ldap_config.bind_dn and ldap_config.bind_password then
        ok, err = ldap:bind(ldap_config.bind_dn, ldap_config.bind_password)
        if not ok then
            ldap:close()
            return { success = false, message = "Service account bind failed: " .. (err or "unknown") }
        end
    else
        -- Try anonymous bind
        ok, err = ldap:bind("", "")
        -- Anonymous bind failure is not necessarily an error
    end

    ldap:close()

    return {
        success = true,
        message = "LDAP connection successful",
        host = ldap_config.host,
        port = ldap_config.port,
        ssl = ldap_config.use_ssl or ldap_config.port == 636,
    }
end

return _M
