-- rbac.lua
-- Role-Based Access Control for WAF Admin API
-- Handles permission checking and vhost scoping

local cjson = require "cjson.safe"
local redis = require "resty.redis"
local resty_sha256 = require "resty.sha256"
local resty_string = require "resty.string"

local _M = {}

-- Redis configuration
local REDIS_HOST = os.getenv("REDIS_HOST") or "redis"
local REDIS_PORT = tonumber(os.getenv("REDIS_PORT")) or 6379
local REDIS_PASSWORD = os.getenv("REDIS_PASSWORD") or nil

-- Redis key prefixes
local ROLE_KEY_PREFIX = "waf:auth:roles:config:"
local USER_KEY_PREFIX = "waf:admin:users:"
local VHOST_KEY_PREFIX = "waf:vhosts:config:"
local ENDPOINT_KEY_PREFIX = "waf:endpoints:config:"

-- Default role definitions (authoritative source - seeded to Redis on startup)
local DEFAULT_ROLES = {
    admin = {
        id = "admin",
        name = "Administrator",
        description = "Full access to all resources",
        permissions = {
            vhosts = {"create", "read", "update", "delete", "enable", "disable"},
            endpoints = {"create", "read", "update", "delete", "enable", "disable"},
            keywords = {"create", "read", "update", "delete"},
            config = {"read", "update"},
            users = {"create", "read", "update", "delete"},
            providers = {"create", "read", "update", "delete"},
            logs = {"read"},
            metrics = {"read", "reset"},
            bulk = {"import", "export", "clear"},
            captcha = {"create", "read", "update", "delete", "enable", "disable", "test"},
            webhooks = {"read", "update", "test"},
            geoip = {"read", "update", "reload"},
            reputation = {"read", "update"},
            timing = {"read", "update"},
            behavioral = {"read", "update"},
            cluster = {"read"},
            sync = {"execute"},
            status = {"read"},
            hashes = {"read", "create"},
            whitelist = {"read", "create", "delete"},
            fingerprint_profiles = {"create", "read", "update", "delete", "test", "reset"}
        },
        scope = "global"  -- Can access all vhosts
    },
    operator = {
        id = "operator",
        name = "Operator",
        description = "Can manage vhosts, endpoints, keywords; view logs and metrics",
        permissions = {
            vhosts = {"read", "update", "enable", "disable"},
            endpoints = {"create", "read", "update", "delete", "enable", "disable"},
            keywords = {"create", "read", "update", "delete"},
            config = {"read"},
            logs = {"read"},
            metrics = {"read"},
            bulk = {"import", "export"},
            captcha = {"read"},
            webhooks = {"read"},
            geoip = {"read"},
            reputation = {"read"},
            timing = {"read"},
            behavioral = {"read"},
            cluster = {"read"},
            status = {"read"},
            hashes = {"read", "create"},
            whitelist = {"read"},
            fingerprint_profiles = {"read", "update", "test"}
        },
        scope = "vhost-scoped"  -- Can only access assigned vhosts
    },
    viewer = {
        id = "viewer",
        name = "Viewer",
        description = "Read-only access to all resources",
        permissions = {
            vhosts = {"read"},
            endpoints = {"read"},
            keywords = {"read"},
            config = {"read"},
            logs = {"read"},
            metrics = {"read"},
            captcha = {"read"},
            webhooks = {"read"},
            geoip = {"read"},
            reputation = {"read"},
            timing = {"read"},
            behavioral = {"read"},
            cluster = {"read"},
            status = {"read"},
            hashes = {"read"},
            whitelist = {"read"},
            fingerprint_profiles = {"read"}
        },
        scope = "vhost-scoped"
    }
}

-- Endpoint permission mapping
-- Maps API endpoints to resource/action pairs
local ENDPOINT_PERMISSIONS = {
    -- Status and Metrics
    ["GET:/status"] = {resource = "status", action = "read"},
    ["GET:/metrics"] = {resource = "metrics", action = "read"},
    ["POST:/metrics/reset"] = {resource = "metrics", action = "reset"},

    -- Keywords
    ["GET:/keywords/blocked"] = {resource = "keywords", action = "read"},
    ["POST:/keywords/blocked"] = {resource = "keywords", action = "create"},
    ["DELETE:/keywords/blocked"] = {resource = "keywords", action = "delete"},
    ["PUT:/keywords/blocked"] = {resource = "keywords", action = "update"},
    ["GET:/keywords/flagged"] = {resource = "keywords", action = "read"},
    ["POST:/keywords/flagged"] = {resource = "keywords", action = "create"},
    ["DELETE:/keywords/flagged"] = {resource = "keywords", action = "delete"},
    ["PUT:/keywords/flagged"] = {resource = "keywords", action = "update"},

    -- Hashes
    ["GET:/hashes/blocked"] = {resource = "hashes", action = "read"},
    ["POST:/hashes/blocked"] = {resource = "hashes", action = "create"},

    -- IP Whitelist
    ["GET:/whitelist/ips"] = {resource = "whitelist", action = "read"},
    ["POST:/whitelist/ips"] = {resource = "whitelist", action = "create"},
    ["DELETE:/whitelist/ips"] = {resource = "whitelist", action = "delete"},

    -- Sync
    ["POST:/sync"] = {resource = "sync", action = "execute"},

    -- Config
    ["GET:/config/thresholds"] = {resource = "config", action = "read"},
    ["POST:/config/thresholds"] = {resource = "config", action = "update"},
    ["GET:/config/routing"] = {resource = "config", action = "read"},
    ["PUT:/config/routing"] = {resource = "config", action = "update"},

    -- Endpoints (list/stats/match/learning)
    ["GET:/endpoints"] = {resource = "endpoints", action = "read"},
    ["GET:/endpoints/stats"] = {resource = "endpoints", action = "read"},
    ["GET:/endpoints/match"] = {resource = "endpoints", action = "read"},
    ["GET:/endpoints/learned-fields"] = {resource = "endpoints", action = "read"},
    ["DELETE:/endpoints/learned-fields"] = {resource = "endpoints", action = "delete"},
    ["POST:/endpoints"] = {resource = "endpoints", action = "create"},

    -- Vhosts (list/stats/match/context/learning)
    ["GET:/vhosts"] = {resource = "vhosts", action = "read"},
    ["GET:/vhosts/stats"] = {resource = "vhosts", action = "read"},
    ["GET:/vhosts/match"] = {resource = "vhosts", action = "read"},
    ["GET:/vhosts/context"] = {resource = "vhosts", action = "read"},
    ["GET:/vhosts/learned-fields"] = {resource = "vhosts", action = "read"},
    ["DELETE:/vhosts/learned-fields"] = {resource = "vhosts", action = "delete"},
    ["POST:/vhosts"] = {resource = "vhosts", action = "create"},

    -- Learning stats
    ["GET:/learning/stats"] = {resource = "endpoints", action = "read"},

    -- CAPTCHA
    ["GET:/captcha/providers"] = {resource = "captcha", action = "read"},
    ["POST:/captcha/providers"] = {resource = "captcha", action = "create"},
    ["GET:/captcha/config"] = {resource = "captcha", action = "read"},
    ["PUT:/captcha/config"] = {resource = "captcha", action = "update"},

    -- Webhooks
    ["GET:/webhooks/config"] = {resource = "webhooks", action = "read"},
    ["PUT:/webhooks/config"] = {resource = "webhooks", action = "update"},
    ["POST:/webhooks/test"] = {resource = "webhooks", action = "test"},
    ["GET:/webhooks/stats"] = {resource = "webhooks", action = "read"},

    -- Bulk operations
    ["GET:/bulk/export/keywords"] = {resource = "bulk", action = "export"},
    ["POST:/bulk/import/keywords"] = {resource = "bulk", action = "import"},
    ["GET:/bulk/export/ips"] = {resource = "bulk", action = "export"},
    ["POST:/bulk/import/ips"] = {resource = "bulk", action = "import"},
    ["GET:/bulk/export/hashes"] = {resource = "bulk", action = "export"},
    ["POST:/bulk/import/hashes"] = {resource = "bulk", action = "import"},
    ["DELETE:/bulk/clear/keywords"] = {resource = "bulk", action = "clear"},
    ["GET:/bulk/export/all"] = {resource = "bulk", action = "export"},

    -- GeoIP
    ["GET:/geoip/status"] = {resource = "geoip", action = "read"},
    ["GET:/geoip/config"] = {resource = "geoip", action = "read"},
    ["PUT:/geoip/config"] = {resource = "geoip", action = "update"},
    ["POST:/geoip/reload"] = {resource = "geoip", action = "reload"},
    ["GET:/geoip/lookup"] = {resource = "geoip", action = "read"},

    -- Reputation
    ["GET:/reputation/status"] = {resource = "reputation", action = "read"},
    ["GET:/reputation/config"] = {resource = "reputation", action = "read"},
    ["PUT:/reputation/config"] = {resource = "reputation", action = "update"},
    ["GET:/reputation/check"] = {resource = "reputation", action = "read"},
    ["GET:/reputation/blocklist"] = {resource = "reputation", action = "read"},
    ["POST:/reputation/blocklist"] = {resource = "reputation", action = "update"},
    ["DELETE:/reputation/blocklist"] = {resource = "reputation", action = "update"},
    ["DELETE:/reputation/cache"] = {resource = "reputation", action = "update"},

    -- Timing token
    ["GET:/timing/status"] = {resource = "timing", action = "read"},
    ["GET:/timing/config"] = {resource = "timing", action = "read"},
    ["PUT:/timing/config"] = {resource = "timing", action = "update"},

    -- Behavioral tracking
    ["GET:/behavioral/summary"] = {resource = "metrics", action = "read"},
    ["GET:/behavioral/stats"] = {resource = "metrics", action = "read"},
    ["GET:/behavioral/baseline"] = {resource = "metrics", action = "read"},
    ["GET:/behavioral/flows"] = {resource = "metrics", action = "read"},
    ["GET:/behavioral/vhosts"] = {resource = "metrics", action = "read"},
    ["POST:/behavioral/recalculate"] = {resource = "metrics", action = "reset"},

    -- User management (admin only - will be added later)
    ["GET:/users"] = {resource = "users", action = "read"},
    ["POST:/users"] = {resource = "users", action = "create"},
    ["GET:/users/{id}"] = {resource = "users", action = "read"},
    ["PUT:/users/{id}"] = {resource = "users", action = "update"},
    ["DELETE:/users/{id}"] = {resource = "users", action = "delete"},
    ["POST:/users/{id}/reset-password"] = {resource = "users", action = "update"},

    -- Auth provider management (admin only - will be added later)
    ["GET:/auth/providers/config"] = {resource = "providers", action = "read"},
    ["POST:/auth/providers/config"] = {resource = "providers", action = "create"},
    ["PUT:/auth/providers/config/{id}"] = {resource = "providers", action = "update"},
    ["DELETE:/auth/providers/config/{id}"] = {resource = "providers", action = "delete"},

    -- Cluster status
    ["GET:/cluster/status"] = {resource = "cluster", action = "read"},
    ["GET:/cluster/instances"] = {resource = "cluster", action = "read"},
    ["GET:/cluster/leader"] = {resource = "cluster", action = "read"},
    ["GET:/cluster/config"] = {resource = "cluster", action = "read"},
    ["GET:/cluster/this"] = {resource = "cluster", action = "read"},

    -- Fingerprint profiles
    ["GET:/fingerprint-profiles"] = {resource = "fingerprint_profiles", action = "read"},
    ["POST:/fingerprint-profiles"] = {resource = "fingerprint_profiles", action = "create"},
    ["POST:/fingerprint-profiles/test"] = {resource = "fingerprint_profiles", action = "test"},
    ["POST:/fingerprint-profiles/reset-builtin"] = {resource = "fingerprint_profiles", action = "reset"},
}

-- Parametric endpoint permissions (for /endpoints/{id}, /vhosts/{id}, etc.)
local PARAMETRIC_PERMISSIONS = {
    -- Endpoints
    endpoints = {
        ["GET"] = {resource = "endpoints", action = "read", scoped = true},
        ["PUT"] = {resource = "endpoints", action = "update", scoped = true},
        ["DELETE"] = {resource = "endpoints", action = "delete", scoped = true},
        ["POST:enable"] = {resource = "endpoints", action = "enable", scoped = true},
        ["POST:disable"] = {resource = "endpoints", action = "disable", scoped = true},
    },
    -- Vhosts
    vhosts = {
        ["GET"] = {resource = "vhosts", action = "read", scoped = true},
        ["PUT"] = {resource = "vhosts", action = "update", scoped = true},
        ["DELETE"] = {resource = "vhosts", action = "delete", scoped = true},
        ["POST:enable"] = {resource = "vhosts", action = "enable", scoped = true},
        ["POST:disable"] = {resource = "vhosts", action = "disable", scoped = true},
    },
    -- CAPTCHA providers
    captcha_providers = {
        ["GET"] = {resource = "captcha", action = "read"},
        ["PUT"] = {resource = "captcha", action = "update"},
        ["DELETE"] = {resource = "captcha", action = "delete"},
        ["POST:test"] = {resource = "captcha", action = "test"},
        ["POST:enable"] = {resource = "captcha", action = "enable"},
        ["POST:disable"] = {resource = "captcha", action = "disable"},
    },
    -- Users
    users = {
        ["GET"] = {resource = "users", action = "read"},
        ["PUT"] = {resource = "users", action = "update"},
        ["DELETE"] = {resource = "users", action = "delete"},
        ["POST:reset-password"] = {resource = "users", action = "update"},
    },
    -- Auth providers
    auth_providers = {
        ["GET"] = {resource = "providers", action = "read"},
        ["PUT"] = {resource = "providers", action = "update"},
        ["DELETE"] = {resource = "providers", action = "delete"},
        ["POST:test"] = {resource = "providers", action = "read"},
        ["POST:enable"] = {resource = "providers", action = "update"},
        ["POST:disable"] = {resource = "providers", action = "update"},
    },
    -- Fingerprint profiles
    ["fingerprint-profiles"] = {
        ["GET"] = {resource = "fingerprint_profiles", action = "read"},
        ["PUT"] = {resource = "fingerprint_profiles", action = "update"},
        ["DELETE"] = {resource = "fingerprint_profiles", action = "delete"},
    },
}

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

-- Get role definition (from Redis or defaults)
function _M.get_role(role_id)
    if not role_id then
        return nil
    end

    -- Try Redis first
    local red, err = get_redis()
    if red then
        local role_json = red:get(ROLE_KEY_PREFIX .. role_id)
        close_redis(red)

        if role_json and role_json ~= ngx.null then
            local role = cjson.decode(role_json)
            if role then
                return role
            end
        end
    end

    -- Fall back to defaults
    return DEFAULT_ROLES[role_id]
end

-- Get all role definitions
function _M.get_all_roles()
    local roles = {}

    -- Try Redis first
    local red, err = get_redis()
    if red then
        local role_ids = red:smembers("waf:auth:roles:index")
        if role_ids and type(role_ids) == "table" then
            for _, role_id in ipairs(role_ids) do
                local role_json = red:get(ROLE_KEY_PREFIX .. role_id)
                if role_json and role_json ~= ngx.null then
                    local role = cjson.decode(role_json)
                    if role then
                        roles[role_id] = role
                    end
                end
            end
        end
        close_redis(red)
    end

    -- Merge with defaults (defaults take precedence if not in Redis)
    for role_id, role_def in pairs(DEFAULT_ROLES) do
        if not roles[role_id] then
            roles[role_id] = role_def
        end
    end

    return roles
end

-- Check if a role has a specific permission
function _M.role_has_permission(role_id, resource, action)
    local role = _M.get_role(role_id)
    if not role then
        return false
    end

    local resource_permissions = role.permissions[resource]
    if not resource_permissions then
        return false
    end

    for _, perm in ipairs(resource_permissions) do
        if perm == action then
            return true
        end
    end

    return false
end

-- Check if a vhost is in user's scope
function _M.is_vhost_in_scope(vhost_scope, vhost_id)
    if not vhost_scope or type(vhost_scope) ~= "table" or #vhost_scope == 0 then
        return false
    end

    for _, scope in ipairs(vhost_scope) do
        if scope == "*" then
            return true
        end
        if scope == vhost_id then
            return true
        end
    end

    return false
end

-- Get vhost_id for an endpoint (for scope checking)
function _M.get_endpoint_vhost(endpoint_id)
    local red, err = get_redis()
    if not red then
        return nil
    end

    local config_json = red:get(ENDPOINT_KEY_PREFIX .. endpoint_id)
    close_redis(red)

    if not config_json or config_json == ngx.null then
        return nil
    end

    local config = cjson.decode(config_json)
    if not config then
        return nil
    end

    return config.vhost_id  -- nil means global endpoint
end

-- Get permission requirement for an endpoint
function _M.get_endpoint_permission(method, path)
    -- First try exact match
    local key = method .. ":" .. path
    local perm = ENDPOINT_PERMISSIONS[key]
    if perm then
        return perm
    end

    -- Check for parametric endpoints
    local endpoint_id = path:match("^/endpoints/([a-zA-Z0-9_-]+)/?([a-z]*)$")
    if endpoint_id then
        local action = path:match("^/endpoints/[a-zA-Z0-9_-]+/([a-z]+)$")
        local handler_key = action and (method .. ":" .. action) or method
        return PARAMETRIC_PERMISSIONS.endpoints[handler_key], endpoint_id, "endpoint"
    end

    local vhost_id = path:match("^/vhosts/([a-zA-Z0-9_-]+)/?([a-z]*)$")
    if vhost_id then
        local action = path:match("^/vhosts/[a-zA-Z0-9_-]+/([a-z]+)$")
        local handler_key = action and (method .. ":" .. action) or method
        return PARAMETRIC_PERMISSIONS.vhosts[handler_key], vhost_id, "vhost"
    end

    local provider_id = path:match("^/captcha/providers/([a-zA-Z0-9_-]+)/?([a-z]*)$")
    if provider_id then
        local action = path:match("^/captcha/providers/[a-zA-Z0-9_-]+/([a-z]+)$")
        local handler_key = action and (method .. ":" .. action) or method
        return PARAMETRIC_PERMISSIONS.captcha_providers[handler_key], provider_id, "captcha"
    end

    local username = path:match("^/users/([a-zA-Z0-9_.-]+)/?([a-z-]*)$")
    if username then
        local action = path:match("^/users/[a-zA-Z0-9_.-]+/([a-z-]+)$")
        local handler_key = action and (method .. ":" .. action) or method
        return PARAMETRIC_PERMISSIONS.users[handler_key], username, "user"
    end

    local auth_provider_id = path:match("^/auth/providers/config/([a-zA-Z0-9_-]+)/?([a-z]*)$")
    if auth_provider_id then
        local action = path:match("^/auth/providers/config/[a-zA-Z0-9_-]+/([a-z]+)$")
        local handler_key = action and (method .. ":" .. action) or method
        return PARAMETRIC_PERMISSIONS.auth_providers[handler_key], auth_provider_id, "auth_provider"
    end

    local profile_id = path:match("^/fingerprint%-profiles/([a-zA-Z0-9_-]+)$")
    if profile_id and profile_id ~= "test" and profile_id ~= "reset-builtin" then
        return PARAMETRIC_PERMISSIONS["fingerprint-profiles"][method], profile_id, "fingerprint_profile"
    end

    return nil
end

-- Main permission check function
-- Returns: allowed (bool), error_message (string or nil)
function _M.check_permission(session, method, path)
    if not session then
        return false, "No session"
    end

    local role_id = session.role
    if not role_id then
        return false, "No role in session"
    end

    -- Get permission requirement for this endpoint
    local permission, resource_id, resource_type = _M.get_endpoint_permission(method, path)

    if not permission then
        -- Allow endpoints without explicit permission mapping (be careful!)
        -- In production, you might want to deny by default
        ngx.log(ngx.WARN, "RBAC: No permission mapping for ", method, " ", path)
        return true
    end

    -- Check if role has required permission
    if not _M.role_has_permission(role_id, permission.resource, permission.action) then
        return false, string.format("Permission denied: %s:%s required",
            permission.resource, permission.action)
    end

    -- Check vhost scope if applicable
    if permission.scoped and resource_id then
        local vhost_scope = session.vhost_scope

        -- Check scope based on resource type
        if resource_type == "vhost" then
            if not _M.is_vhost_in_scope(vhost_scope, resource_id) then
                return false, "Access denied: vhost " .. resource_id .. " not in scope"
            end
        elseif resource_type == "endpoint" then
            local vhost_id = _M.get_endpoint_vhost(resource_id)
            -- Global endpoints (vhost_id = nil) are accessible if user has any scope
            if vhost_id and not _M.is_vhost_in_scope(vhost_scope, vhost_id) then
                return false, "Access denied: endpoint belongs to vhost " .. vhost_id .. " not in scope"
            end
        end
    end

    return true
end

-- Middleware function to be called from admin_api
function _M.check_request()
    local session = ngx.ctx.admin_user
    if not session then
        ngx.status = 401
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Unauthorized",
            message = "Authentication required"
        }))
        return ngx.exit(401)
    end

    local method = ngx.req.get_method()
    local path = ngx.var.uri:match("/api(/.*)") or ngx.var.uri:match("/waf%-admin(/.*)") or "/"

    local allowed, err = _M.check_permission(session, method, path)
    if not allowed then
        ngx.status = 403
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Forbidden",
            message = err or "Permission denied"
        }))
        return ngx.exit(403)
    end

    return true
end

-- Get user's effective permissions (cached in session or computed)
function _M.get_user_permissions(session)
    if session.permissions then
        return session.permissions
    end

    local role = _M.get_role(session.role)
    if not role then
        return {}
    end

    return role.permissions
end

-- Filter vhosts by user's scope
function _M.filter_vhosts_by_scope(vhosts, session)
    if not session or not session.vhost_scope then
        return {}
    end

    -- Global scope returns all
    for _, scope in ipairs(session.vhost_scope) do
        if scope == "*" then
            return vhosts
        end
    end

    -- Filter to only scoped vhosts
    local filtered = {}
    for _, vhost in ipairs(vhosts) do
        if _M.is_vhost_in_scope(session.vhost_scope, vhost.id) then
            table.insert(filtered, vhost)
        end
    end

    return filtered
end

-- Filter endpoints by user's vhost scope
function _M.filter_endpoints_by_scope(endpoints, session)
    if not session or not session.vhost_scope then
        return {}
    end

    -- Global scope returns all
    for _, scope in ipairs(session.vhost_scope) do
        if scope == "*" then
            return endpoints
        end
    end

    -- Filter to only endpoints in scoped vhosts (or global endpoints)
    local filtered = {}
    for _, endpoint in ipairs(endpoints) do
        local vhost_id = endpoint.vhost_id
        -- Include global endpoints (no vhost_id) and scoped endpoints
        if not vhost_id or _M.is_vhost_in_scope(session.vhost_scope, vhost_id) then
            table.insert(filtered, endpoint)
        end
    end

    return filtered
end

-- Seed RBAC roles to Redis
-- This ensures roles are always up-to-date with the Lua definitions
-- Called on startup via init_worker_by_lua
function _M.seed_roles()
    local red, err = get_redis()
    if not red then
        ngx.log(ngx.WARN, "RBAC: Failed to connect to Redis for seeding: ", err)
        return false, err
    end

    local seeded = 0
    for role_id, role_def in pairs(DEFAULT_ROLES) do
        local role_json = cjson.encode(role_def)
        if role_json then
            local ok, err = red:set(ROLE_KEY_PREFIX .. role_id, role_json)
            if ok then
                seeded = seeded + 1
            else
                ngx.log(ngx.WARN, "RBAC: Failed to seed role ", role_id, ": ", err)
            end
        end
    end

    -- Update role index
    local role_ids = {}
    for role_id, _ in pairs(DEFAULT_ROLES) do
        table.insert(role_ids, role_id)
    end
    red:del("waf:auth:roles:index")
    if #role_ids > 0 then
        red:sadd("waf:auth:roles:index", unpack(role_ids))
    end

    close_redis(red)
    ngx.log(ngx.INFO, "RBAC: Seeded ", seeded, " roles to Redis")
    return true
end

-- Helper: Hash password with salt (same algorithm as admin_auth.lua)
local function hash_password(password, salt)
    local sha256 = resty_sha256:new()
    sha256:update(salt .. password .. salt)
    local digest = sha256:final()
    return resty_string.to_hex(digest)
end

-- Seed default admin user if not exists
-- Uses environment variables for salt and password
-- Called on startup via init_worker_by_lua
function _M.seed_default_admin()
    local admin_salt = os.getenv("WAF_ADMIN_SALT")
    local admin_password = os.getenv("WAF_ADMIN_PASSWORD") or "changeme"

    -- Salt is required for security - fail if not provided
    if not admin_salt or admin_salt == "" then
        ngx.log(ngx.WARN, "RBAC: WAF_ADMIN_SALT not set, skipping default admin seeding")
        ngx.log(ngx.WARN, "RBAC: Set WAF_ADMIN_SALT environment variable to enable default admin user")
        return false, "WAF_ADMIN_SALT not set"
    end

    local red, err = get_redis()
    if not red then
        ngx.log(ngx.WARN, "RBAC: Failed to connect to Redis for admin seeding: ", err)
        return false, err
    end

    -- Check if admin user already exists
    local existing = red:get(USER_KEY_PREFIX .. "admin")
    if existing and existing ~= ngx.null then
        close_redis(red)
        ngx.log(ngx.INFO, "RBAC: Admin user already exists, skipping seed")
        return true, "exists"
    end

    -- Create default admin user
    local password_hash = hash_password(admin_password, admin_salt)
    local admin_user = {
        username = "admin",
        password_hash = password_hash,
        salt = admin_salt,
        role = "admin",
        vhost_scope = {"*"},
        auth_provider = "local",
        must_change_password = (admin_password == "changeme"),
        created_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
    }

    local admin_json = cjson.encode(admin_user)
    local ok, err = red:set(USER_KEY_PREFIX .. "admin", admin_json)
    close_redis(red)

    if not ok then
        ngx.log(ngx.ERR, "RBAC: Failed to create default admin user: ", err)
        return false, err
    end

    ngx.log(ngx.INFO, "RBAC: Default admin user created (username: admin)")
    if admin_password == "changeme" then
        ngx.log(ngx.WARN, "RBAC: Using default password 'changeme' - change it immediately!")
    end

    return true, "created"
end

-- Get all defined roles (for admin API)
function _M.get_all_roles()
    local roles = {}
    for role_id, role_def in pairs(DEFAULT_ROLES) do
        roles[role_id] = role_def
    end
    return roles
end

return _M
