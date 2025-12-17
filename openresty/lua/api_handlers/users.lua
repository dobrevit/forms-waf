-- api_handlers/users.lua
-- User management API handlers

local _M = {}

local cjson = require "cjson.safe"
local utils = require "api_handlers.utils"

local USER_KEY_PREFIX = "waf:admin:users:"

-- Helper: Generate random salt
local function generate_salt(length)
    length = length or 16
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local salt = {}
    for i = 1, length do
        local rand = math.random(1, #chars)
        table.insert(salt, chars:sub(rand, rand))
    end
    return table.concat(salt)
end

-- Helper: Hash password with salt (same as admin_auth.lua)
local function hash_password(password, salt)
    local resty_sha256 = require "resty.sha256"
    local resty_string = require "resty.string"
    local sha256 = resty_sha256:new()
    sha256:update(salt .. password .. salt)
    local digest = sha256:final()
    return resty_string.to_hex(digest)
end

-- Helper: Generate temporary password
local function generate_temp_password()
    local chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    local password = {}
    for i = 1, 12 do
        local rand = math.random(1, #chars)
        table.insert(password, chars:sub(rand, rand))
    end
    return table.concat(password)
end

-- GET /api/users - List all users
function _M.list()
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Get all user keys
    local keys = red:keys(USER_KEY_PREFIX .. "*")
    local users = {}

    if keys and type(keys) == "table" then
        for _, key in ipairs(keys) do
            local user_json = red:get(key)
            if user_json and user_json ~= ngx.null then
                local user = cjson.decode(user_json)
                if user then
                    -- Don't expose sensitive fields
                    table.insert(users, {
                        username = user.username,
                        role = user.role or "viewer",
                        vhost_scope = user.vhost_scope or {"*"},
                        auth_provider = user.auth_provider or "local",
                        display_name = user.display_name,
                        email = user.email,
                        enabled = user.enabled ~= false,
                        must_change_password = user.must_change_password or false,
                        created_at = user.created_at,
                        last_login = user.last_login
                    })
                end
            end
        end
    end

    utils.close_redis(red)
    return utils.json_response({ users = users })
end

-- POST /api/users - Create new local user
function _M.create()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate required fields
    if not data.username or data.username == "" then
        return utils.error_response("Username is required")
    end

    if not data.username:match("^[a-zA-Z0-9_-]+$") then
        return utils.error_response("Username can only contain letters, numbers, underscores, and hyphens")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if user already exists
    local existing = red:get(USER_KEY_PREFIX .. data.username)
    if existing and existing ~= ngx.null then
        utils.close_redis(red)
        return utils.error_response("User already exists: " .. data.username, 409)
    end

    -- Generate password if not provided
    local password = data.password
    local must_change = true
    if not password or password == "" then
        password = generate_temp_password()
    else
        if #password < 8 then
            utils.close_redis(red)
            return utils.error_response("Password must be at least 8 characters")
        end
        must_change = data.must_change_password ~= false
    end

    -- Hash password
    local salt = generate_salt(16)
    local password_hash = hash_password(password, salt)

    -- Validate role
    local role = data.role or "viewer"
    if role ~= "admin" and role ~= "operator" and role ~= "viewer" then
        utils.close_redis(red)
        return utils.error_response("Invalid role. Must be: admin, operator, or viewer")
    end

    -- Validate vhost_scope
    local vhost_scope = data.vhost_scope or {"*"}
    if type(vhost_scope) ~= "table" then
        vhost_scope = {"*"}
    end

    -- Create user object
    local user = {
        username = data.username,
        password_hash = password_hash,
        salt = salt,
        role = role,
        vhost_scope = vhost_scope,
        auth_provider = "local",
        display_name = data.display_name,
        email = data.email,
        enabled = true,
        must_change_password = must_change,
        created_at = os.date("!%Y-%m-%dT%H:%M:%SZ")
    }

    -- Store user
    local ok, err = red:set(USER_KEY_PREFIX .. data.username, cjson.encode(user))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to create user: " .. (err or "unknown"), 500)
    end

    -- Return user info (include temp password if generated)
    local response = {
        success = true,
        user = {
            username = user.username,
            role = user.role,
            vhost_scope = user.vhost_scope,
            auth_provider = user.auth_provider,
            display_name = user.display_name,
            email = user.email,
            enabled = user.enabled,
            must_change_password = user.must_change_password,
            created_at = user.created_at
        }
    }

    -- Include temporary password if it was generated
    if data.password == nil or data.password == "" then
        response.temporary_password = password
        response.message = "User created with temporary password. User must change password on first login."
    end

    return utils.json_response(response, 201)
end

-- GET /api/users/{username} - Get specific user
function _M.get(username)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local user_json = red:get(USER_KEY_PREFIX .. username)
    utils.close_redis(red)

    if not user_json or user_json == ngx.null then
        return utils.error_response("User not found: " .. username, 404)
    end

    local user = cjson.decode(user_json)
    if not user then
        return utils.error_response("Invalid user data", 500)
    end

    -- Don't expose sensitive fields
    return utils.json_response({
        user = {
            username = user.username,
            role = user.role or "viewer",
            vhost_scope = user.vhost_scope or {"*"},
            auth_provider = user.auth_provider or "local",
            display_name = user.display_name,
            email = user.email,
            enabled = user.enabled ~= false,
            must_change_password = user.must_change_password or false,
            created_at = user.created_at,
            last_login = user.last_login
        }
    })
end

-- PUT /api/users/{username} - Update user
function _M.update(username)
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

    local user_json = red:get(USER_KEY_PREFIX .. username)
    if not user_json or user_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("User not found: " .. username, 404)
    end

    local user = cjson.decode(user_json)
    if not user then
        utils.close_redis(red)
        return utils.error_response("Invalid user data", 500)
    end

    -- Check if this would remove the last admin
    local is_demoting_admin = user.role == "admin" and data.role ~= nil and data.role ~= "admin"
    local is_disabling_admin = user.role == "admin" and data.enabled == false and user.enabled ~= false

    if is_demoting_admin or is_disabling_admin then
        -- Count how many enabled admins exist
        local admin_count = 0
        local keys = red:keys(USER_KEY_PREFIX .. "*")
        if keys and type(keys) == "table" then
            for _, key in ipairs(keys) do
                local other_json = red:get(key)
                if other_json and other_json ~= ngx.null then
                    local other = cjson.decode(other_json)
                    if other and other.role == "admin" and other.enabled ~= false then
                        admin_count = admin_count + 1
                    end
                end
            end
        end

        if admin_count <= 1 then
            utils.close_redis(red)
            if is_demoting_admin then
                return utils.error_response("Cannot demote the last admin. Promote another user to admin first.", 400)
            else
                return utils.error_response("Cannot disable the last admin. Promote another user to admin first.", 400)
            end
        end
    end

    -- Update allowed fields
    if data.role ~= nil then
        if data.role ~= "admin" and data.role ~= "operator" and data.role ~= "viewer" then
            utils.close_redis(red)
            return utils.error_response("Invalid role. Must be: admin, operator, or viewer")
        end
        user.role = data.role
    end

    if data.vhost_scope ~= nil then
        if type(data.vhost_scope) == "table" then
            user.vhost_scope = data.vhost_scope
        end
    end

    if data.display_name ~= nil then
        user.display_name = data.display_name
    end

    if data.email ~= nil then
        user.email = data.email
    end

    if data.enabled ~= nil then
        user.enabled = data.enabled
    end

    user.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")

    -- Save updated user
    local ok, err = red:set(USER_KEY_PREFIX .. username, cjson.encode(user))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to update user: " .. (err or "unknown"), 500)
    end

    return utils.json_response({
        success = true,
        user = {
            username = user.username,
            role = user.role,
            vhost_scope = user.vhost_scope,
            auth_provider = user.auth_provider,
            display_name = user.display_name,
            email = user.email,
            enabled = user.enabled,
            must_change_password = user.must_change_password,
            created_at = user.created_at,
            updated_at = user.updated_at
        }
    })
end

-- DELETE /api/users/{username} - Delete user
function _M.delete(username)
    -- Prevent deleting self
    local session = ngx.ctx.admin_user
    if session and session.username == username then
        return utils.error_response("Cannot delete your own account", 400)
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    -- Check if user exists
    local user_json = red:get(USER_KEY_PREFIX .. username)
    if not user_json or user_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("User not found: " .. username, 404)
    end

    local user = cjson.decode(user_json)

    -- Prevent deleting the last admin
    if user and user.role == "admin" then
        local admin_count = 0
        local keys = red:keys(USER_KEY_PREFIX .. "*")
        if keys and type(keys) == "table" then
            for _, key in ipairs(keys) do
                local other_json = red:get(key)
                if other_json and other_json ~= ngx.null then
                    local other = cjson.decode(other_json)
                    if other and other.role == "admin" and other.enabled ~= false then
                        admin_count = admin_count + 1
                    end
                end
            end
        end

        if admin_count <= 1 then
            utils.close_redis(red)
            return utils.error_response("Cannot delete the last admin. Promote another user to admin first.", 400)
        end
    end

    -- Delete user
    red:del(USER_KEY_PREFIX .. username)

    -- Also delete any active sessions for this user
    local session_keys = red:keys("waf:admin:sessions:*")
    if session_keys and type(session_keys) == "table" then
        for _, key in ipairs(session_keys) do
            local sess_json = red:get(key)
            if sess_json and sess_json ~= ngx.null then
                local sess = cjson.decode(sess_json)
                if sess and sess.username == username then
                    red:del(key)
                end
            end
        end
    end

    utils.close_redis(red)

    return utils.json_response({
        success = true,
        message = "User deleted: " .. username
    })
end

-- POST /api/users/{username}/reset-password - Reset user password
function _M.reset_password(username)
    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis error: " .. (err or "unknown"), 500)
    end

    local user_json = red:get(USER_KEY_PREFIX .. username)
    if not user_json or user_json == ngx.null then
        utils.close_redis(red)
        return utils.error_response("User not found: " .. username, 404)
    end

    local user = cjson.decode(user_json)
    if not user then
        utils.close_redis(red)
        return utils.error_response("Invalid user data", 500)
    end

    -- Only allow password reset for local users
    if user.auth_provider and user.auth_provider ~= "local" then
        utils.close_redis(red)
        return utils.error_response("Cannot reset password for SSO users", 400)
    end

    -- Generate new temporary password
    local temp_password = generate_temp_password()
    local salt = generate_salt(16)
    local password_hash = hash_password(temp_password, salt)

    -- Update user
    user.password_hash = password_hash
    user.salt = salt
    user.must_change_password = true
    user.password_changed_at = nil
    user.updated_at = os.date("!%Y-%m-%dT%H:%M:%SZ")

    local ok, err = red:set(USER_KEY_PREFIX .. username, cjson.encode(user))
    utils.close_redis(red)

    if not ok then
        return utils.error_response("Failed to reset password: " .. (err or "unknown"), 500)
    end

    return utils.json_response({
        success = true,
        temporary_password = temp_password,
        message = "Password reset. User must change password on next login."
    })
end

-- Register handlers with main router
function _M.register(handlers, param_handlers)
    handlers["GET:/users"] = _M.list
    handlers["POST:/users"] = _M.create

    param_handlers.users = {
        ["GET"] = _M.get,
        ["PUT"] = _M.update,
        ["DELETE"] = _M.delete,
        ["POST:reset-password"] = _M.reset_password,
    }
end

return _M
