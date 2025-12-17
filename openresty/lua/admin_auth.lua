-- admin_auth.lua
-- Authentication handler for admin UI
-- Handles login, logout, session verification, and password changes

local cjson = require "cjson.safe"
local resty_sha256 = require "resty.sha256"
local resty_string = require "resty.string"
local redis_sync = require "redis_sync"

local _M = {}

-- Configuration
local SESSION_TTL = 86400  -- 24 hours
local SESSION_COOKIE_NAME = "waf_admin_session"
local REDIS_PREFIX = "waf:admin:"

-- Helper: Generate random token
local function generate_token(length)
    length = length or 32
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local token = {}

    -- Use OpenResty's random generator
    for i = 1, length do
        local rand = math.random(1, #chars)
        table.insert(token, chars:sub(rand, rand))
    end

    return table.concat(token)
end

-- Helper: Hash password with salt
local function hash_password(password, salt)
    local sha256 = resty_sha256:new()
    sha256:update(salt .. password .. salt)
    local digest = sha256:final()
    return resty_string.to_hex(digest)
end

-- Helper: Send JSON response
local function send_json(status, data)
    ngx.status = status
    ngx.header["Content-Type"] = "application/json"
    ngx.say(cjson.encode(data))
    ngx.exit(status)
end

-- Helper: Read JSON body
local function read_json_body()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    if not body then
        return nil, "Empty request body"
    end

    local data, err = cjson.decode(body)
    if not data then
        return nil, "Invalid JSON: " .. (err or "unknown error")
    end

    return data
end

-- Helper: Get session from cookie
local function get_session_token()
    local cookies = ngx.var.http_cookie
    if not cookies then
        return nil
    end

    local pattern = SESSION_COOKIE_NAME .. "=([^;]+)"
    local token = cookies:match(pattern)
    return token
end

-- Helper: Set session cookie
local function set_session_cookie(token, max_age)
    local cookie = SESSION_COOKIE_NAME .. "=" .. token
    cookie = cookie .. "; Path=/; HttpOnly; SameSite=Strict"

    if max_age then
        cookie = cookie .. "; Max-Age=" .. max_age
    end

    -- In production, add Secure flag
    -- cookie = cookie .. "; Secure"

    ngx.header["Set-Cookie"] = cookie
end

-- Helper: Clear session cookie
local function clear_session_cookie()
    local cookie = SESSION_COOKIE_NAME .. "=; Path=/; HttpOnly; Max-Age=0"
    ngx.header["Set-Cookie"] = cookie
end

-- Get Redis connection
local function get_redis()
    local red, err = redis_sync.get_connection()
    if not red then
        ngx.log(ngx.ERR, "Failed to get Redis connection: ", err)
        return nil, err
    end
    return red
end

-- Close Redis connection
local function close_redis(red)
    redis_sync.return_connection(red)
end

-- Validate session token and return user data
function _M.validate_session(token)
    if not token then
        return nil, "No session token"
    end

    local red, err = get_redis()
    if not red then
        return nil, err
    end

    local session_key = REDIS_PREFIX .. "sessions:" .. token
    local session_data, err = red:get(session_key)
    close_redis(red)

    if not session_data or session_data == ngx.null then
        return nil, "Session not found or expired"
    end

    local session, err = cjson.decode(session_data)
    if not session then
        return nil, "Invalid session data"
    end

    return session
end

-- Check if request is authenticated (middleware)
function _M.check_auth()
    local token = get_session_token()
    local session, err = _M.validate_session(token)

    if not session then
        send_json(401, {
            success = false,
            error = "Unauthorized",
            message = err or "Authentication required"
        })
    end

    -- Store user in request context for later use
    ngx.ctx.admin_user = session
    return session
end

-- Handle login
function _M.handle_login()
    if ngx.req.get_method() ~= "POST" then
        send_json(405, { success = false, error = "Method not allowed" })
    end

    local body, err = read_json_body()
    if not body then
        send_json(400, { success = false, error = err })
    end

    local username = body.username
    local password = body.password

    if not username or not password then
        send_json(400, {
            success = false,
            error = "Missing credentials",
            message = "Username and password are required"
        })
    end

    -- Get user from Redis
    local red, err = get_redis()
    if not red then
        send_json(500, { success = false, error = "Database connection failed" })
    end

    local user_key = REDIS_PREFIX .. "users:" .. username
    local user_data, err = red:get(user_key)

    if not user_data or user_data == ngx.null then
        close_redis(red)
        -- Use same error message to prevent user enumeration
        send_json(401, {
            success = false,
            error = "Invalid credentials",
            message = "Username or password is incorrect"
        })
    end

    local user, err = cjson.decode(user_data)
    if not user then
        close_redis(red)
        send_json(500, { success = false, error = "Invalid user data" })
    end

    -- Verify password
    local password_hash = hash_password(password, user.salt or "")
    if password_hash ~= user.password_hash then
        close_redis(red)
        send_json(401, {
            success = false,
            error = "Invalid credentials",
            message = "Username or password is incorrect"
        })
    end

    -- Create session
    local session_token = generate_token(48)
    local session_data = {
        username = username,
        role = user.role or "admin",
        vhost_scope = user.vhost_scope or {"*"},  -- Default to global access
        auth_provider = user.auth_provider or "local",
        created_at = ngx.time(),
        expires_at = ngx.time() + SESSION_TTL,
        must_change_password = user.must_change_password or false
    }

    local session_key = REDIS_PREFIX .. "sessions:" .. session_token
    local ok, err = red:setex(session_key, SESSION_TTL, cjson.encode(session_data))
    close_redis(red)

    if not ok then
        send_json(500, { success = false, error = "Failed to create session" })
    end

    -- Set cookie
    set_session_cookie(session_token, SESSION_TTL)

    -- Return user info (without sensitive data)
    send_json(200, {
        success = true,
        data = {
            user = {
                username = session_data.username,
                role = session_data.role,
                vhost_scope = session_data.vhost_scope,
                auth_provider = session_data.auth_provider,
                display_name = user.display_name,
                email = user.email,
                must_change_password = session_data.must_change_password
            }
        }
    })
end

-- Handle logout
function _M.handle_logout()
    if ngx.req.get_method() ~= "POST" then
        send_json(405, { success = false, error = "Method not allowed" })
    end

    local token = get_session_token()

    if token then
        -- Delete session from Redis
        local red, err = get_redis()
        if red then
            local session_key = REDIS_PREFIX .. "sessions:" .. token
            red:del(session_key)
            close_redis(red)
        end
    end

    -- Clear cookie
    clear_session_cookie()

    send_json(200, {
        success = true,
        message = "Logged out successfully"
    })
end

-- Handle session verification
function _M.handle_verify()
    if ngx.req.get_method() ~= "GET" then
        send_json(405, { success = false, error = "Method not allowed" })
    end

    local token = get_session_token()
    local session, err = _M.validate_session(token)

    if not session then
        send_json(401, {
            success = false,
            authenticated = false,
            error = err or "Not authenticated"
        })
    end

    send_json(200, {
        success = true,
        authenticated = true,
        data = {
            user = {
                username = session.username,
                role = session.role,
                vhost_scope = session.vhost_scope or {"*"},
                auth_provider = session.auth_provider or "local",
                must_change_password = session.must_change_password
            }
        }
    })
end

-- Handle password change
function _M.handle_change_password()
    if ngx.req.get_method() ~= "POST" then
        send_json(405, { success = false, error = "Method not allowed" })
    end

    -- Require authentication
    local token = get_session_token()
    local session, err = _M.validate_session(token)

    if not session then
        send_json(401, { success = false, error = "Authentication required" })
    end

    local body, err = read_json_body()
    if not body then
        send_json(400, { success = false, error = err })
    end

    local current_password = body.current_password
    local new_password = body.new_password

    if not current_password or not new_password then
        send_json(400, {
            success = false,
            error = "Missing passwords",
            message = "Current password and new password are required"
        })
    end

    if #new_password < 8 then
        send_json(400, {
            success = false,
            error = "Password too short",
            message = "New password must be at least 8 characters"
        })
    end

    local red, err = get_redis()
    if not red then
        send_json(500, { success = false, error = "Database connection failed" })
    end

    -- Get current user data
    local user_key = REDIS_PREFIX .. "users:" .. session.username
    local user_data, err = red:get(user_key)

    if not user_data or user_data == ngx.null then
        close_redis(red)
        send_json(500, { success = false, error = "User not found" })
    end

    local user, err = cjson.decode(user_data)
    if not user then
        close_redis(red)
        send_json(500, { success = false, error = "Invalid user data" })
    end

    -- Verify current password
    local current_hash = hash_password(current_password, user.salt or "")
    if current_hash ~= user.password_hash then
        close_redis(red)
        send_json(401, {
            success = false,
            error = "Invalid password",
            message = "Current password is incorrect"
        })
    end

    -- Generate new salt and hash
    local new_salt = generate_token(16)
    local new_hash = hash_password(new_password, new_salt)

    -- Update user
    user.salt = new_salt
    user.password_hash = new_hash
    user.must_change_password = false
    user.password_changed_at = ngx.time()

    local ok, err = red:set(user_key, cjson.encode(user))

    if not ok then
        close_redis(red)
        send_json(500, { success = false, error = "Failed to update password" })
    end

    -- Update session to remove must_change_password flag
    local session_key = REDIS_PREFIX .. "sessions:" .. token
    session.must_change_password = false
    red:setex(session_key, SESSION_TTL, cjson.encode(session))

    close_redis(red)

    send_json(200, {
        success = true,
        message = "Password changed successfully"
    })
end

-- Main request handler
function _M.handle_request()
    local uri = ngx.var.uri

    -- Seed random number generator
    math.randomseed(ngx.time() + ngx.worker.pid())

    -- Route auth requests
    if uri == "/api/auth/login" then
        return _M.handle_login()
    elseif uri == "/api/auth/logout" then
        return _M.handle_logout()
    elseif uri == "/api/auth/verify" then
        return _M.handle_verify()
    elseif uri == "/api/auth/change-password" then
        return _M.handle_change_password()
    elseif uri:match("^/api/auth/providers") or
           uri:match("^/api/auth/sso/") or
           uri:match("^/api/auth/callback/") then
        -- Forward provider/SSO related requests to admin_api
        local admin_api = require "admin_api"
        return admin_api.handle_request()
    else
        send_json(404, { success = false, error = "Auth endpoint not found" })
    end
end

return _M
