-- password_utils.lua
-- Secure password hashing utilities (F02)
-- Implements PBKDF2-SHA256 with configurable iterations

local _M = {}

local resty_sha256 = require "resty.sha256"
local resty_string = require "resty.string"
local resty_random = require "resty.random"
local bit = require "bit"

-- Configuration
local DEFAULT_ITERATIONS = 100000  -- OWASP recommended minimum for PBKDF2-SHA256
local HASH_LENGTH = 32  -- 256 bits
local SALT_LENGTH = 16  -- 128 bits

-- XOR two binary strings of equal length
local function xor_strings(s1, s2)
    local result = {}
    for i = 1, #s1 do
        result[i] = string.char(bit.bxor(s1:byte(i), s2:byte(i)))
    end
    return table.concat(result)
end

-- HMAC-SHA256 implementation
local function hmac_sha256(key, message)
    local block_size = 64  -- SHA256 block size

    -- If key is longer than block size, hash it
    if #key > block_size then
        local sha = resty_sha256:new()
        sha:update(key)
        key = sha:final()
    end

    -- Pad key to block size
    if #key < block_size then
        key = key .. string.rep("\0", block_size - #key)
    end

    -- Create inner and outer padding
    local o_key_pad = {}
    local i_key_pad = {}
    for i = 1, block_size do
        o_key_pad[i] = string.char(bit.bxor(key:byte(i), 0x5c))
        i_key_pad[i] = string.char(bit.bxor(key:byte(i), 0x36))
    end
    o_key_pad = table.concat(o_key_pad)
    i_key_pad = table.concat(i_key_pad)

    -- HMAC = H(o_key_pad || H(i_key_pad || message))
    local sha_inner = resty_sha256:new()
    sha_inner:update(i_key_pad)
    sha_inner:update(message)
    local inner_hash = sha_inner:final()

    local sha_outer = resty_sha256:new()
    sha_outer:update(o_key_pad)
    sha_outer:update(inner_hash)
    return sha_outer:final()
end

-- PBKDF2-SHA256 implementation
-- password: the password to hash
-- salt: random salt (binary string)
-- iterations: number of iterations
-- dk_len: derived key length in bytes
local function pbkdf2_sha256(password, salt, iterations, dk_len)
    iterations = iterations or DEFAULT_ITERATIONS
    dk_len = dk_len or HASH_LENGTH

    local dk = ""
    local block_num = 1

    while #dk < dk_len do
        -- U1 = PRF(Password, Salt || INT(i))
        local block_num_bytes = string.char(
            bit.band(bit.rshift(block_num, 24), 0xff),
            bit.band(bit.rshift(block_num, 16), 0xff),
            bit.band(bit.rshift(block_num, 8), 0xff),
            bit.band(block_num, 0xff)
        )

        local u = hmac_sha256(password, salt .. block_num_bytes)
        local t = u

        -- Iterate: U2 = PRF(Password, U1), etc.
        for _ = 2, iterations do
            u = hmac_sha256(password, u)
            t = xor_strings(t, u)
        end

        dk = dk .. t
        block_num = block_num + 1
    end

    return dk:sub(1, dk_len)
end

-- Generate a cryptographically secure random salt
function _M.generate_salt()
    local salt = resty_random.bytes(SALT_LENGTH, true)
    if not salt then
        -- Fallback to less secure random if strong random fails
        ngx.log(ngx.WARN, "password_utils: strong random failed, using fallback")
        salt = resty_random.bytes(SALT_LENGTH, false)
    end
    return salt and resty_string.to_hex(salt) or nil
end

-- Hash a password using PBKDF2-SHA256
-- Returns: hash string in format "pbkdf2:iterations:salt:hash"
function _M.hash_password(password, salt, iterations)
    if not password then
        return nil, "password required"
    end

    salt = salt or _M.generate_salt()
    if not salt then
        return nil, "failed to generate salt"
    end

    iterations = iterations or DEFAULT_ITERATIONS

    -- Convert hex salt to binary for PBKDF2
    local salt_binary = ""
    for i = 1, #salt, 2 do
        salt_binary = salt_binary .. string.char(tonumber(salt:sub(i, i + 1), 16))
    end

    local dk = pbkdf2_sha256(password, salt_binary, iterations, HASH_LENGTH)
    local hash = resty_string.to_hex(dk)

    -- Return in structured format for easy verification
    return string.format("pbkdf2:%d:%s:%s", iterations, salt, hash)
end

-- Verify a password against a stored hash
-- Supports both new PBKDF2 format and legacy SHA256 format for migration
function _M.verify_password(password, stored_hash, legacy_salt)
    if not password or not stored_hash then
        return false
    end

    -- Check if it's the new PBKDF2 format
    if stored_hash:match("^pbkdf2:") then
        local iterations, salt, hash = stored_hash:match("^pbkdf2:(%d+):([a-f0-9]+):([a-f0-9]+)$")
        if not iterations then
            return false
        end

        iterations = tonumber(iterations)
        local computed = _M.hash_password(password, salt, iterations)
        if not computed then
            return false
        end

        -- Constant-time comparison to prevent timing attacks
        return _M.secure_compare(computed, stored_hash)
    end

    -- Legacy format: plain SHA256 hash with separate salt
    -- This allows migration from old password format
    if legacy_salt then
        local sha256 = resty_sha256:new()
        sha256:update(legacy_salt .. password .. legacy_salt)
        local digest = sha256:final()
        local computed_hash = resty_string.to_hex(digest)
        return _M.secure_compare(computed_hash, stored_hash)
    end

    return false
end

-- Constant-time string comparison to prevent timing attacks
function _M.secure_compare(a, b)
    if type(a) ~= "string" or type(b) ~= "string" then
        return false
    end

    if #a ~= #b then
        return false
    end

    local result = 0
    for i = 1, #a do
        result = bit.bor(result, bit.bxor(a:byte(i), b:byte(i)))
    end

    return result == 0
end

-- Check if a stored hash needs to be upgraded (is in legacy format)
function _M.needs_upgrade(stored_hash)
    if not stored_hash then
        return false
    end
    return not stored_hash:match("^pbkdf2:")
end

-- Get recommended iterations (may be tuned based on hardware)
function _M.get_iterations()
    return DEFAULT_ITERATIONS
end

return _M
