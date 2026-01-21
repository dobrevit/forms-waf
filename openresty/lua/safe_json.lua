-- safe_json.lua
-- Safe JSON encoding/decoding with security limits (F07)
-- Wraps cjson.safe with depth limits and size checks

local cjson = require "cjson.safe"

local _M = {}

-- Configuration
local MAX_DECODE_DEPTH = 10  -- Maximum nesting depth for JSON parsing
local MAX_ARRAY_SIZE = 10000  -- Maximum array elements
local MAX_ENCODE_DEPTH = 100  -- Maximum nesting for encoding

-- Configure cjson limits
cjson.decode_max_depth(MAX_DECODE_DEPTH)

-- Note: cjson doesn't have built-in array size limit, but depth limit helps
-- For very large arrays, the input size should be checked before parsing

-- Wrapper for safe JSON decoding with additional checks
function _M.decode(json_string)
    if not json_string then
        return nil, "nil input"
    end

    if type(json_string) ~= "string" then
        return nil, "input must be string"
    end

    -- Basic sanity check on input size (prevent DoS via huge JSON)
    -- 10MB limit by default
    if #json_string > 10 * 1024 * 1024 then
        return nil, "JSON input too large"
    end

    return cjson.decode(json_string)
end

-- Wrapper for safe JSON encoding
function _M.encode(value)
    return cjson.encode(value)
end

-- Get the array metatable for empty arrays
_M.array_mt = cjson.array_mt

-- Re-export null
_M.null = cjson.null

-- Re-export encode_empty_table_as_object setting
function _M.encode_empty_table_as_object(setting)
    cjson.encode_empty_table_as_object(setting)
end

-- Get current decode depth limit
function _M.get_max_depth()
    return MAX_DECODE_DEPTH
end

return _M
