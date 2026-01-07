-- charset.lua
-- Handles charset detection and conversion to UTF-8 for form data
-- Ensures all HTTP headers contain valid UTF-8 content

local _M = {}

-- Try to load iconv
local iconv_ok, iconv = pcall(require, "iconv")

if not iconv_ok then
    ngx.log(ngx.WARN, "charset: lua-iconv not available, will use fallback sanitization")
end

-- Common charset aliases (lowercase keys)
local CHARSET_ALIASES = {
    ["iso-8859-1"] = "ISO-8859-1",
    ["iso8859-1"] = "ISO-8859-1",
    ["iso_8859-1"] = "ISO-8859-1",
    ["latin1"] = "ISO-8859-1",
    ["latin-1"] = "ISO-8859-1",
    ["l1"] = "ISO-8859-1",
    ["windows-1252"] = "WINDOWS-1252",
    ["cp1252"] = "WINDOWS-1252",
    ["cp-1252"] = "WINDOWS-1252",
    ["iso-8859-15"] = "ISO-8859-15",
    ["iso8859-15"] = "ISO-8859-15",
    ["latin9"] = "ISO-8859-15",
    ["iso-8859-2"] = "ISO-8859-2",
    ["iso8859-2"] = "ISO-8859-2",
    ["latin2"] = "ISO-8859-2",
    ["utf-8"] = "UTF-8",
    ["utf8"] = "UTF-8",
    ["us-ascii"] = "ASCII",
    ["ascii"] = "ASCII",
}

-- Parse charset from Content-Type header
-- @param content_type: The Content-Type header value
-- @return: Normalized charset name or nil
function _M.parse_charset(content_type)
    if not content_type then
        return nil
    end

    -- Match charset=value (with or without quotes)
    local charset = content_type:match("charset%s*=%s*\"?([^;%s\"]+)\"?")
    if charset then
        charset = charset:lower()
        return CHARSET_ALIASES[charset] or charset:upper()
    end

    return nil
end

-- Convert string from source charset to UTF-8
-- @param str: String to convert
-- @param source_charset: Source charset name (e.g., "ISO-8859-1")
-- @return: UTF-8 encoded string
function _M.to_utf8(str, source_charset)
    if not str or str == "" then
        return str
    end

    -- If no charset specified or already UTF-8/ASCII, validate and return
    -- Note: ASCII is a strict subset of UTF-8 (bytes 0x00-0x7F are identical)
    if not source_charset or source_charset == "UTF-8" or source_charset == "ASCII" then
        -- Validate the actual bytes match the claimed charset
        -- (e.g., Content-Type may claim ASCII but contain high bytes)
        if _M.is_valid_utf8(str) then
            return str
        end
        -- Not valid UTF-8 (malformed sequences or claimed ASCII with high bytes), sanitize it
        return _M.sanitize_to_ascii(str)
    end

    -- If iconv not available, fall back to sanitization
    if not iconv_ok then
        return _M.sanitize_to_ascii(str)
    end

    -- Create converter: from source charset to UTF-8
    local cd, err = iconv.new("UTF-8", source_charset)
    if not cd then
        ngx.log(ngx.WARN, "charset: failed to create converter for ", source_charset, ": ", tostring(err))
        return _M.sanitize_to_ascii(str)
    end

    local result, err = cd:iconv(str)
    if not result then
        ngx.log(ngx.WARN, "charset: conversion failed from ", source_charset, ": ", tostring(err))
        return _M.sanitize_to_ascii(str)
    end

    return result
end

-- Fallback: sanitize non-ASCII bytes to underscore
-- Used when iconv is not available or conversion fails
-- @param str: String to sanitize
-- @return: ASCII-safe string (printable ASCII only)
function _M.sanitize_to_ascii(str)
    if type(str) ~= "string" then
        return tostring(str)
    end
    -- Replace control characters (0x00-0x1F except tab/newline/CR) and non-ASCII bytes (0x7F-0xFF)
    -- Keeps: tab (0x09), newline (0x0A), CR (0x0D), printable ASCII (0x20-0x7E)
    return str:gsub("[%z\1-\8\11\12\14-\31\127-\255]", "_")
end

-- Check if string is valid UTF-8
-- @param str: String to check
-- @return: true if valid UTF-8, false otherwise
function _M.is_valid_utf8(str)
    if type(str) ~= "string" then
        return true
    end

    local i = 1
    local len = #str

    while i <= len do
        local c = string.byte(str, i)

        if c < 128 then
            -- ASCII (0x00-0x7F)
            i = i + 1
        elseif c >= 194 and c <= 223 then
            -- 2-byte sequence (0xC2-0xDF)
            if i + 1 > len then return false end
            local c2 = string.byte(str, i + 1)
            if c2 < 128 or c2 > 191 then return false end
            i = i + 2
        elseif c >= 224 and c <= 239 then
            -- 3-byte sequence (0xE0-0xEF)
            if i + 2 > len then return false end
            local c2 = string.byte(str, i + 1)
            local c3 = string.byte(str, i + 2)
            if c2 < 128 or c2 > 191 or c3 < 128 or c3 > 191 then return false end
            -- Check for overlong encoding
            if c == 224 and c2 < 160 then return false end
            -- Check for surrogates (0xD800-0xDFFF)
            if c == 237 and c2 > 159 then return false end
            i = i + 3
        elseif c >= 240 and c <= 244 then
            -- 4-byte sequence (0xF0-0xF4)
            if i + 3 > len then return false end
            local c2 = string.byte(str, i + 1)
            local c3 = string.byte(str, i + 2)
            local c4 = string.byte(str, i + 3)
            if c2 < 128 or c2 > 191 or c3 < 128 or c3 > 191 or c4 < 128 or c4 > 191 then
                return false
            end
            -- Check for overlong encoding
            if c == 240 and c2 < 144 then return false end
            -- Check for values > 0x10FFFF
            if c == 244 and c2 > 143 then return false end
            i = i + 4
        else
            -- Invalid start byte
            return false
        end
    end

    return true
end

-- Ensure string is valid UTF-8 (convert or sanitize as needed)
-- @param str: String to ensure is UTF-8
-- @param source_charset: Optional source charset for conversion
-- @return: Valid UTF-8 string
function _M.ensure_utf8(str, source_charset)
    if not str or str == "" then
        return str
    end

    if _M.is_valid_utf8(str) then
        return str
    end

    return _M.to_utf8(str, source_charset)
end

-- Sanitize a string specifically for use in HTTP headers
-- Headers must be valid UTF-8 and should not contain control characters
-- @param str: String to sanitize
-- @return: Header-safe UTF-8 string
function _M.sanitize_for_header(str)
    if type(str) ~= "string" then
        return tostring(str)
    end

    if _M.is_valid_utf8(str) then
        -- Valid UTF-8, just remove control characters (0x00-0x1F except tab/newline/CR, plus DEL 0x7F)
        -- Preserves UTF-8 multibyte sequences (0x80-0xFF are valid in UTF-8)
        return str:gsub("[%z\1-\8\11\12\14-\31\127]", "_")
    end

    -- Not valid UTF-8, sanitize completely
    return _M.sanitize_to_ascii(str)
end

return _M
