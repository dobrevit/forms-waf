-- form_parser.lua
-- Parses various form content types (urlencoded, multipart, JSON)
-- Handles charset conversion for non-UTF-8 form submissions

local _M = {}

local upload = require "resty.upload"
local cjson = require "cjson.safe"
local charset = require "charset"

-- Convert all keys and values in form data to UTF-8
-- @param form_data: Table of form field key-value pairs
-- @param source_charset: Source charset for conversion
-- @return: New table with UTF-8 keys and values
local function convert_form_to_utf8(form_data, source_charset)
    if not form_data or not source_charset then
        return form_data
    end

    local result = {}

    for key, value in pairs(form_data) do
        local new_key = charset.to_utf8(tostring(key), source_charset)
        local new_value

        if type(value) == "table" then
            -- Handle array values (multiple values for same key)
            new_value = {}
            for i, v in ipairs(value) do
                new_value[i] = charset.to_utf8(tostring(v), source_charset)
            end
        elseif type(value) == "string" then
            new_value = charset.to_utf8(value, source_charset)
        else
            new_value = value
        end

        result[new_key] = new_value
    end

    return result
end

-- Parse URL-encoded form data
local function parse_urlencoded(body)
    local data = {}

    if not body or body == "" then
        return data
    end

    for pair in body:gmatch("[^&]+") do
        local key, value = pair:match("([^=]*)=?(.*)")
        if key then
            key = ngx.unescape_uri(key)
            value = value and ngx.unescape_uri(value) or ""

            -- Handle arrays (multiple values for same key)
            if data[key] then
                if type(data[key]) == "table" then
                    table.insert(data[key], value)
                else
                    data[key] = {data[key], value}
                end
            else
                data[key] = value
            end
        end
    end

    return data
end

-- Parse multipart form data
local function parse_multipart()
    local chunk_size = 8192
    local form, err = upload:new(chunk_size)

    if not form then
        return nil, "failed to create upload form: " .. (err or "unknown")
    end

    form:set_timeout(5000) -- 5 seconds

    local data = {}
    local current_field = nil
    local current_value = {}
    local current_filename = nil
    local current_is_file = false  -- Track if this part is a file upload

    while true do
        local typ, res, err = form:read()

        if not typ then
            return nil, "failed to read form: " .. (err or "unknown")
        end

        if typ == "header" then
            local header_name = res[1] and res[1]:lower() or ""

            if header_name == "content-disposition" then
                -- Parse Content-Disposition header
                local header_value = res[2] or ""

                -- Extract field name
                local name = header_value:match('name="([^"]*)"')
                if not name then
                    name = header_value:match("name=([^;%s]+)")
                end
                current_field = name

                -- Extract filename if present (file upload)
                local filename = header_value:match('filename="([^"]*)"')
                if not filename then
                    filename = header_value:match("filename=([^;%s]+)")
                end
                current_filename = filename

                -- If filename is present, this is a file
                if filename then
                    current_is_file = true
                end

            elseif header_name == "content-type" then
                -- If a Content-Type header is present for this part, consider it for file detection
                -- Regular form fields typically don't have Content-Type headers; presence indicates a file
                local content_type = res[2] or ""
                -- Treat as file if:
                -- 1. Already marked as file (has filename), OR
                -- 2. Has binary/non-text content type, OR
                -- 3. Has application/* type (documents, archives, etc.)
                if not current_is_file then
                    if content_type ~= "" and not content_type:match("^text/") then
                        current_is_file = true
                    end
                end
            end

        elseif typ == "body" then
            if current_field then
                -- Skip file contents, only track filename/presence
                if current_is_file then
                    if current_filename then
                        current_value = {"[FILE:" .. current_filename .. "]"}
                    else
                        -- File without filename - use placeholder
                        current_value = {"[FILE:unnamed]"}
                    end
                else
                    table.insert(current_value, res)
                end
            end

        elseif typ == "part_end" then
            if current_field and #current_value > 0 then
                local value = table.concat(current_value)

                -- Handle arrays
                if data[current_field] then
                    if type(data[current_field]) == "table" then
                        table.insert(data[current_field], value)
                    else
                        data[current_field] = {data[current_field], value}
                    end
                else
                    data[current_field] = value
                end
            end

            current_field = nil
            current_value = {}
            current_filename = nil
            current_is_file = false

        elseif typ == "eof" then
            break
        end
    end

    return data
end

-- Parse JSON body
local function parse_json(body)
    if not body or body == "" then
        return {}
    end

    local data, err = cjson.decode(body)
    if not data then
        return nil, "JSON parse error: " .. (err or "unknown")
    end

    -- Flatten nested JSON to key-value pairs for scanning
    local flat = {}

    local function flatten(obj, prefix)
        if type(obj) == "table" then
            for k, v in pairs(obj) do
                local new_key = prefix and (prefix .. "." .. tostring(k)) or tostring(k)
                flatten(v, new_key)
            end
        else
            flat[prefix or "value"] = tostring(obj)
        end
    end

    flatten(data, nil)
    return flat
end

-- Main parse function - detects content type and parses accordingly
-- Also handles charset conversion for non-UTF-8 form submissions
function _M.parse()
    local content_type_raw = ngx.var.content_type or ""
    local content_type = content_type_raw:lower()

    -- Parse charset from Content-Type header (e.g., "charset=iso-8859-1")
    -- Note: JSON is always UTF-8 by RFC specification, so we skip charset for JSON
    local source_charset = charset.parse_charset(content_type_raw)

    local data, err

    if content_type:find("multipart/form%-data") then
        data, err = parse_multipart()

    elseif content_type:find("application/x%-www%-form%-urlencoded") then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()

        if not body then
            -- Body might be in a file
            local body_file = ngx.req.get_body_file()
            if body_file then
                local f = io.open(body_file, "r")
                if f then
                    body = f:read("*all")
                    f:close()
                end
            end
        end

        data = parse_urlencoded(body)

    elseif content_type:find("application/json") then
        -- JSON is always UTF-8 by spec, no charset conversion needed
        source_charset = nil
        ngx.req.read_body()
        local body = ngx.req.get_body_data()

        if not body then
            local body_file = ngx.req.get_body_file()
            if body_file then
                local f = io.open(body_file, "r")
                if f then
                    body = f:read("*all")
                    f:close()
                end
            end
        end

        data, err = parse_json(body)
    else
        -- Unsupported content type
        return nil, "unsupported content type"
    end

    -- Convert form data to UTF-8 if a non-UTF-8 charset was specified
    if data and source_charset and source_charset ~= "UTF-8" and source_charset ~= "ASCII" then
        data = convert_form_to_utf8(data, source_charset)
    end

    return data, err
end

-- Utility: Get all form values as a single string (for scanning)
-- @param form_data: table of form field key-value pairs
-- @param exclude_set: optional table of field names to exclude (keys are field names, values are truthy)
function _M.get_combined_text(form_data, exclude_set)
    if not form_data then
        return ""
    end

    local parts = {}

    for key, value in pairs(form_data) do
        -- Skip excluded fields (e.g., CSRF tokens, captchas)
        if not exclude_set or not exclude_set[key] then
            if type(value) == "table" then
                for _, v in ipairs(value) do
                    table.insert(parts, tostring(v))
                end
            else
                table.insert(parts, tostring(value))
            end
        end
    end

    return table.concat(parts, " ")
end

-- Reconstruct request body from form_data
-- Used when filtering unexpected fields
-- Returns: body string or nil (if content type not supported for reconstruction)
function _M.reconstruct_body(form_data, content_type)
    if not form_data or not content_type then
        return nil
    end

    content_type = content_type:lower()

    if content_type:find("application/x%-www%-form%-urlencoded") then
        -- Reconstruct URL-encoded body
        local parts = {}
        for key, value in pairs(form_data) do
            if type(value) == "table" then
                -- Array values: repeat the key
                for _, v in ipairs(value) do
                    table.insert(parts, ngx.escape_uri(key) .. "=" .. ngx.escape_uri(tostring(v)))
                end
            else
                table.insert(parts, ngx.escape_uri(key) .. "=" .. ngx.escape_uri(tostring(value)))
            end
        end
        return table.concat(parts, "&")

    elseif content_type:find("application/json") then
        -- Reconstruct JSON body
        -- Note: We work with flattened data, so we need to unflatten it
        local result = {}
        for key, value in pairs(form_data) do
            -- Handle flattened keys like "user.name" -> {user: {name: value}}
            local parts_list = {}
            for part in key:gmatch("[^.]+") do
                table.insert(parts_list, part)
            end

            if #parts_list == 1 then
                -- Simple key
                result[key] = value
            else
                -- Nested key - rebuild structure
                local current = result
                for i = 1, #parts_list - 1 do
                    local part = parts_list[i]
                    if not current[part] then
                        current[part] = {}
                    end
                    current = current[part]
                end
                current[parts_list[#parts_list]] = value
            end
        end
        return cjson.encode(result)

    elseif content_type:find("multipart/form%-data") then
        -- Multipart reconstruction is complex (boundaries, files, etc.)
        -- Not supported - return nil to skip filtering
        ngx.log(ngx.WARN, "Cannot filter multipart/form-data requests - filtering skipped")
        return nil
    end

    return nil
end

return _M
