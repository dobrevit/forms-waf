-- form_parser.lua
-- Parses various form content types (urlencoded, multipart, JSON)

local _M = {}

local upload = require "resty.upload"
local cjson = require "cjson.safe"

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

    while true do
        local typ, res, err = form:read()

        if not typ then
            return nil, "failed to read form: " .. (err or "unknown")
        end

        if typ == "header" then
            -- Parse Content-Disposition header
            if res[1] and res[1]:lower() == "content-disposition" then
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
            end

        elseif typ == "body" then
            if current_field then
                -- Skip file contents, only track filename
                if current_filename then
                    current_value = {"[FILE:" .. current_filename .. "]"}
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
function _M.parse()
    local content_type = ngx.var.content_type or ""
    content_type = content_type:lower()

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

    return data, err
end

-- Utility: Get all form values as a single string (for scanning)
function _M.get_combined_text(form_data)
    if not form_data then
        return ""
    end

    local parts = {}

    for key, value in pairs(form_data) do
        if type(value) == "table" then
            for _, v in ipairs(value) do
                table.insert(parts, tostring(v))
            end
        else
            table.insert(parts, tostring(value))
        end
    end

    return table.concat(parts, " ")
end

return _M
