-- content_hasher.lua
-- Generates SHA256 hashes of form content for duplicate/flood detection

local _M = {}

local resty_sha256 = require "resty.sha256"
local str = require "resty.string"

-- Fields to exclude from hashing (dynamic fields that change per request)
local EXCLUDED_FIELDS = {
    ["_token"] = true,
    ["csrf_token"] = true,
    ["csrf"] = true,
    ["_csrf"] = true,
    ["authenticity_token"] = true,
    ["timestamp"] = true,
    ["_timestamp"] = true,
    ["nonce"] = true,
    ["_nonce"] = true,
    ["captcha"] = true,
    ["g-recaptcha-response"] = true,
    ["h-captcha-response"] = true,
    ["cf-turnstile-response"] = true,
}

-- Normalize text for consistent hashing
local function normalize_text(text)
    if not text or text == "" then
        return ""
    end

    -- Convert to lowercase
    text = text:lower()

    -- Remove extra whitespace
    text = text:gsub("%s+", " ")

    -- Trim
    text = text:match("^%s*(.-)%s*$") or ""

    -- Remove common punctuation that might vary
    text = text:gsub("[%.!?,;:'\"-]", "")

    return text
end

-- Sort table keys for consistent ordering
local function sorted_keys(tbl)
    local keys = {}
    for k in pairs(tbl) do
        table.insert(keys, k)
    end
    table.sort(keys)
    return keys
end

-- Generate hash of form data
function _M.hash_form(form_data, options)
    options = options or {}
    local exclude_fields = options.exclude_fields or EXCLUDED_FIELDS
    local normalize = options.normalize ~= false -- default true

    if not form_data or type(form_data) ~= "table" then
        return nil, "invalid form data"
    end

    local sha256 = resty_sha256:new()
    if not sha256 then
        return nil, "failed to create SHA256 instance"
    end

    -- Build deterministic string from form data
    local keys = sorted_keys(form_data)
    local parts = {}

    for _, key in ipairs(keys) do
        -- Skip excluded fields
        local lower_key = key:lower()
        if not exclude_fields[lower_key] then
            local value = form_data[key]

            if type(value) == "table" then
                -- Sort array values for consistency
                local sorted_values = {}
                for _, v in ipairs(value) do
                    table.insert(sorted_values, tostring(v))
                end
                table.sort(sorted_values)

                for _, v in ipairs(sorted_values) do
                    local processed = normalize and normalize_text(v) or v
                    table.insert(parts, key .. "=" .. processed)
                end
            else
                local processed = normalize and normalize_text(tostring(value)) or tostring(value)
                table.insert(parts, key .. "=" .. processed)
            end
        end
    end

    -- Create hash input
    local hash_input = table.concat(parts, "&")

    if hash_input == "" then
        -- No hashable content
        return "empty", nil
    end

    sha256:update(hash_input)
    local digest = sha256:final()

    return str.to_hex(digest), nil
end

-- Generate hash of specific fields only
function _M.hash_fields(form_data, field_names)
    if not form_data or not field_names then
        return nil, "invalid arguments"
    end

    local subset = {}
    for _, field in ipairs(field_names) do
        if form_data[field] then
            subset[field] = form_data[field]
        end
    end

    return _M.hash_form(subset, {exclude_fields = {}})
end

-- Generate hash of combined text content only (ignoring field names)
function _M.hash_content_only(form_data)
    if not form_data then
        return nil, "invalid form data"
    end

    local sha256 = resty_sha256:new()
    if not sha256 then
        return nil, "failed to create SHA256 instance"
    end

    local values = {}

    for key, value in pairs(form_data) do
        local lower_key = key:lower()
        if not EXCLUDED_FIELDS[lower_key] then
            if type(value) == "table" then
                for _, v in ipairs(value) do
                    table.insert(values, normalize_text(tostring(v)))
                end
            else
                table.insert(values, normalize_text(tostring(value)))
            end
        end
    end

    -- Sort values for consistency
    table.sort(values)

    local hash_input = table.concat(values, "|")

    if hash_input == "" then
        return "empty", nil
    end

    sha256:update(hash_input)
    local digest = sha256:final()

    return str.to_hex(digest), nil
end

-- Generate short hash (first 16 chars) for logging
function _M.short_hash(form_data)
    local full_hash, err = _M.hash_form(form_data)
    if not full_hash then
        return nil, err
    end

    return full_hash:sub(1, 16)
end

return _M
