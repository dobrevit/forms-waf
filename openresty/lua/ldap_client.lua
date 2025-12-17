-- ldap_client.lua
-- Lightweight LDAP client using OpenResty cosocket
-- Implements basic LDAP operations: bind, search, unbind

local _M = {}

local bit = require "bit"
local tcp = ngx.socket.tcp

-- LDAP Protocol constants
local LDAP_VERSION = 3

-- LDAP Operation tags
local LDAP_BIND_REQUEST = 0x60
local LDAP_BIND_RESPONSE = 0x61
local LDAP_UNBIND_REQUEST = 0x42
local LDAP_SEARCH_REQUEST = 0x63
local LDAP_SEARCH_RESULT_ENTRY = 0x64
local LDAP_SEARCH_RESULT_DONE = 0x65

-- LDAP Result codes
local LDAP_SUCCESS = 0
local LDAP_INVALID_CREDENTIALS = 49

-- BER tag classes
local BER_UNIVERSAL = 0x00
local BER_CONSTRUCTED = 0x20
local BER_SEQUENCE = 0x30
local BER_SET = 0x31
local BER_INTEGER = 0x02
local BER_OCTET_STRING = 0x04
local BER_BOOLEAN = 0x01
local BER_ENUMERATED = 0x0A

-- BER encoding helpers
local function ber_encode_length(length)
    if length < 128 then
        return string.char(length)
    elseif length < 256 then
        return string.char(0x81, length)
    elseif length < 65536 then
        return string.char(0x82, bit.rshift(length, 8), bit.band(length, 0xFF))
    else
        return string.char(0x83,
            bit.rshift(length, 16),
            bit.band(bit.rshift(length, 8), 0xFF),
            bit.band(length, 0xFF))
    end
end

local function ber_encode_integer(value)
    local bytes = {}
    local negative = value < 0

    if value == 0 then
        bytes[1] = 0
    else
        local v = value
        if negative then
            v = -v - 1
        end
        while v > 0 do
            table.insert(bytes, 1, bit.band(v, 0xFF))
            v = bit.rshift(v, 8)
        end
        if negative then
            for i, b in ipairs(bytes) do
                bytes[i] = bit.bxor(b, 0xFF)
            end
        end
        -- Add sign byte if needed
        if not negative and bytes[1] >= 128 then
            table.insert(bytes, 1, 0)
        elseif negative and bytes[1] < 128 then
            table.insert(bytes, 1, 0xFF)
        end
    end

    local data = string.char(unpack(bytes))
    return string.char(BER_INTEGER) .. ber_encode_length(#data) .. data
end

local function ber_encode_string(value)
    return string.char(BER_OCTET_STRING) .. ber_encode_length(#value) .. value
end

local function ber_encode_boolean(value)
    return string.char(BER_BOOLEAN) .. string.char(1) .. string.char(value and 0xFF or 0x00)
end

local function ber_encode_enumerated(value)
    return string.char(BER_ENUMERATED) .. string.char(1) .. string.char(value)
end

local function ber_encode_sequence(...)
    local content = table.concat({...})
    return string.char(BER_SEQUENCE) .. ber_encode_length(#content) .. content
end

local function ber_encode_set(...)
    local content = table.concat({...})
    return string.char(BER_SET) .. ber_encode_length(#content) .. content
end

local function ber_encode_context(tag, value, constructed)
    local t = 0x80 + tag
    if constructed then
        t = t + 0x20
    end
    return string.char(t) .. ber_encode_length(#value) .. value
end

-- BER decoding helpers
local function ber_decode_length(data, pos)
    local first = string.byte(data, pos)
    if first < 128 then
        return first, pos + 1
    end

    local num_bytes = bit.band(first, 0x7F)
    local length = 0
    for i = 1, num_bytes do
        length = bit.lshift(length, 8) + string.byte(data, pos + i)
    end
    return length, pos + 1 + num_bytes
end

local function ber_decode_integer(data, pos)
    local tag = string.byte(data, pos)
    if tag ~= BER_INTEGER and tag ~= BER_ENUMERATED then
        return nil, pos, "Expected integer"
    end

    local length, new_pos = ber_decode_length(data, pos + 1)
    local value = 0
    local negative = string.byte(data, new_pos) >= 128

    for i = 0, length - 1 do
        local b = string.byte(data, new_pos + i)
        if negative then
            b = bit.bxor(b, 0xFF)
        end
        value = bit.lshift(value, 8) + b
    end

    if negative then
        value = -(value + 1)
    end

    return value, new_pos + length
end

local function ber_decode_string(data, pos)
    local tag = string.byte(data, pos)
    if tag ~= BER_OCTET_STRING then
        return nil, pos, "Expected octet string"
    end

    local length, new_pos = ber_decode_length(data, pos + 1)
    local value = string.sub(data, new_pos, new_pos + length - 1)
    return value, new_pos + length
end

local function ber_decode_sequence(data, pos)
    local tag = string.byte(data, pos)
    if tag ~= BER_SEQUENCE and bit.band(tag, 0xE0) ~= 0x60 then
        return nil, pos, "Expected sequence"
    end

    local length, new_pos = ber_decode_length(data, pos + 1)
    return new_pos, new_pos + length
end

-- LDAP Message construction
local function create_ldap_message(message_id, operation)
    local msg = ber_encode_sequence(
        ber_encode_integer(message_id),
        operation
    )
    return msg
end

-- LDAP Bind Request (Simple authentication)
local function create_bind_request(message_id, dn, password)
    local bind_request = string.char(LDAP_BIND_REQUEST) ..
        ber_encode_length(
            #ber_encode_integer(LDAP_VERSION) +
            #ber_encode_string(dn) +
            #ber_encode_context(0, password, false)
        ) ..
        ber_encode_integer(LDAP_VERSION) ..
        ber_encode_string(dn) ..
        ber_encode_context(0, password, false)  -- Simple auth

    return create_ldap_message(message_id, bind_request)
end

-- LDAP Search Request
local function create_search_request(message_id, base_dn, scope, filter, attributes)
    scope = scope or 2  -- subtree
    filter = filter or "(objectClass=*)"
    attributes = attributes or {}

    -- Encode filter (simplified - only supports basic filters)
    local encoded_filter
    local filter_match = filter:match("^%(([^=]+)=([^)]+)%)$")
    if filter_match then
        local attr, value = filter:match("^%(([^=]+)=([^)]+)%)$")
        -- equalityMatch filter
        encoded_filter = ber_encode_context(3,
            ber_encode_string(attr) .. ber_encode_string(value),
            true)
    else
        -- Default: present filter for objectClass
        encoded_filter = ber_encode_context(7, "objectClass", false)
    end

    -- Encode attributes
    local attr_list = ""
    for _, attr in ipairs(attributes) do
        attr_list = attr_list .. ber_encode_string(attr)
    end
    local encoded_attrs = ber_encode_sequence(attr_list)

    local search_content =
        ber_encode_string(base_dn) ..           -- baseObject
        ber_encode_enumerated(scope) ..          -- scope
        ber_encode_enumerated(0) ..              -- derefAliases (never)
        ber_encode_integer(0) ..                 -- sizeLimit (no limit)
        ber_encode_integer(0) ..                 -- timeLimit (no limit)
        ber_encode_boolean(false) ..             -- typesOnly
        encoded_filter ..                        -- filter
        encoded_attrs                            -- attributes

    local search_request = string.char(LDAP_SEARCH_REQUEST) ..
        ber_encode_length(#search_content) ..
        search_content

    return create_ldap_message(message_id, search_request)
end

-- LDAP Unbind Request
local function create_unbind_request(message_id)
    local unbind = string.char(LDAP_UNBIND_REQUEST) .. string.char(0)
    return create_ldap_message(message_id, unbind)
end

-- Parse LDAP response
local function parse_ldap_response(data)
    if not data or #data < 2 then
        return nil, "Empty response"
    end

    local pos = 1
    local tag = string.byte(data, pos)

    if tag ~= BER_SEQUENCE then
        return nil, "Invalid LDAP message"
    end

    local length, content_start = ber_decode_length(data, pos + 1)

    -- Parse message ID
    local message_id, next_pos = ber_decode_integer(data, content_start)
    if not message_id then
        return nil, "Failed to parse message ID"
    end

    -- Get operation tag
    local op_tag = string.byte(data, next_pos)
    local op_length, op_content_start = ber_decode_length(data, next_pos + 1)

    local result = {
        message_id = message_id,
        operation = op_tag,
        raw_data = data,
    }

    -- Parse based on operation type
    if op_tag == LDAP_BIND_RESPONSE then
        local result_code = ber_decode_integer(data, op_content_start)
        result.result_code = result_code
        result.success = (result_code == LDAP_SUCCESS)

    elseif op_tag == LDAP_SEARCH_RESULT_ENTRY then
        -- Parse search result entry
        local dn, pos = ber_decode_string(data, op_content_start)
        result.dn = dn
        result.attributes = {}
        -- Parse attributes (simplified)

    elseif op_tag == LDAP_SEARCH_RESULT_DONE then
        local result_code = ber_decode_integer(data, op_content_start)
        result.result_code = result_code
        result.success = (result_code == LDAP_SUCCESS)
        result.done = true
    end

    return result
end

-- Read LDAP message from socket
local function read_ldap_message(sock)
    -- Read first 2 bytes to get tag and length indicator
    local header, err = sock:receive(2)
    if not header then
        return nil, "Failed to read header: " .. (err or "unknown")
    end

    local tag = string.byte(header, 1)
    local len_byte = string.byte(header, 2)

    local length
    local extra_bytes = ""

    if len_byte < 128 then
        length = len_byte
    else
        local num_len_bytes = bit.band(len_byte, 0x7F)
        local len_data, err = sock:receive(num_len_bytes)
        if not len_data then
            return nil, "Failed to read length: " .. (err or "unknown")
        end
        extra_bytes = len_data
        length = 0
        for i = 1, num_len_bytes do
            length = bit.lshift(length, 8) + string.byte(len_data, i)
        end
    end

    -- Read the content
    local content, err = sock:receive(length)
    if not content then
        return nil, "Failed to read content: " .. (err or "unknown")
    end

    return header .. extra_bytes .. content
end

-- LDAP Client class
local LDAPClient = {}
LDAPClient.__index = LDAPClient

function _M.new(config)
    local self = setmetatable({}, LDAPClient)
    self.host = config.host or "localhost"
    self.port = config.port or 389
    self.use_ssl = config.use_ssl or false
    self.ssl_verify = config.ssl_verify ~= false
    self.timeout = config.timeout or 5000
    self.message_id = 0
    self.sock = nil
    return self
end

function LDAPClient:connect()
    local sock, err = tcp()
    if not sock then
        return nil, "Failed to create socket: " .. (err or "unknown")
    end

    sock:settimeout(self.timeout)

    local ok, err = sock:connect(self.host, self.port)
    if not ok then
        return nil, "Failed to connect: " .. (err or "unknown")
    end

    if self.use_ssl then
        local session, err = sock:sslhandshake(nil, self.host, self.ssl_verify)
        if not session then
            sock:close()
            return nil, "SSL handshake failed: " .. (err or "unknown")
        end
    end

    self.sock = sock
    return true
end

function LDAPClient:close()
    if self.sock then
        -- Send unbind request
        self.message_id = self.message_id + 1
        local unbind = create_unbind_request(self.message_id)
        self.sock:send(unbind)
        self.sock:close()
        self.sock = nil
    end
end

function LDAPClient:bind(dn, password)
    if not self.sock then
        return nil, "Not connected"
    end

    self.message_id = self.message_id + 1
    local request = create_bind_request(self.message_id, dn or "", password or "")

    local bytes, err = self.sock:send(request)
    if not bytes then
        return nil, "Failed to send bind request: " .. (err or "unknown")
    end

    local response_data, err = read_ldap_message(self.sock)
    if not response_data then
        return nil, "Failed to read bind response: " .. (err or "unknown")
    end

    local response, err = parse_ldap_response(response_data)
    if not response then
        return nil, "Failed to parse bind response: " .. (err or "unknown")
    end

    if response.success then
        return true
    else
        local error_msg = "Bind failed"
        if response.result_code == LDAP_INVALID_CREDENTIALS then
            error_msg = "Invalid credentials"
        end
        return nil, error_msg
    end
end

function LDAPClient:search(base_dn, scope, filter, attributes)
    if not self.sock then
        return nil, "Not connected"
    end

    self.message_id = self.message_id + 1
    local request = create_search_request(self.message_id, base_dn, scope, filter, attributes)

    local bytes, err = self.sock:send(request)
    if not bytes then
        return nil, "Failed to send search request: " .. (err or "unknown")
    end

    local entries = {}

    -- Read all search results
    while true do
        local response_data, err = read_ldap_message(self.sock)
        if not response_data then
            return nil, "Failed to read search response: " .. (err or "unknown")
        end

        local response, err = parse_ldap_response(response_data)
        if not response then
            return nil, "Failed to parse search response: " .. (err or "unknown")
        end

        if response.operation == LDAP_SEARCH_RESULT_ENTRY then
            table.insert(entries, response)
        elseif response.operation == LDAP_SEARCH_RESULT_DONE then
            if response.success then
                return entries
            else
                return nil, "Search failed with code: " .. (response.result_code or "unknown")
            end
        end
    end
end

return _M
