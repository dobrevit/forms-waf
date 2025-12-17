-- ip_utils.lua
-- IP address and CIDR matching utilities for WAF

local bit = require "bit"

local _M = {}

-- Parse IPv4 address to 32-bit numeric value
-- Returns nil if invalid
function _M.ip_to_number(ip)
    if not ip or type(ip) ~= "string" then
        return nil
    end

    local o1, o2, o3, o4 = ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    if not o1 then
        return nil
    end

    o1, o2, o3, o4 = tonumber(o1), tonumber(o2), tonumber(o3), tonumber(o4)

    -- Validate octet ranges
    if o1 > 255 or o2 > 255 or o3 > 255 or o4 > 255 then
        return nil
    end

    -- Convert to 32-bit number
    return o1 * 16777216 + o2 * 65536 + o3 * 256 + o4
end

-- Parse CIDR notation (e.g., "10.0.0.0/8")
-- Returns: network_number, mask, prefix_bits (or nil on error)
function _M.parse_cidr(cidr)
    if not cidr or type(cidr) ~= "string" then
        return nil
    end

    local ip, bits = cidr:match("^([%d%.]+)/(%d+)$")
    if not ip then
        return nil
    end

    bits = tonumber(bits)
    if not bits or bits < 0 or bits > 32 then
        return nil
    end

    local ip_num = _M.ip_to_number(ip)
    if not ip_num then
        return nil
    end

    -- Calculate mask: for /24, mask = 0xFFFFFF00
    local mask
    if bits == 0 then
        mask = 0
    elseif bits == 32 then
        mask = 0xFFFFFFFF
    else
        mask = bit.lshift(0xFFFFFFFF, 32 - bits)
        -- Handle sign extension in Lua's bit library
        mask = bit.band(mask, 0xFFFFFFFF)
    end

    return ip_num, mask, bits
end

-- Check if an IP address is within a CIDR range
-- Returns: true if IP is in range, false otherwise
function _M.ip_in_cidr(ip, cidr)
    local ip_num = _M.ip_to_number(ip)
    if not ip_num then
        return false
    end

    local net, mask = _M.parse_cidr(cidr)
    if not net then
        return false
    end

    -- Apply mask to both IP and network, compare
    return bit.band(ip_num, mask) == bit.band(net, mask)
end

-- Check if IP is allowlisted (exact match OR CIDR match)
-- exact_dict: ngx.shared dict with exact IPs
-- cidr_list: table of CIDR strings
-- Returns: true if allowlisted, false otherwise
function _M.is_ip_allowlisted(ip, exact_dict, cidr_list)
    if not ip then
        return false
    end

    -- Fast path: exact match in shared dict
    if exact_dict and exact_dict:get(ip) then
        return true
    end

    -- Slow path: check CIDR ranges
    if cidr_list and type(cidr_list) == "table" then
        for _, cidr in ipairs(cidr_list) do
            if _M.ip_in_cidr(ip, cidr) then
                return true
            end
        end
    end

    return false
end

-- Validate IP address format (IPv4 only for now)
function _M.is_valid_ip(ip)
    return _M.ip_to_number(ip) ~= nil
end

-- Validate CIDR notation
function _M.is_valid_cidr(cidr)
    local net, mask, bits = _M.parse_cidr(cidr)
    return net ~= nil
end

-- Validate either IP or CIDR
function _M.is_valid_ip_or_cidr(entry)
    if not entry or type(entry) ~= "string" then
        return false
    end

    if entry:match("/%d+$") then
        return _M.is_valid_cidr(entry)
    else
        return _M.is_valid_ip(entry)
    end
end

return _M
