-- ip_utils.lua
-- IP address and CIDR matching utilities for WAF
-- F13: Now supports both IPv4 and IPv6

local bit = require "bit"

local _M = {}

-- ============================================================================
-- IPv4 Functions
-- ============================================================================

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

-- Parse IPv4 CIDR notation (e.g., "10.0.0.0/8")
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

-- ============================================================================
-- IPv6 Functions (F13)
-- ============================================================================

-- Parse IPv6 address to array of 8 16-bit groups
-- Handles full, compressed (::), and mixed (::ffff:192.168.1.1) formats
-- Returns: table of 8 numbers, or nil if invalid
function _M.ipv6_to_groups(ip)
    if not ip or type(ip) ~= "string" then
        return nil
    end

    -- Normalize to lowercase
    ip = ip:lower()

    -- Validate: :: must appear at most once in the address
    -- Count occurrences of :: (not just :)
    local double_colon_count = 0
    local pos = 1
    while true do
        local found = ip:find("::", pos, true)  -- plain search, not pattern
        if not found then break end
        double_colon_count = double_colon_count + 1
        pos = found + 2
    end
    if double_colon_count > 1 then
        return nil  -- Invalid: multiple :: in address
    end

    -- Handle IPv4-mapped IPv6 (::ffff:192.168.1.1 or ::ffff:0:192.168.1.1)
    -- Must be exactly ::ffff: prefix (not 1:2::ffff:...)
    local ipv4_mapped = ip:match("^::ffff:(%d+%.%d+%.%d+%.%d+)$")
    if ipv4_mapped then
        local ipv4_num = _M.ip_to_number(ipv4_mapped)
        if not ipv4_num then
            return nil
        end
        return {0, 0, 0, 0, 0, 0xffff,
                bit.rshift(ipv4_num, 16),
                bit.band(ipv4_num, 0xffff)}
    end

    -- Also handle ::ffff:0:a.b.c.d format (SIIT)
    local ipv4_siit = ip:match("^::ffff:0:(%d+%.%d+%.%d+%.%d+)$")
    if ipv4_siit then
        local ipv4_num = _M.ip_to_number(ipv4_siit)
        if not ipv4_num then
            return nil
        end
        return {0, 0, 0, 0, 0xffff, 0,
                bit.rshift(ipv4_num, 16),
                bit.band(ipv4_num, 0xffff)}
    end

    -- Split on :: (we already validated there's at most one)
    local left, right = ip:match("^(.*)::(.*)$")
    local groups = {}

    if left then
        -- Has :: compression
        local left_groups = {}
        local right_groups = {}

        -- Parse left side
        if left ~= "" then
            for group in left:gmatch("([%x]+)") do
                local num = tonumber(group, 16)
                if not num or num > 0xffff then
                    return nil
                end
                table.insert(left_groups, num)
            end
        end

        -- Parse right side
        if right ~= "" then
            for group in right:gmatch("([%x]+)") do
                local num = tonumber(group, 16)
                if not num or num > 0xffff then
                    return nil
                end
                table.insert(right_groups, num)
            end
        end

        -- Calculate how many zeros to insert
        local total = #left_groups + #right_groups
        if total > 8 then
            return nil
        end
        local zeros_needed = 8 - total

        -- Build full address
        for _, g in ipairs(left_groups) do
            table.insert(groups, g)
        end
        for _ = 1, zeros_needed do
            table.insert(groups, 0)
        end
        for _, g in ipairs(right_groups) do
            table.insert(groups, g)
        end
    else
        -- Full format (no ::)
        local count = 0
        for group in ip:gmatch("([%x]+)") do
            local num = tonumber(group, 16)
            if not num or num > 0xffff then
                return nil
            end
            table.insert(groups, num)
            count = count + 1
        end

        if count ~= 8 then
            return nil
        end
    end

    if #groups ~= 8 then
        return nil
    end

    return groups
end

-- Parse IPv6 CIDR notation (e.g., "2001:db8::/32")
-- Returns: groups table, prefix_bits (or nil on error)
function _M.parse_ipv6_cidr(cidr)
    if not cidr or type(cidr) ~= "string" then
        return nil
    end

    local ip, bits = cidr:match("^(.+)/(%d+)$")
    if not ip then
        return nil
    end

    bits = tonumber(bits)
    if not bits or bits < 0 or bits > 128 then
        return nil
    end

    local groups = _M.ipv6_to_groups(ip)
    if not groups then
        return nil
    end

    return groups, bits
end

-- Check if an IPv6 address is within a CIDR range
function _M.ipv6_in_cidr(ip, cidr)
    local ip_groups = _M.ipv6_to_groups(ip)
    if not ip_groups then
        return false
    end

    local net_groups, prefix_bits = _M.parse_ipv6_cidr(cidr)
    if not net_groups then
        return false
    end

    -- Compare bits up to prefix length
    local remaining_bits = prefix_bits

    for i = 1, 8 do
        if remaining_bits <= 0 then
            break
        end

        if remaining_bits >= 16 then
            -- Full 16-bit group comparison
            if ip_groups[i] ~= net_groups[i] then
                return false
            end
            remaining_bits = remaining_bits - 16
        else
            -- Partial group comparison
            local mask = bit.lshift(0xffff, 16 - remaining_bits)
            mask = bit.band(mask, 0xffff)
            if bit.band(ip_groups[i], mask) ~= bit.band(net_groups[i], mask) then
                return false
            end
            remaining_bits = 0
        end
    end

    return true
end

-- ============================================================================
-- Unified Functions (IPv4 + IPv6)
-- ============================================================================

-- Check if string is an IPv6 address
function _M.is_ipv6(ip)
    if not ip or type(ip) ~= "string" then
        return false
    end
    -- IPv6 addresses contain colons
    return ip:find(":") ~= nil
end

-- Check if string is an IPv4 address
function _M.is_ipv4(ip)
    return _M.ip_to_number(ip) ~= nil
end

-- Check if an IP address (v4 or v6) is within a CIDR range
-- Returns: true if IP is in range, false otherwise
function _M.ip_in_cidr(ip, cidr)
    if not ip or not cidr then
        return false
    end

    local ip_is_v6 = _M.is_ipv6(ip)
    local cidr_is_v6 = _M.is_ipv6(cidr)

    -- IP and CIDR must be same version
    if ip_is_v6 ~= cidr_is_v6 then
        return false
    end

    if ip_is_v6 then
        return _M.ipv6_in_cidr(ip, cidr)
    else
        -- IPv4 path (original implementation)
        local ip_num = _M.ip_to_number(ip)
        if not ip_num then
            return false
        end

        local net, mask = _M.parse_cidr(cidr)
        if not net then
            return false
        end

        return bit.band(ip_num, mask) == bit.band(net, mask)
    end
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

-- Validate IP address format (IPv4 or IPv6)
function _M.is_valid_ip(ip)
    if not ip or type(ip) ~= "string" then
        return false
    end

    if _M.is_ipv6(ip) then
        return _M.ipv6_to_groups(ip) ~= nil
    else
        return _M.ip_to_number(ip) ~= nil
    end
end

-- Validate CIDR notation (IPv4 or IPv6)
function _M.is_valid_cidr(cidr)
    if not cidr or type(cidr) ~= "string" then
        return false
    end

    if _M.is_ipv6(cidr) then
        local groups, bits = _M.parse_ipv6_cidr(cidr)
        return groups ~= nil
    else
        local net, mask, bits = _M.parse_cidr(cidr)
        return net ~= nil
    end
end

-- Validate either IP or CIDR (IPv4 or IPv6)
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

-- Normalize IPv6 address to full expanded format
-- Useful for consistent storage/comparison
function _M.normalize_ipv6(ip)
    local groups = _M.ipv6_to_groups(ip)
    if not groups then
        return nil
    end

    local parts = {}
    for _, g in ipairs(groups) do
        table.insert(parts, string.format("%04x", g))
    end
    return table.concat(parts, ":")
end

return _M
