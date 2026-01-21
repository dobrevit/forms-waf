-- ssrf_protection.lua
-- Server-Side Request Forgery (SSRF) protection
-- Prevents requests to internal/private networks from user-controlled URLs
--
-- F15: SSRF Protection for webhook and external service URLs

local ip_utils = require "ip_utils"

local _M = {}

-- Private/internal IPv4 CIDR ranges that should be blocked
local PRIVATE_IPV4_CIDRS = {
    "10.0.0.0/8",        -- RFC 1918 Class A private
    "172.16.0.0/12",     -- RFC 1918 Class B private
    "192.168.0.0/16",    -- RFC 1918 Class C private
    "127.0.0.0/8",       -- Loopback
    "169.254.0.0/16",    -- Link-local
    "0.0.0.0/8",         -- "This" network
    "100.64.0.0/10",     -- Carrier-grade NAT (RFC 6598)
    "192.0.0.0/24",      -- IETF Protocol assignments
    "192.0.2.0/24",      -- TEST-NET-1 (documentation)
    "198.51.100.0/24",   -- TEST-NET-2 (documentation)
    "203.0.113.0/24",    -- TEST-NET-3 (documentation)
    "224.0.0.0/4",       -- Multicast
    "240.0.0.0/4",       -- Reserved for future use
}

-- Private/internal IPv6 CIDR ranges that should be blocked
local PRIVATE_IPV6_CIDRS = {
    "::1/128",           -- Loopback
    "::/128",            -- Unspecified
    "fc00::/7",          -- Unique local addresses (RFC 4193)
    "fe80::/10",         -- Link-local
    "ff00::/8",          -- Multicast
    "::ffff:0:0/96",     -- IPv4-mapped (check IPv4 part separately)
}

-- Blocked hostnames
local BLOCKED_HOSTNAMES = {
    ["localhost"] = true,
    ["localhost.localdomain"] = true,
    ["ip6-localhost"] = true,
    ["ip6-loopback"] = true,
}

-- Allowed schemes for outbound requests
local ALLOWED_SCHEMES = {
    ["http"] = true,
    ["https"] = true,
}

-- Environment variable to allow internal URLs (for testing/special deployments)
local ALLOW_INTERNAL = os.getenv("WAF_ALLOW_INTERNAL_URLS") == "true"

-- Check if an IP address is private/internal
function _M.is_private_ip(ip)
    if not ip then
        return true, "no_ip"
    end

    -- Check IPv6
    if ip_utils.is_ipv6(ip) then
        -- Check IPv6 private ranges
        for _, cidr in ipairs(PRIVATE_IPV6_CIDRS) do
            if ip_utils.ip_in_cidr(ip, cidr) then
                return true, "ipv6_private"
            end
        end

        -- Check if it's an IPv4-mapped address
        local ipv4_part = ip:match("::ffff:(%d+%.%d+%.%d+%.%d+)$")
        if ipv4_part then
            -- Check the IPv4 part against IPv4 private ranges
            for _, cidr in ipairs(PRIVATE_IPV4_CIDRS) do
                if ip_utils.ip_in_cidr(ipv4_part, cidr) then
                    return true, "ipv4_mapped_private"
                end
            end
        end

        return false
    end

    -- Check IPv4
    if ip_utils.is_ipv4(ip) then
        for _, cidr in ipairs(PRIVATE_IPV4_CIDRS) do
            if ip_utils.ip_in_cidr(ip, cidr) then
                return true, "ipv4_private"
            end
        end
        return false
    end

    -- Unknown format - block to be safe
    return true, "invalid_ip"
end

-- Check if a hostname is blocked
function _M.is_blocked_hostname(hostname)
    if not hostname then
        return true, "no_hostname"
    end

    hostname = hostname:lower()

    -- Direct match
    if BLOCKED_HOSTNAMES[hostname] then
        return true, "blocked_hostname"
    end

    -- Check for localhost-like patterns
    if hostname:match("^localhost%.") or hostname:match("%.localhost$") then
        return true, "localhost_variant"
    end

    -- Check for IP address in hostname (decimal)
    if hostname:match("^%d+%.%d+%.%d+%.%d+$") then
        return _M.is_private_ip(hostname)
    end

    -- Check for decimal IP encoding tricks (e.g., 2130706433 = 127.0.0.1)
    local decimal_ip = tonumber(hostname)
    if decimal_ip and decimal_ip > 0 and decimal_ip <= 4294967295 then
        -- Convert decimal to dotted quad
        local o1 = math.floor(decimal_ip / 16777216) % 256
        local o2 = math.floor(decimal_ip / 65536) % 256
        local o3 = math.floor(decimal_ip / 256) % 256
        local o4 = decimal_ip % 256
        local converted = o1 .. "." .. o2 .. "." .. o3 .. "." .. o4
        return _M.is_private_ip(converted)
    end

    -- Check for hex encoding (e.g., 0x7f.0x0.0x0.0x1)
    if hostname:match("^0x[%x]+%.0x[%x]+%.0x[%x]+%.0x[%x]+$") then
        return true, "hex_encoded_ip"
    end

    -- Check for octal encoding (e.g., 0177.0.0.01)
    if hostname:match("^0%d+%.0%d*%.0%d*%.0%d*$") then
        return true, "octal_encoded_ip"
    end

    return false
end

-- Validate a URL for SSRF safety
-- Returns: is_safe, error_reason
function _M.validate_url(url)
    if not url or url == "" then
        return false, "empty_url"
    end

    -- Parse URL scheme
    local scheme = url:match("^(%w+)://")
    if not scheme then
        return false, "no_scheme"
    end

    scheme = scheme:lower()
    if not ALLOWED_SCHEMES[scheme] then
        return false, "disallowed_scheme"
    end

    -- Parse hostname and port
    local host_with_port = url:match("^%w+://([^/]+)")
    if not host_with_port then
        return false, "no_host"
    end

    -- Handle IPv6 addresses in brackets
    local hostname, port
    if host_with_port:match("^%[") then
        -- IPv6 format: [::1]:8080 or [::1]
        hostname = host_with_port:match("^%[([^%]]+)%]")
        port = host_with_port:match("%]:(%d+)$")
    else
        -- IPv4 or hostname: example.com:8080 or example.com
        hostname, port = host_with_port:match("^([^:]+):?(%d*)$")
    end

    if not hostname then
        return false, "invalid_host_format"
    end

    -- Remove userinfo if present (http://user:pass@host)
    if hostname:find("@") then
        hostname = hostname:match("@(.+)$") or hostname
    end

    hostname = hostname:lower()

    -- Check blocked hostnames
    local blocked, reason = _M.is_blocked_hostname(hostname)
    if blocked then
        return false, reason
    end

    -- If hostname is an IP address, check if private
    if ip_utils.is_valid_ip(hostname) then
        local is_private, priv_reason = _M.is_private_ip(hostname)
        if is_private then
            return false, priv_reason
        end
    end

    -- For hostnames, we can't check DNS resolution in sync Lua easily
    -- The http_utils module will do runtime DNS resolution validation
    -- Here we just do static checks

    return true
end

-- Check if URL should bypass SSRF protection
-- Used for admin-configured allowlists
function _M.is_url_allowed(url, allowlist)
    if ALLOW_INTERNAL then
        return true
    end

    if not allowlist or #allowlist == 0 then
        return false
    end

    -- Parse URL host
    local host = url:match("^%w+://([^/:]+)")
    if not host then
        return false
    end
    host = host:lower()

    for _, allowed in ipairs(allowlist) do
        allowed = allowed:lower()
        if host == allowed then
            return true
        end
        -- Wildcard match (*.example.com)
        if allowed:sub(1, 2) == "*." then
            local suffix = allowed:sub(2)  -- .example.com
            if host:sub(-#suffix) == suffix then
                return true
            end
        end
    end

    return false
end

-- Validate URL with optional allowlist
-- Returns: is_safe, error_reason
function _M.validate_url_safe(url, allowlist)
    -- First check allowlist
    if _M.is_url_allowed(url, allowlist) then
        return true
    end

    -- Then do standard validation
    return _M.validate_url(url)
end

-- Runtime DNS resolution check (to be called from cosocket context)
-- This catches SSRF via DNS rebinding or internal DNS names
function _M.check_resolved_ip(ip)
    if ALLOW_INTERNAL then
        return true
    end

    local is_private, reason = _M.is_private_ip(ip)
    if is_private then
        ngx.log(ngx.WARN, "SSRF: blocked request to private IP: ", ip, " (", reason, ")")
        return false, "resolved_to_private_ip"
    end

    return true
end

-- Get module info for debugging
function _M.get_info()
    return {
        allow_internal = ALLOW_INTERNAL,
        ipv4_blocked_ranges = #PRIVATE_IPV4_CIDRS,
        ipv6_blocked_ranges = #PRIVATE_IPV6_CIDRS,
        blocked_hostnames = BLOCKED_HOSTNAMES,
    }
end

return _M
