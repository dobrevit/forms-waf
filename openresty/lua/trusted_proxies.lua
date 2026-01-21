-- trusted_proxies.lua
-- Secure client IP extraction with trusted proxy validation (F01)
-- Ensures X-Forwarded-For is only trusted from known proxy sources

local _M = {}

local ip_utils = require "ip_utils"

-- Default trusted proxy CIDRs (private networks)
-- These should be overridden via WAF_TRUSTED_PROXIES environment variable
local DEFAULT_TRUSTED_CIDRS = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "100.64.0.0/10",  -- Kubernetes pod network
    "::1/128",        -- IPv6 loopback
    "fc00::/7",       -- IPv6 private
    "fe80::/10",      -- IPv6 link-local
}

-- Cache parsed trusted CIDRs
local trusted_cidrs_cache = nil
local trusted_cidrs_cache_time = 0
local CACHE_TTL = 60  -- Refresh every 60 seconds

-- Parse trusted proxies from environment variable
local function parse_trusted_proxies()
    local now = ngx.now()
    if trusted_cidrs_cache and (now - trusted_cidrs_cache_time) < CACHE_TTL then
        return trusted_cidrs_cache
    end

    local cidrs = {}

    -- Start with defaults
    for _, cidr in ipairs(DEFAULT_TRUSTED_CIDRS) do
        table.insert(cidrs, cidr)
    end

    -- Parse environment variable (comma-separated)
    local env_proxies = os.getenv("WAF_TRUSTED_PROXIES")
    if env_proxies and env_proxies ~= "" then
        for cidr in env_proxies:gmatch("([^,]+)") do
            local trimmed = cidr:match("^%s*(.-)%s*$")
            if trimmed and trimmed ~= "" then
                -- Validate CIDR format
                if ip_utils.is_valid_ip_or_cidr(trimmed) then
                    table.insert(cidrs, trimmed)
                else
                    ngx.log(ngx.WARN, "trusted_proxies: invalid CIDR in WAF_TRUSTED_PROXIES: ", trimmed)
                end
            end
        end
    end

    trusted_cidrs_cache = cidrs
    trusted_cidrs_cache_time = now
    return cidrs
end

-- Check if an IP is a trusted proxy
function _M.is_trusted(ip)
    if not ip then
        return false
    end

    local cidrs = parse_trusted_proxies()

    for _, cidr in ipairs(cidrs) do
        if ip_utils.ip_in_cidr(ip, cidr) then
            return true
        end
    end

    return false
end

-- Get the real client IP from the request
-- Uses nginx's real_ip module result ($remote_addr after real_ip processing)
-- Falls back to manual XFF parsing if needed
function _M.get_client_ip()
    -- nginx's real_ip module already processes XFF and sets remote_addr
    -- to the real client IP based on set_real_ip_from directives
    local remote_addr = ngx.var.remote_addr

    -- If we have a binary_remote_addr, remote_addr is already processed
    -- by the real_ip module - this is the recommended approach
    if remote_addr then
        return remote_addr
    end

    -- Fallback: should not normally reach here
    return ngx.var.remote_addr or "0.0.0.0"
end

-- Get client IP with explicit XFF validation (for cases where real_ip module
-- is not configured or additional validation is needed)
-- This implements the "rightmost untrusted IP" algorithm
function _M.get_client_ip_from_xff()
    local remote_addr = ngx.var.remote_addr

    -- If request didn't come from a trusted proxy, don't trust XFF
    if not _M.is_trusted(remote_addr) then
        return remote_addr
    end

    local xff = ngx.var.http_x_forwarded_for
    if not xff or xff == "" then
        return remote_addr
    end

    -- Parse XFF header (format: "client, proxy1, proxy2, ...")
    local ips = {}
    for ip in xff:gmatch("([^,]+)") do
        local trimmed = ip:match("^%s*(.-)%s*$")
        if trimmed and trimmed ~= "" then
            table.insert(ips, trimmed)
        end
    end

    -- Find rightmost untrusted IP (the real client)
    -- Walk backwards through the chain
    for i = #ips, 1, -1 do
        local ip = ips[i]
        if ip_utils.is_valid_ip(ip) and not _M.is_trusted(ip) then
            return ip
        end
    end

    -- All IPs in chain are trusted, use the first one
    if #ips > 0 and ip_utils.is_valid_ip(ips[1]) then
        return ips[1]
    end

    return remote_addr
end

-- Get trusted proxy CIDRs (for debugging/admin API)
function _M.get_trusted_cidrs()
    return parse_trusted_proxies()
end

return _M
