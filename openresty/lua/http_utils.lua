--[[
    HTTP Utilities Module
    Provides HTTP request functionality with proxy support

    Supports:
    - HTTP_PROXY / http_proxy environment variables
    - HTTPS_PROXY / https_proxy environment variables
    - NO_PROXY / no_proxy for bypass rules (with wildcard support)
    - CONNECT tunneling for HTTPS through HTTP proxy

    NOTE: Proxy configuration is read at module load time (once per nginx worker).
    Changes to environment variables require worker restart to take effect.
    This is standard OpenResty behavior where Lua modules are cached per worker.
]]

local http = require "resty.http"
local cjson = require "cjson.safe"

local _M = {}

-- Proxy configuration from environment (read once at module load time)
local HTTP_PROXY = os.getenv("HTTP_PROXY") or os.getenv("http_proxy")
local HTTPS_PROXY = os.getenv("HTTPS_PROXY") or os.getenv("https_proxy")
local NO_PROXY = os.getenv("NO_PROXY") or os.getenv("no_proxy") or ""

-- Parse NO_PROXY into a lookup table
local no_proxy_hosts = {}
for host in NO_PROXY:gmatch("[^,]+") do
    local h = host:match("^%s*(.-)%s*$")  -- trim whitespace
    if h and h ~= "" then
        no_proxy_hosts[h:lower()] = true
    end
end

-- Check if a host should bypass proxy
function _M.should_bypass_proxy(host)
    if not host then return true end
    host = host:lower()

    -- Direct match
    if no_proxy_hosts[host] then return true end

    -- Wildcard match (e.g., .example.com matches sub.example.com)
    for pattern, _ in pairs(no_proxy_hosts) do
        if pattern:sub(1, 1) == "." then
            -- Wildcard pattern
            if host:sub(-#pattern) == pattern or host == pattern:sub(2) then
                return true
            end
        end
    end

    return false
end

-- Get proxy URL for a given target URL
function _M.get_proxy_for_url(url)
    if url:match("^https://") then
        return HTTPS_PROXY
    else
        return HTTP_PROXY
    end
end

-- Check if proxy is configured
function _M.has_proxy()
    return HTTP_PROXY ~= nil or HTTPS_PROXY ~= nil
end

-- Extract host from URL
local function extract_host(url)
    return url:match("https?://([^/:]+)")
end

-- Extract path from URL
local function extract_path(url)
    return url:match("https?://[^/]+(.*)") or "/"
end

-- Parse proxy URL and return host, port
-- Returns nil if invalid
local function parse_proxy_url(proxy_url)
    if not proxy_url then return nil, nil end

    local proxy_host, proxy_port = proxy_url:match("https?://([^/:]+):?(%d*)")
    if not proxy_host then
        return nil, nil
    end

    -- Determine default port based on proxy URL scheme
    if not proxy_port or proxy_port == "" then
        if proxy_url:match("^https://") then
            proxy_port = 443
        else
            proxy_port = 80
        end
    else
        proxy_port = tonumber(proxy_port)
    end

    return proxy_host, proxy_port
end

-- Perform HTTP request with optional proxy support
-- opts: {
--   method = "GET" | "POST" | ...,
--   body = string,
--   headers = table,
--   timeout = number (ms),
--   ssl_verify = boolean,
-- }
-- Returns: response table with {status, headers, body} or nil, error
function _M.request(url, opts)
    opts = opts or {}
    local httpc = http.new()
    httpc:set_timeout(opts.timeout or 5000)

    local host = extract_host(url)
    if not host then
        return nil, "Invalid URL: cannot extract host"
    end

    -- Check if we should use proxy
    local use_proxy = false
    local proxy_url = nil

    if not _M.should_bypass_proxy(host) then
        proxy_url = _M.get_proxy_for_url(url)
        if proxy_url then
            use_proxy = true
        end
    end

    if use_proxy then
        -- Parse proxy URL
        local proxy_host, proxy_port = parse_proxy_url(proxy_url)
        if not proxy_host then
            ngx.log(ngx.WARN, "Invalid proxy URL: ", proxy_url, ", falling back to direct connection")
            use_proxy = false
        else
            ngx.log(ngx.DEBUG, "Using proxy ", proxy_host, ":", proxy_port, " for ", url)

            -- Connect to proxy
            local ok, conn_err = httpc:connect(proxy_host, proxy_port)
            if not ok then
                ngx.log(ngx.ERR, "Failed to connect to proxy: ", conn_err)
                return nil, "Proxy connection failed: " .. conn_err
            end

            -- For HTTPS, use CONNECT tunnel
            if url:match("^https://") then
                local target_host = url:match("https://([^/]+)")
                local res, err = httpc:request({
                    method = "CONNECT",
                    path = target_host,
                    headers = {
                        ["Host"] = target_host,
                    },
                })
                if not res then
                    ngx.log(ngx.ERR, "CONNECT tunnel failed: ", err)
                    httpc:close()
                    return nil, "Proxy CONNECT failed: " .. (err or "unknown error")
                end
                if res.status ~= 200 then
                    ngx.log(ngx.ERR, "CONNECT tunnel failed with status: ", res.status)
                    httpc:close()
                    return nil, "Proxy CONNECT failed with status: " .. tostring(res.status)
                end

                -- Upgrade to TLS
                local ssl_ok, ssl_err = httpc:ssl_handshake(nil, host, opts.ssl_verify ~= false)
                if not ssl_ok then
                    ngx.log(ngx.ERR, "SSL handshake through proxy failed: ", ssl_err)
                    httpc:close()
                    return nil, "SSL handshake failed: " .. ssl_err
                end
            end

            -- Build request options for proxy path
            local path = extract_path(url)
            local request_opts = {
                method = opts.method or "GET",
                path = path,
                body = opts.body,
                headers = opts.headers or {},
            }
            request_opts.headers["Host"] = host

            -- Make the actual request through proxy
            local res, err = httpc:request(request_opts)
            if not res then
                ngx.log(ngx.ERR, "Request through proxy failed: ", err)
                httpc:close()
                return nil, err
            end

            -- Read body
            local body_data, read_err = res:read_body()
            if not body_data then
                ngx.log(ngx.ERR, "Failed to read response body: ", read_err)
                httpc:close()
                return nil, "Failed to read response"
            end

            httpc:set_keepalive()

            return {
                status = res.status,
                headers = res.headers,
                body = body_data,
            }
        end
    end

    -- Direct connection (no proxy or proxy bypass)
    local request_opts = {
        method = opts.method or "GET",
        body = opts.body,
        headers = opts.headers,
        ssl_verify = opts.ssl_verify ~= false,
    }

    local res, err = httpc:request_uri(url, request_opts)
    if not res then
        return nil, err
    end

    return {
        status = res.status,
        headers = res.headers,
        body = res.body,
    }
end

-- Convenience function for JSON POST requests
function _M.post_json(url, data, opts)
    opts = opts or {}
    opts.method = "POST"
    opts.body = cjson.encode(data)
    opts.headers = opts.headers or {}
    opts.headers["Content-Type"] = "application/json"

    return _M.request(url, opts)
end

-- Convenience function for form POST requests
function _M.post_form(url, params, opts)
    opts = opts or {}
    opts.method = "POST"

    -- Build form body
    local body_parts = {}
    for k, v in pairs(params) do
        if v then
            table.insert(body_parts, ngx.escape_uri(k) .. "=" .. ngx.escape_uri(tostring(v)))
        end
    end
    opts.body = table.concat(body_parts, "&")

    opts.headers = opts.headers or {}
    opts.headers["Content-Type"] = "application/x-www-form-urlencoded"

    return _M.request(url, opts)
end

return _M
