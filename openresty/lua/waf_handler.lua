-- waf_handler.lua
-- Main WAF processing module that orchestrates form parsing, hashing, and filtering

local _M = {}

local form_parser = require "form_parser"
local content_hasher = require "content_hasher"
local keyword_filter = require "keyword_filter"
local config = require "waf_config"
local cjson = require "cjson.safe"

-- Process incoming request
function _M.process_request()
    local method = ngx.req.get_method()

    -- Only process POST/PUT/PATCH requests with form data
    if method ~= "POST" and method ~= "PUT" and method ~= "PATCH" then
        return
    end

    local content_type = ngx.var.content_type or ""

    -- Check if this is a form submission
    if not (content_type:find("application/x%-www%-form%-urlencoded") or
            content_type:find("multipart/form%-data") or
            content_type:find("application/json")) then
        return
    end

    -- Get client IP (considering proxies)
    local client_ip = ngx.var.http_x_forwarded_for or ngx.var.remote_addr
    if client_ip then
        -- Take first IP if multiple
        client_ip = client_ip:match("([^,]+)")
    end

    -- Check IP whitelist first
    local whitelist = ngx.shared.ip_whitelist
    if whitelist:get(client_ip) then
        ngx.header["X-Whitelisted"] = "true"
        return
    end

    -- Parse form data
    local form_data, err = form_parser.parse()
    if err then
        ngx.log(ngx.WARN, "Form parsing error: ", err)
        -- Continue without blocking on parse errors
        return
    end

    if not form_data or next(form_data) == nil then
        return
    end

    -- Initialize response headers
    local spam_score = 0
    local spam_flags = {}
    local blocked = false
    local block_reason = nil

    -- Step 1: Keyword filtering
    local keyword_result = keyword_filter.scan(form_data)
    spam_score = spam_score + (keyword_result.score or 0)

    if keyword_result.blocked_keywords and #keyword_result.blocked_keywords > 0 then
        blocked = true
        block_reason = "blocked_keyword"
        for _, kw in ipairs(keyword_result.blocked_keywords) do
            table.insert(spam_flags, "kw:" .. kw)
        end
    end

    if keyword_result.flagged_keywords then
        for _, kw in ipairs(keyword_result.flagged_keywords) do
            table.insert(spam_flags, "flag:" .. kw)
        end
    end

    -- Step 2: Content hashing
    local form_hash = content_hasher.hash_form(form_data)

    -- Check if hash is in blocklist
    local hash_blocked = keyword_filter.is_hash_blocked(form_hash)
    if hash_blocked then
        blocked = true
        block_reason = "blocked_hash"
        table.insert(spam_flags, "hash:blocked")
    end

    -- Step 3: Pattern-based scoring
    local pattern_result = keyword_filter.pattern_scan(form_data)
    spam_score = spam_score + (pattern_result.score or 0)
    if pattern_result.flags then
        for _, flag in ipairs(pattern_result.flags) do
            table.insert(spam_flags, "pattern:" .. flag)
        end
    end

    -- Step 4: Check spam score threshold
    local thresholds = config.get_thresholds()
    if spam_score >= thresholds.spam_score_block then
        blocked = true
        block_reason = "spam_score_exceeded"
        table.insert(spam_flags, "score:exceeded")
    end

    -- Set response headers for HAProxy
    ngx.header["X-Form-Hash"] = form_hash
    ngx.header["X-Spam-Score"] = tostring(spam_score)
    ngx.header["X-Spam-Flags"] = table.concat(spam_flags, ",")
    ngx.header["X-Client-IP"] = client_ip

    -- If blocked at OpenResty level, respond immediately
    if blocked then
        ngx.header["X-Blocked"] = "true"
        ngx.header["X-Block-Reason"] = block_reason

        -- Log the block
        ngx.log(ngx.WARN, string.format(
            "BLOCKED: ip=%s reason=%s score=%d hash=%s flags=%s",
            client_ip, block_reason, spam_score, form_hash, table.concat(spam_flags, ",")
        ))

        -- Return 403 with JSON error
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Request blocked",
            reason = block_reason,
            request_id = ngx.var.request_id or ngx.now()
        }))
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    -- Log processing info
    ngx.log(ngx.INFO, string.format(
        "PROCESSED: ip=%s score=%d hash=%s flags=%s",
        client_ip, spam_score, form_hash, table.concat(spam_flags, ",")
    ))
end

return _M
