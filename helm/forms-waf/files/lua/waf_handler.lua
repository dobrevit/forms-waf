-- waf_handler.lua
-- Main WAF processing module that orchestrates form parsing, hashing, and filtering
-- Now with dynamic endpoint configuration and virtual host support

local _M = {}

local form_parser = require "form_parser"
local content_hasher = require "content_hasher"
local keyword_filter = require "keyword_filter"
local waf_config = require "waf_config"
local endpoint_matcher = require "endpoint_matcher"
local config_resolver = require "config_resolver"
local vhost_matcher = require "vhost_matcher"
local vhost_resolver = require "vhost_resolver"
local cjson = require "cjson.safe"

-- Process incoming request
function _M.process_request()
    local method = ngx.req.get_method()
    local path = ngx.var.uri
    local host = ngx.var.http_host or ngx.var.host
    local content_type = ngx.var.content_type or ""

    -- Step 0: Resolve full request context (vhost + endpoint)
    local context = vhost_resolver.resolve_request_context(host, path, method)
    local summary = vhost_resolver.get_context_summary(context)

    -- Set context headers early (useful for debugging and downstream services)
    ngx.header["X-WAF-Vhost"] = summary.vhost_id
    ngx.header["X-WAF-Vhost-Match"] = summary.vhost_match
    ngx.header["X-WAF-Endpoint"] = summary.endpoint_id or "global"
    ngx.header["X-WAF-Match-Type"] = summary.endpoint_match
    ngx.header["X-WAF-Mode"] = summary.mode

    -- Store context for use in balancer phase
    ngx.ctx.waf_context = context
    ngx.ctx.waf_routing = vhost_resolver.get_routing(context)

    -- Check if WAF should be skipped
    if vhost_resolver.should_skip_waf(context) then
        ngx.header["X-WAF-Skipped"] = "true"
        ngx.header["X-WAF-Skip-Reason"] = context.reason or "unknown"
        ngx.log(ngx.DEBUG, string.format(
            "WAF SKIPPED: host=%s path=%s vhost=%s endpoint=%s reason=%s",
            host, path, summary.vhost_id, summary.endpoint_id or "none", context.reason or "unknown"
        ))
        return
    end

    -- Get effective endpoint config from context
    local effective_config = context.endpoint

    -- Only process configured HTTP methods with form data
    -- Default: POST/PUT/PATCH, but can be overridden per endpoint
    local allowed_methods = {"POST", "PUT", "PATCH"}
    if effective_config and effective_config.matching and effective_config.matching.methods then
        allowed_methods = effective_config.matching.methods
    end

    local method_allowed = false
    for _, m in ipairs(allowed_methods) do
        if m == "*" or m:upper() == method then
            method_allowed = true
            break
        end
    end

    if not method_allowed then
        return
    end

    -- Check if this is a form submission (content type check)
    local valid_content_type = false
    local allowed_content_types = {"application/x-www-form-urlencoded", "multipart/form-data", "application/json"}

    if effective_config and effective_config.matching and effective_config.matching.content_types then
        allowed_content_types = effective_config.matching.content_types
    end

    for _, ct in ipairs(allowed_content_types) do
        if ct == "*" or content_type:find(ct, 1, true) then
            valid_content_type = true
            break
        end
    end

    if not valid_content_type then
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
    if whitelist and whitelist:get(client_ip) then
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

    -- Validate required fields if configured
    local valid, field_errors = vhost_resolver.validate_fields(context, form_data)
    if not valid and vhost_resolver.should_block(context) then
        ngx.status = ngx.HTTP_BAD_REQUEST
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Validation failed",
            errors = field_errors,
            vhost = summary.vhost_id,
            endpoint = summary.endpoint_id
        }))
        return ngx.exit(ngx.HTTP_BAD_REQUEST)
    end

    -- Initialize response tracking
    local spam_score = 0
    local spam_flags = {}
    local blocked = false
    local block_reason = nil

    -- Get thresholds from context
    local thresholds = vhost_resolver.get_thresholds(context)

    -- Step 1: Keyword filtering
    local keyword_result = keyword_filter.scan(form_data)

    -- Apply context-specific keyword exclusions
    if keyword_result.blocked_keywords and #keyword_result.blocked_keywords > 0 then
        local filtered_blocked = {}
        for _, kw in ipairs(keyword_result.blocked_keywords) do
            if not vhost_resolver.is_keyword_excluded(context, kw, "blocked") then
                table.insert(filtered_blocked, kw)
            end
        end

        if #filtered_blocked > 0 and vhost_resolver.should_inherit_global_keywords(context) then
            blocked = true
            block_reason = "blocked_keyword"
            for _, kw in ipairs(filtered_blocked) do
                table.insert(spam_flags, "kw:" .. kw)
            end
        end
    end

    -- Add score from flagged keywords (with exclusions)
    if keyword_result.flagged_keywords then
        for _, kw in ipairs(keyword_result.flagged_keywords) do
            if not vhost_resolver.is_keyword_excluded(context, kw, "flagged") then
                table.insert(spam_flags, "flag:" .. kw)
            end
        end
    end

    -- Only add score if inheriting global keywords
    if vhost_resolver.should_inherit_global_keywords(context) then
        spam_score = spam_score + (keyword_result.score or 0)
    end

    -- Check context-specific additional keywords (vhost + endpoint)
    local additional = vhost_resolver.get_additional_keywords(context)
    if #additional.blocked > 0 or #additional.flagged > 0 then
        local combined_text = form_parser.get_combined_text(form_data):lower()

        for _, kw in ipairs(additional.blocked) do
            if combined_text:find(kw:lower(), 1, true) then
                blocked = true
                block_reason = "additional_blocked_keyword"
                table.insert(spam_flags, "add_kw:" .. kw)
            end
        end

        for _, entry in ipairs(additional.flagged) do
            local kw, score_str = entry:match("([^:]+):?(%d*)")
            local kw_score = tonumber(score_str) or 10
            if kw and combined_text:find(kw:lower(), 1, true) then
                spam_score = spam_score + kw_score
                table.insert(spam_flags, "add_flag:" .. kw)
            end
        end
    end

    -- Step 2: Content hashing (only if enabled and fields specified)
    local hash_config = vhost_resolver.get_hash_content_config(context)
    local form_hash = nil

    if hash_config.enabled and hash_config.fields and #hash_config.fields > 0 then
        -- Hash only specified fields
        form_hash = content_hasher.hash_fields(form_data, hash_config.fields)

        -- Check if hash is in blocklist
        if form_hash then
            local hash_blocked = keyword_filter.is_hash_blocked(form_hash)
            if hash_blocked then
                blocked = true
                block_reason = "blocked_hash"
                table.insert(spam_flags, "hash:blocked")
            end
        end
    end

    -- Step 3: Pattern-based scoring
    local should_inherit_patterns = true
    if context.endpoint then
        should_inherit_patterns = config_resolver.should_inherit_global_patterns(context.endpoint)
    end

    if should_inherit_patterns then
        local pattern_result = keyword_filter.pattern_scan(form_data)

        -- Filter out disabled patterns
        if pattern_result.flags and context.endpoint then
            for _, flag_entry in ipairs(pattern_result.flags) do
                local flag_name = flag_entry:match("([^:]+)")
                if not config_resolver.is_pattern_disabled(context.endpoint, flag_name) then
                    table.insert(spam_flags, "pattern:" .. flag_entry)
                end
            end
        elseif pattern_result.flags then
            for _, flag_entry in ipairs(pattern_result.flags) do
                table.insert(spam_flags, "pattern:" .. flag_entry)
            end
        end

        -- Add pattern score
        spam_score = spam_score + (pattern_result.score or 0)
    end

    -- Check endpoint-specific custom patterns
    if context.endpoint then
        local custom_patterns = config_resolver.get_custom_patterns(context.endpoint)
        if #custom_patterns > 0 then
            local combined_text = form_parser.get_combined_text(form_data)
            for _, pattern_def in ipairs(custom_patterns) do
                local matches = {}
                for match in combined_text:gmatch(pattern_def.pattern) do
                    table.insert(matches, match)
                end
                if #matches > 0 then
                    local pattern_score = (pattern_def.score or 10) * math.min(#matches, 5)
                    spam_score = spam_score + pattern_score
                    table.insert(spam_flags, "ep_pattern:" .. (pattern_def.flag or "custom") .. ":" .. #matches)
                end
            end
        end
    end

    -- Step 4: Check spam score threshold
    local block_threshold = vhost_resolver.get_block_threshold(context)
    if spam_score >= block_threshold then
        blocked = true
        block_reason = "spam_score_exceeded"
        table.insert(spam_flags, "score:exceeded")
    end

    -- Set response headers for HAProxy
    if form_hash then
        ngx.header["X-Form-Hash"] = form_hash
    end
    ngx.header["X-Spam-Score"] = tostring(spam_score)
    ngx.header["X-Spam-Flags"] = table.concat(spam_flags, ",")
    ngx.header["X-Client-IP"] = client_ip

    -- Determine if we should actually block
    local should_block = blocked and vhost_resolver.should_block(context)

    -- In monitoring mode, log but don't block
    if blocked and not should_block then
        ngx.header["X-WAF-Would-Block"] = "true"
        ngx.header["X-WAF-Block-Reason"] = block_reason
        ngx.log(ngx.WARN, string.format(
            "MONITORING (would block): ip=%s host=%s path=%s vhost=%s endpoint=%s reason=%s score=%d hash=%s flags=%s",
            client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
            block_reason, spam_score, form_hash, table.concat(spam_flags, ",")
        ))
        return
    end

    -- If blocked at OpenResty level, respond immediately
    if should_block then
        ngx.header["X-Blocked"] = "true"
        ngx.header["X-Block-Reason"] = block_reason

        -- Log the block
        ngx.log(ngx.WARN, string.format(
            "BLOCKED: ip=%s host=%s path=%s vhost=%s endpoint=%s reason=%s score=%d hash=%s flags=%s",
            client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
            block_reason, spam_score, form_hash, table.concat(spam_flags, ",")
        ))

        -- Return 403 with JSON error
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header["Content-Type"] = "application/json"
        ngx.say(cjson.encode({
            error = "Request blocked",
            reason = block_reason,
            vhost = summary.vhost_id,
            endpoint = summary.endpoint_id,
            request_id = ngx.var.request_id or ngx.now()
        }))
        return ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    -- Log processing info
    ngx.log(ngx.INFO, string.format(
        "PROCESSED: ip=%s host=%s path=%s vhost=%s endpoint=%s mode=%s score=%d hash=%s flags=%s",
        client_ip, host, path, summary.vhost_id, summary.endpoint_id or "global",
        summary.mode, spam_score, form_hash, table.concat(spam_flags, ",")
    ))
end

-- Get routing decision for balancer phase
-- Returns: {use_haproxy = bool, upstream_url = string|nil, haproxy_backend = string|nil}
function _M.get_routing_decision()
    local routing = ngx.ctx.waf_routing
    if not routing then
        return {use_haproxy = true}
    end

    return {
        use_haproxy = routing.use_haproxy,
        upstream = routing.upstream,
        haproxy_backend = routing.haproxy_backend
    }
end

-- Get vhost context (for use in other modules)
function _M.get_context()
    return ngx.ctx.waf_context
end

return _M
