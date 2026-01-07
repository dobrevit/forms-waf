-- api_handlers/attack_signatures.lua
-- Attack signature management API handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"
local attack_signatures_store = require "attack_signatures_store"
local redis_sync = require "redis_sync"

-- Handlers table
_M.handlers = {}

-- GET /attack-signatures - List all signatures
_M.handlers["GET:/attack-signatures"] = function()
    local args = ngx.req.get_uri_args()

    local opts = {
        tag = args.tag,
        active_only = args.active == "true",
        enabled = args.enabled == "true" and true or (args.enabled == "false" and false or nil),
        include_stats = args.include_stats ~= "false",
    }

    local signatures, err = attack_signatures_store.list(opts)
    if not signatures then
        return utils.error_response("Failed to list signatures: " .. (err or "unknown"), 500)
    end

    return utils.json_response({signatures = signatures})
end

-- POST /attack-signatures - Create a new signature
_M.handlers["POST:/attack-signatures"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Validate required fields
    if not data.id then
        return utils.error_response("Missing 'id' field")
    end

    if not data.name or data.name == "" then
        return utils.error_response("Missing 'name' field")
    end

    -- Create signature
    local signature, err = attack_signatures_store.create(data)
    if not signature then
        local status = 400
        if err and err:find("already exists") then
            status = 409
        end
        return utils.error_response(err or "Failed to create signature", status)
    end

    redis_sync.sync_now()
    return utils.json_response({created = true, signature = signature})
end

-- GET /attack-signatures/:id - Get a specific signature
_M.handlers["GET:/attack-signatures/:id"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing signature ID")
    end

    local signature, err = attack_signatures_store.get(id)
    if not signature then
        local status = 404
        if err and err:find("not found") then
            status = 404
        else
            status = 500
        end
        return utils.error_response(err or "Failed to get signature", status)
    end

    return utils.json_response({signature = signature})
end

-- PUT /attack-signatures/:id - Update a signature
_M.handlers["PUT:/attack-signatures/:id"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing signature ID")
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local signature, err = attack_signatures_store.update(id, data)
    if not signature then
        local status = 400
        if err and err:find("not found") then
            status = 404
        end
        return utils.error_response(err or "Failed to update signature", status)
    end

    redis_sync.sync_now()
    return utils.json_response({updated = true, signature = signature})
end

-- DELETE /attack-signatures/:id - Delete a signature
_M.handlers["DELETE:/attack-signatures/:id"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing signature ID")
    end

    local ok, err = attack_signatures_store.delete(id)
    if not ok then
        local status = 400
        if err and err:find("not found") then
            status = 404
        elseif err and err:find("Cannot delete builtin") then
            status = 403
        end
        return utils.error_response(err or "Failed to delete signature", status)
    end

    redis_sync.sync_now()
    return utils.json_response({deleted = true, id = id})
end

-- POST /attack-signatures/:id/clone - Clone a signature
_M.handlers["POST:/attack-signatures/:id/clone"] = function(params)
    local source_id = params.id
    if not source_id or source_id == "" then
        return utils.error_response("Missing source signature ID")
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    local new_id = data.id
    local new_name = data.name

    if not new_id or new_id == "" then
        return utils.error_response("Missing 'id' for new signature")
    end

    if not new_id:match("^[a-zA-Z0-9_-]+$") then
        return utils.error_response("Signature ID must contain only alphanumeric characters, hyphens, and underscores")
    end

    local signature, err = attack_signatures_store.clone(source_id, new_id, new_name)
    if not signature then
        local status = 400
        if err and err:find("not found") then
            status = 404
        elseif err and err:find("already exists") then
            status = 409
        end
        return utils.error_response(err or "Failed to clone signature", status)
    end

    redis_sync.sync_now()
    return utils.json_response({cloned = true, signature = signature})
end

-- POST /attack-signatures/:id/enable - Enable a signature
_M.handlers["POST:/attack-signatures/:id/enable"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing signature ID")
    end

    local signature, err = attack_signatures_store.enable(id)
    if not signature then
        local status = 400
        if err and err:find("not found") then
            status = 404
        end
        return utils.error_response(err or "Failed to enable signature", status)
    end

    redis_sync.sync_now()
    return utils.json_response({enabled = true, signature = signature})
end

-- POST /attack-signatures/:id/disable - Disable a signature
_M.handlers["POST:/attack-signatures/:id/disable"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing signature ID")
    end

    local signature, err = attack_signatures_store.disable(id)
    if not signature then
        local status = 400
        if err and err:find("not found") then
            status = 404
        end
        return utils.error_response(err or "Failed to disable signature", status)
    end

    redis_sync.sync_now()
    return utils.json_response({disabled = true, signature = signature})
end

-- GET /attack-signatures/:id/stats - Get signature statistics
_M.handlers["GET:/attack-signatures/:id/stats"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing signature ID")
    end

    -- Check if signature exists
    local signature, err = attack_signatures_store.get(id)
    if not signature then
        local status = 404
        if err and err:find("not found") then
            status = 404
        else
            status = 500
        end
        return utils.error_response(err or "Signature not found", status)
    end

    local stats, stats_err = attack_signatures_store.get_stats(id)
    if not stats then
        return utils.error_response("Failed to get stats: " .. (stats_err or "unknown"), 500)
    end

    return utils.json_response({stats = stats})
end

-- GET /attack-signatures/builtins - List builtin signatures
_M.handlers["GET:/attack-signatures/builtins"] = function()
    local ids, err = attack_signatures_store.get_builtin_ids()
    if not ids then
        return utils.error_response("Failed to get builtin IDs: " .. (err or "unknown"), 500)
    end

    return utils.json_response({builtin_ids = ids})
end

-- POST /attack-signatures/reset-builtins - Reset builtin signatures to defaults
_M.handlers["POST:/attack-signatures/reset-builtins"] = function()
    local builtins = require "attack_signatures_builtins"
    local count, err = attack_signatures_store.reset_builtins(builtins.SIGNATURES)
    if not count then
        return utils.error_response("Failed to reset builtins: " .. (err or "unknown"), 500)
    end

    redis_sync.sync_now()
    return utils.json_response({reset = true, count = count})
end

-- GET /attack-signatures/tags - List all tags with counts
_M.handlers["GET:/attack-signatures/tags"] = function()
    local tags, err = attack_signatures_store.get_all_tags()
    if not tags then
        return utils.error_response("Failed to get tags: " .. (err or "unknown"), 500)
    end

    return utils.json_response({tags = tags})
end

-- GET /attack-signatures/export - Export signatures
_M.handlers["GET:/attack-signatures/export"] = function()
    local args = ngx.req.get_uri_args()
    local ids = args.ids

    -- Parse comma-separated IDs if provided
    local id_list = nil
    if ids and ids ~= "" then
        id_list = {}
        for id in ids:gmatch("[^,]+") do
            table.insert(id_list, id:match("^%s*(.-)%s*$"))  -- trim whitespace
        end
    end

    local signatures, err = attack_signatures_store.export(id_list)
    if not signatures then
        return utils.error_response("Failed to export: " .. (err or "unknown"), 500)
    end

    return utils.json_response({
        signatures = signatures,
        exported_at = ngx.utctime(),
        count = #signatures
    })
end

-- POST /attack-signatures/import - Import signatures
_M.handlers["POST:/attack-signatures/import"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    if not data.signatures or type(data.signatures) ~= "table" then
        return utils.error_response("Missing 'signatures' array")
    end

    local opts = {
        overwrite = data.overwrite == true,
        skip_existing = data.skip_existing == true,
    }

    local imported, errors = attack_signatures_store.import(data.signatures, opts)

    redis_sync.sync_now()
    return utils.json_response({
        imported = imported,
        errors = errors,
        total = #data.signatures
    })
end

-- POST /attack-signatures/validate - Validate a signature
_M.handlers["POST:/attack-signatures/validate"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local valid, errors = attack_signatures_store.validate(data)

    return utils.json_response({
        valid = valid,
        errors = errors or {}
    })
end

-- GET /attack-signatures/stats/summary - Get overall signature stats summary
_M.handlers["GET:/attack-signatures/stats/summary"] = function()
    local signatures, err = attack_signatures_store.list({include_stats = true})
    if not signatures then
        return utils.error_response("Failed to get signatures: " .. (err or "unknown"), 500)
    end

    local total_signatures = #signatures
    local enabled_count = 0
    local builtin_count = 0
    local total_matches = 0
    local matches_by_type = {}

    for _, sig in ipairs(signatures) do
        if sig.enabled then
            enabled_count = enabled_count + 1
        end
        if sig.builtin then
            builtin_count = builtin_count + 1
        end
        if sig.stats then
            total_matches = total_matches + (sig.stats.total_matches or 0)
            if sig.stats.matches_by_type then
                for match_type, count in pairs(sig.stats.matches_by_type) do
                    matches_by_type[match_type] = (matches_by_type[match_type] or 0) + count
                end
            end
        end
    end

    return utils.json_response({
        summary = {
            total_signatures = total_signatures,
            enabled_count = enabled_count,
            disabled_count = total_signatures - enabled_count,
            builtin_count = builtin_count,
            custom_count = total_signatures - builtin_count,
            total_matches = total_matches,
            matches_by_type = matches_by_type
        }
    })
end

-- POST /attack-signatures/:id/test - Test a signature against sample data
_M.handlers["POST:/attack-signatures/:id/test"] = function(params)
    local id = params.id
    if not id or id == "" then
        return utils.error_response("Missing signature ID")
    end

    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    -- Get signature
    local signature, err = attack_signatures_store.get(id)
    if not signature then
        local status = 404
        if err and err:find("not found") then
            status = 404
        else
            status = 500
        end
        return utils.error_response(err or "Signature not found", status)
    end

    -- Test data should have sample values for various fields
    local sample = data.sample or {}
    local results = {
        signature_id = id,
        signature_name = signature.name,
        matches = {},
        total_score = 0,
        would_block = false
    }

    -- Test fingerprint patterns (user-agent)
    if signature.signatures and signature.signatures.fingerprint and sample.user_agent then
        local ua = sample.user_agent
        local fp = signature.signatures.fingerprint

        -- Check blocked user agents
        if fp.blocked_user_agents then
            for _, pattern in ipairs(fp.blocked_user_agents) do
                local ok, matched = pcall(function()
                    return ua:match(pattern)
                end)
                if ok and matched then
                    table.insert(results.matches, {
                        type = "fingerprint",
                        pattern_type = "blocked_user_agents",
                        pattern = pattern,
                        matched_value = ua,
                        action = "block"
                    })
                    results.would_block = true
                elseif not ok then
                    ngx.log(ngx.WARN, "attack_signatures_test: invalid pattern in blocked_user_agents: ", pattern, " - error: ", tostring(matched))
                end
            end
        end

        -- Check flagged user agents
        if fp.flagged_user_agents then
            for _, item in ipairs(fp.flagged_user_agents) do
                local pattern = item.pattern or item[1]
                local score = item.score or item[2] or 10
                local ok, matched = pcall(function()
                    return ua:match(pattern)
                end)
                if ok and matched then
                    table.insert(results.matches, {
                        type = "fingerprint",
                        pattern_type = "flagged_user_agents",
                        pattern = pattern,
                        matched_value = ua,
                        action = "flag",
                        score = score
                    })
                    results.total_score = results.total_score + score
                elseif not ok then
                    ngx.log(ngx.WARN, "attack_signatures_test: invalid pattern in flagged_user_agents: ", pattern, " - error: ", tostring(matched))
                end
            end
        end
    end

    -- Test keyword patterns
    if signature.signatures and signature.signatures.keyword_filter then
        local kf = signature.signatures.keyword_filter
        local content = sample.content or sample.body or ""

        -- Check blocked keywords
        if kf.blocked_keywords then
            for _, keyword in ipairs(kf.blocked_keywords) do
                if content:lower():find(keyword:lower(), 1, true) then
                    table.insert(results.matches, {
                        type = "keyword_filter",
                        pattern_type = "blocked_keywords",
                        pattern = keyword,
                        matched_value = content:sub(1, 100),
                        action = "block"
                    })
                    results.would_block = true
                end
            end
        end

        -- Check flagged keywords
        if kf.flagged_keywords then
            for _, item in ipairs(kf.flagged_keywords) do
                local keyword = item.keyword or item[1]
                local score = item.score or item[2] or 10
                if content:lower():find(keyword:lower(), 1, true) then
                    table.insert(results.matches, {
                        type = "keyword_filter",
                        pattern_type = "flagged_keywords",
                        pattern = keyword,
                        matched_value = content:sub(1, 100),
                        action = "flag",
                        score = score
                    })
                    results.total_score = results.total_score + score
                end
            end
        end

        -- Check blocked patterns (regex)
        if kf.blocked_patterns then
            for _, pattern in ipairs(kf.blocked_patterns) do
                local ok, matched = pcall(function()
                    return content:match(pattern)
                end)
                if ok and matched then
                    table.insert(results.matches, {
                        type = "keyword_filter",
                        pattern_type = "blocked_patterns",
                        pattern = pattern,
                        matched_value = matched,
                        action = "block"
                    })
                    results.would_block = true
                elseif not ok then
                    ngx.log(ngx.WARN, "attack_signatures_test: invalid pattern in blocked_patterns: ", pattern, " - error: ", tostring(matched))
                end
            end
        end

        -- Check flagged patterns (regex)
        if kf.flagged_patterns then
            for _, item in ipairs(kf.flagged_patterns) do
                local pattern = item.pattern or item[1]
                local score = item.score or item[2] or 10
                local ok, matched = pcall(function()
                    return content:match(pattern)
                end)
                if ok and matched then
                    table.insert(results.matches, {
                        type = "keyword_filter",
                        pattern_type = "flagged_patterns",
                        pattern = pattern,
                        matched_value = matched,
                        action = "flag",
                        score = score
                    })
                    results.total_score = results.total_score + score
                elseif not ok then
                    ngx.log(ngx.WARN, "attack_signatures_test: invalid pattern in flagged_patterns: ", pattern, " - error: ", tostring(matched))
                end
            end
        end
    end

    -- Test rate limiter patterns
    if signature.signatures and signature.signatures.rate_limiter and sample.username then
        local rl = signature.signatures.rate_limiter
        local username = sample.username

        -- Check blocked usernames
        if rl.blocked_usernames then
            for _, blocked_user in ipairs(rl.blocked_usernames) do
                if username:lower() == blocked_user:lower() then
                    table.insert(results.matches, {
                        type = "rate_limiter",
                        pattern_type = "blocked_usernames",
                        pattern = blocked_user,
                        matched_value = username,
                        action = "block"
                    })
                    results.would_block = true
                end
            end
        end

        -- Check blocked password patterns
        if rl.blocked_passwords and sample.password then
            for _, blocked_pass in ipairs(rl.blocked_passwords) do
                if sample.password:lower() == blocked_pass:lower() then
                    table.insert(results.matches, {
                        type = "rate_limiter",
                        pattern_type = "blocked_passwords",
                        pattern = "[redacted]",
                        matched_value = "[redacted]",
                        action = "block"
                    })
                    results.would_block = true
                end
            end
        end
    end

    return utils.json_response({
        test = results,
        sample_provided = sample
    })
end

return _M
