-- defense_line_executor.lua
-- Executes defense lines with attack signature merging
-- Defense lines run AFTER base profile passes and are ADDITIVE

local _M = {}

local cjson = require "cjson.safe"

-- Lazy-load dependencies to avoid circular requires
local _profile_executor
local _profile_store
local _signature_store

local function get_profile_executor()
    if not _profile_executor then
        _profile_executor = require "defense_profile_executor"
    end
    return _profile_executor
end

local function get_profile_store()
    if not _profile_store then
        _profile_store = require "defense_profiles_store"
    end
    return _profile_store
end

local function get_signature_store()
    if not _signature_store then
        _signature_store = require "attack_signatures_store"
    end
    return _signature_store
end

-- Helper to extend arrays (append items from source to target)
local function extend(target, source)
    if not source then return target end
    for _, item in ipairs(source) do
        table.insert(target, item)
    end
    return target
end

-- Helper to deep copy a table
local function deep_copy(orig)
    if type(orig) ~= 'table' then return orig end
    local copy = {}
    for k, v in pairs(orig) do
        copy[k] = deep_copy(v)
    end
    return copy
end

-- Resolve attack signatures from signature IDs
-- Returns array of signature objects sorted by priority
function _M.resolve_signatures(signature_ids)
    if not signature_ids or #signature_ids == 0 then
        return {}
    end

    local store = get_signature_store()
    local signatures = {}

    for i, sig_id in ipairs(signature_ids) do
        local sig, err = store.get(sig_id)
        if sig and sig.enabled ~= false then
            table.insert(signatures, {
                signature = sig,
                priority = sig.priority or (i * 10)  -- Use index as default priority
            })
        else
            ngx.log(ngx.WARN, "Failed to load signature '", sig_id, "': ", err or "disabled")
        end
    end

    -- Sort by priority (lower = first)
    table.sort(signatures, function(a, b)
        return a.priority < b.priority
    end)

    return signatures
end

-- Merge signatures for a specific defense type
-- Returns merged config that can be used by the defense node
function _M.merge_signatures_for_defense(defense_type, signatures)
    local merged = {}

    for _, entry in ipairs(signatures) do
        local sig = entry.signature
        local section = sig.signatures and sig.signatures[defense_type]
        if not section then goto continue end

        if defense_type == "ip_allowlist" then
            merged.allowed_cidrs = extend(merged.allowed_cidrs or {}, section.allowed_cidrs)
            merged.allowed_ips = extend(merged.allowed_ips or {}, section.allowed_ips)

        elseif defense_type == "geoip" then
            merged.blocked_countries = extend(merged.blocked_countries or {}, section.blocked_countries)
            merged.flagged_countries = extend(merged.flagged_countries or {}, section.flagged_countries)
            merged.blocked_regions = extend(merged.blocked_regions or {}, section.blocked_regions)
            merged.flagged_regions = extend(merged.flagged_regions or {}, section.flagged_regions)

        elseif defense_type == "ip_reputation" then
            merged.blocked_cidrs = extend(merged.blocked_cidrs or {}, section.blocked_cidrs)
            merged.flagged_cidrs = extend(merged.flagged_cidrs or {}, section.flagged_cidrs)
            merged.blocked_asns = extend(merged.blocked_asns or {}, section.blocked_asns)
            if section.min_reputation_score then
                merged.min_reputation_score = math.max(
                    merged.min_reputation_score or 0,
                    section.min_reputation_score
                )
            end

        elseif defense_type == "timing_token" then
            if section.min_time_ms then
                merged.min_time_ms = math.max(merged.min_time_ms or 0, section.min_time_ms)
            end
            if section.max_time_ms then
                merged.max_time_ms = math.min(merged.max_time_ms or 999999999, section.max_time_ms)
            end
            merged.require_token = merged.require_token or section.require_token

        elseif defense_type == "behavioral" then
            if section.min_interaction_score then
                merged.min_interaction_score = math.max(
                    merged.min_interaction_score or 0,
                    section.min_interaction_score
                )
            end
            if section.min_time_on_page_ms then
                merged.min_time_on_page_ms = math.max(
                    merged.min_time_on_page_ms or 0,
                    section.min_time_on_page_ms
                )
            end
            if section.max_time_on_page_ms then
                merged.max_time_on_page_ms = math.min(
                    merged.max_time_on_page_ms or 999999999,
                    section.max_time_on_page_ms
                )
            end
            merged.require_mouse_movement = merged.require_mouse_movement or section.require_mouse_movement
            merged.require_keyboard_input = merged.require_keyboard_input or section.require_keyboard_input
            merged.require_scroll = merged.require_scroll or section.require_scroll

        elseif defense_type == "honeypot" then
            merged.field_names = extend(merged.field_names or {}, section.field_names)
            if section.blocked_if_filled ~= nil then
                merged.blocked_if_filled = merged.blocked_if_filled ~= false and section.blocked_if_filled ~= false
            end
            if section.score_if_filled then
                merged.score_if_filled = math.max(merged.score_if_filled or 0, section.score_if_filled)
            end

        elseif defense_type == "keyword_filter" then
            merged.blocked_keywords = extend(merged.blocked_keywords or {}, section.blocked_keywords)
            merged.flagged_keywords = extend(merged.flagged_keywords or {}, section.flagged_keywords)
            merged.blocked_patterns = extend(merged.blocked_patterns or {}, section.blocked_patterns)
            merged.flagged_patterns = extend(merged.flagged_patterns or {}, section.flagged_patterns)

        elseif defense_type == "content_hash" then
            merged.blocked_hashes = extend(merged.blocked_hashes or {}, section.blocked_hashes)
            merged.blocked_fuzzy_hashes = extend(merged.blocked_fuzzy_hashes or {}, section.blocked_fuzzy_hashes)
            merged.flagged_hashes = extend(merged.flagged_hashes or {}, section.flagged_hashes)

        elseif defense_type == "expected_fields" then
            merged.required_fields = extend(merged.required_fields or {}, section.required_fields)
            merged.forbidden_fields = extend(merged.forbidden_fields or {}, section.forbidden_fields)
            merged.optional_fields = extend(merged.optional_fields or {}, section.optional_fields)
            if section.max_extra_fields then
                merged.max_extra_fields = math.min(
                    merged.max_extra_fields or 999999,
                    section.max_extra_fields
                )
            end

        elseif defense_type == "pattern_scan" then
            merged.blocked_patterns = extend(merged.blocked_patterns or {}, section.blocked_patterns)
            merged.flagged_patterns = extend(merged.flagged_patterns or {}, section.flagged_patterns)
            merged.scan_fields = extend(merged.scan_fields or {}, section.scan_fields)
            merged.multiline = merged.multiline or section.multiline

        elseif defense_type == "disposable_email" then
            merged.blocked_domains = extend(merged.blocked_domains or {}, section.blocked_domains)
            merged.allowed_domains = extend(merged.allowed_domains or {}, section.allowed_domains)
            merged.blocked_patterns = extend(merged.blocked_patterns or {}, section.blocked_patterns)
            merged.flagged_domains = extend(merged.flagged_domains or {}, section.flagged_domains)

        elseif defense_type == "field_anomalies" then
            merged.field_rules = extend(merged.field_rules or {}, section.field_rules)
            if section.max_field_length then
                merged.max_field_length = math.min(
                    merged.max_field_length or 999999,
                    section.max_field_length
                )
            end
            if section.max_total_size then
                merged.max_total_size = math.min(
                    merged.max_total_size or 999999999,
                    section.max_total_size
                )
            end

        elseif defense_type == "fingerprint" then
            merged.blocked_user_agents = extend(merged.blocked_user_agents or {}, section.blocked_user_agents)
            merged.flagged_user_agents = extend(merged.flagged_user_agents or {}, section.flagged_user_agents)
            merged.required_fingerprint_fields = extend(merged.required_fingerprint_fields or {}, section.required_fingerprint_fields)
            merged.blocked_fingerprints = extend(merged.blocked_fingerprints or {}, section.blocked_fingerprints)
            merged.flagged_fingerprints = extend(merged.flagged_fingerprints or {}, section.flagged_fingerprints)

        elseif defense_type == "header_consistency" then
            merged.required_headers = extend(merged.required_headers or {}, section.required_headers)
            merged.forbidden_headers = extend(merged.forbidden_headers or {}, section.forbidden_headers)
            merged.header_rules = extend(merged.header_rules or {}, section.header_rules)

        elseif defense_type == "rate_limiter" then
            -- Use most restrictive rate limits
            if section.requests_per_second then
                merged.requests_per_second = math.min(
                    merged.requests_per_second or 999999,
                    section.requests_per_second
                )
            end
            if section.requests_per_minute then
                merged.requests_per_minute = math.min(
                    merged.requests_per_minute or 999999,
                    section.requests_per_minute
                )
            end
            if section.requests_per_hour then
                merged.requests_per_hour = math.min(
                    merged.requests_per_hour or 999999,
                    section.requests_per_hour
                )
            end
            if section.burst_limit then
                merged.burst_limit = math.min(
                    merged.burst_limit or 999999,
                    section.burst_limit
                )
            end
            if section.by_field then
                merged.by_field = section.by_field
            end
        end

        ::continue::
    end

    return merged
end

-- Get all defense types used by a profile
local function get_profile_defense_types(profile)
    local types = {}
    if profile.graph and profile.graph.nodes then
        for _, node in ipairs(profile.graph.nodes) do
            if node.type == "defense" and node.defense then
                types[node.defense] = true
            end
        end
    end
    return types
end

-- Create a modified profile with signature patterns merged into defense node configs
function _M.create_merged_profile(profile, signatures)
    if not signatures or #signatures == 0 then
        return profile
    end

    -- Deep copy the profile to avoid modifying the original
    local merged_profile = deep_copy(profile)

    -- Get which defense types are used by this profile
    local defense_types = get_profile_defense_types(profile)

    -- For each defense type in the profile, merge signature patterns
    for _, node in ipairs(merged_profile.graph.nodes) do
        if node.type == "defense" and node.defense then
            local merged_patterns = _M.merge_signatures_for_defense(node.defense, signatures)

            -- Merge patterns into node config
            if next(merged_patterns) then
                node.config = node.config or {}
                node.config.signature_patterns = merged_patterns
                node.config.has_signatures = true
            end
        end
    end

    return merged_profile
end

-- Execute a single defense line
-- A defense line consists of: profile_id + signature_ids
function _M.execute_defense_line(defense_line, request_context)
    local start_time = ngx.now()

    if not defense_line then
        return {
            action = "allow",
            score = 0,
            flags = {},
            execution_time_ms = 0
        }
    end

    -- Check if enabled
    if defense_line.enabled == false then
        return {
            action = "allow",
            score = 0,
            flags = {"defense_line_disabled"},
            execution_time_ms = 0
        }
    end

    -- Get the profile
    local store = get_profile_store()
    local profile, err = store.get(defense_line.profile_id)
    if not profile then
        ngx.log(ngx.ERR, "Defense line profile not found: ", defense_line.profile_id, " - ", err)
        return {
            action = "allow",
            score = 0,
            flags = {"defense_line_profile_error"},
            details = {error = err, profile_id = defense_line.profile_id},
            execution_time_ms = (ngx.now() - start_time) * 1000
        }
    end

    -- Check if profile is enabled
    if not profile.enabled then
        return {
            action = "allow",
            score = 0,
            flags = {"defense_line_profile_disabled"},
            execution_time_ms = (ngx.now() - start_time) * 1000
        }
    end

    -- Resolve attack signatures
    local signatures = _M.resolve_signatures(defense_line.signature_ids)

    -- Create merged profile with signature patterns
    local merged_profile = _M.create_merged_profile(profile, signatures)

    -- Execute the merged profile
    local executor = get_profile_executor()
    local result = executor.execute(merged_profile, request_context)

    -- Add signature attribution
    result.signatures_loaded = #signatures
    result.signature_ids = defense_line.signature_ids
    result.profile_id = defense_line.profile_id

    return result
end

-- Execute all defense lines for an endpoint
-- Defense lines run AFTER base profile passes
-- If ANY defense line blocks, the request is blocked
function _M.execute(defense_lines, request_context)
    local start_time = ngx.now()

    if not defense_lines or #defense_lines == 0 then
        return {
            action = "allow",
            score = 0,
            flags = {},
            details = {},
            defense_lines_executed = 0,
            blocked_by_line = nil,
            execution_time_ms = 0
        }
    end

    local all_flags = {}
    local all_details = {}
    local total_score = 0
    local blocked_by_line = nil
    local line_results = {}

    -- Execute each defense line sequentially
    -- (Could be parallelized in the future if needed)
    for i, defense_line in ipairs(defense_lines) do
        local line_result = _M.execute_defense_line(defense_line, request_context)

        -- Record result
        line_results[i] = {
            profile_id = defense_line.profile_id,
            signature_ids = defense_line.signature_ids,
            action = line_result.action,
            score = line_result.score,
            flags = line_result.flags,
            execution_time_ms = line_result.execution_time_ms
        }

        -- Accumulate score
        total_score = total_score + (line_result.score or 0)

        -- Collect flags with line prefix
        if line_result.flags then
            for _, flag in ipairs(line_result.flags) do
                table.insert(all_flags, "line" .. i .. ":" .. flag)
            end
        end

        -- Collect details
        if line_result.details then
            all_details["line" .. i] = line_result.details
        end

        -- If this line blocks, record it and stop (short-circuit)
        if line_result.action == "block" then
            blocked_by_line = i
            ngx.log(ngx.INFO, string.format(
                "DEFENSE_LINE_BLOCK: line=%d profile=%s signatures=%s score=%d",
                i, defense_line.profile_id,
                table.concat(defense_line.signature_ids or {}, ","),
                line_result.score or 0
            ))
            break
        end
    end

    local execution_time_ms = (ngx.now() - start_time) * 1000

    return {
        action = blocked_by_line and "block" or "allow",
        score = total_score,
        flags = all_flags,
        details = all_details,
        defense_lines_executed = #line_results,
        blocked_by_line = blocked_by_line,
        line_results = line_results,
        execution_time_ms = execution_time_ms
    }
end

-- Track signature match for analytics
function _M.track_signature_match(signature_id, match_type)
    -- Use shared memory for fast tracking
    local dict = ngx.shared.waf_signature_stats
    if not dict then
        return
    end

    local ok, err = dict:incr(signature_id .. ":total", 1, 0)
    if not ok then
        ngx.log(ngx.WARN, "Failed to increment signature stats: ", err)
        return
    end

    dict:incr(signature_id .. ":" .. match_type, 1, 0)
    dict:set(signature_id .. ":last_match", ngx.time())
end

return _M
