-- field_learner.lua
-- Learns form field names from traffic for configuration assistance
-- Uses local batching to minimize Redis load

local _M = {}

local cjson = require "cjson.safe"

-- Shared dictionary for local batching (defined in nginx.conf)
local learning_cache = ngx.shared.learning_cache

-- Configuration
local BATCH_FLUSH_INTERVAL = 10  -- Flush to Redis every N seconds
local BATCH_SIZE_THRESHOLD = 100 -- Flush when batch reaches this size
local FIELD_TTL = 30 * 24 * 3600 -- 30 days in seconds
local SAMPLE_RATE = 0.1          -- Sample 10% of requests for learning (high traffic optimization)
local MAX_FIELDS_PER_ENDPOINT = 200  -- Prevent unbounded growth

-- Redis key patterns
local KEYS = {
    endpoint_fields = "waf:learning:endpoint:%s:fields",
    vhost_fields = "waf:learning:vhost:%s:fields",
    batch_queue = "learning:batch:queue",
    batch_count = "learning:batch:count",
}

-- Infer field type from name (no value inspection for compliance)
local function infer_type_from_name(field_name)
    local name_lower = field_name:lower()

    -- Token/CSRF patterns
    if name_lower:match("csrf") or name_lower:match("token") or
       name_lower:match("nonce") or name_lower:match("authenticity") then
        return "token"
    end

    -- Email patterns
    if name_lower:match("email") or name_lower:match("e%-mail") then
        return "email"
    end

    -- Phone patterns
    if name_lower:match("phone") or name_lower:match("mobile") or
       name_lower:match("tel") or name_lower:match("fax") then
        return "phone"
    end

    -- URL patterns
    if name_lower:match("url") or name_lower:match("website") or
       name_lower:match("link") or name_lower:match("href") then
        return "url"
    end

    -- Name patterns
    if name_lower:match("name") or name_lower:match("first") or
       name_lower:match("last") or name_lower:match("surname") then
        return "name"
    end

    -- Address patterns
    if name_lower:match("address") or name_lower:match("street") or
       name_lower:match("city") or name_lower:match("zip") or
       name_lower:match("postal") or name_lower:match("country") then
        return "address"
    end

    -- Message/text patterns
    if name_lower:match("message") or name_lower:match("comment") or
       name_lower:match("description") or name_lower:match("body") or
       name_lower:match("content") or name_lower:match("text") then
        return "text"
    end

    -- Password patterns
    if name_lower:match("password") or name_lower:match("passwd") or
       name_lower:match("pwd") or name_lower:match("secret") then
        return "password"
    end

    -- ID patterns
    if name_lower:match("_id$") or name_lower:match("^id$") or
       name_lower:match("uuid") or name_lower:match("guid") then
        return "id"
    end

    -- Date patterns
    if name_lower:match("date") or name_lower:match("time") or
       name_lower:match("created") or name_lower:match("updated") then
        return "datetime"
    end

    -- Number patterns
    if name_lower:match("count") or name_lower:match("amount") or
       name_lower:match("quantity") or name_lower:match("number") or
       name_lower:match("num") or name_lower:match("price") then
        return "numeric"
    end

    -- File patterns
    if name_lower:match("file") or name_lower:match("upload") or
       name_lower:match("attachment") or name_lower:match("image") then
        return "file"
    end

    -- Boolean patterns
    if name_lower:match("^is_") or name_lower:match("^has_") or
       name_lower:match("^can_") or name_lower:match("agree") or
       name_lower:match("subscribe") or name_lower:match("consent") then
        return "boolean"
    end

    return "unknown"
end

-- Add field observation to local batch
local function add_to_batch(endpoint_id, vhost_id, field_name, field_type)
    if not learning_cache then
        return false, "learning cache not available"
    end

    local now = ngx.time()
    local batch_entry = cjson.encode({
        endpoint_id = endpoint_id,
        vhost_id = vhost_id,
        field_name = field_name,
        field_type = field_type,
        timestamp = now,
    })

    -- Add to batch queue (use list-like behavior with unique key)
    local batch_key = KEYS.batch_queue .. ":" .. (endpoint_id or "none") .. ":" .. field_name
    local existing = learning_cache:get(batch_key)

    if not existing then
        -- New field observation
        local ok, err = learning_cache:set(batch_key, batch_entry, BATCH_FLUSH_INTERVAL * 2)
        if ok then
            -- Increment batch counter
            local count = learning_cache:incr(KEYS.batch_count, 1, 0)
            return true, count
        end
        return false, err
    end

    -- Field already in batch, update timestamp
    local entry = cjson.decode(existing)
    if entry then
        entry.timestamp = now
        entry.count = (entry.count or 1) + 1
        learning_cache:set(batch_key, cjson.encode(entry), BATCH_FLUSH_INTERVAL * 2)
    end

    return true, 0
end

-- Record form fields for learning
function _M.record_fields(form_data, endpoint_id, vhost_id)
    if not form_data or type(form_data) ~= "table" then
        return
    end

    -- Probabilistic sampling to reduce load on high-traffic endpoints
    if math.random() > SAMPLE_RATE then
        return
    end

    local fields_recorded = 0

    for field_name, _ in pairs(form_data) do
        if type(field_name) == "string" and field_name ~= "" then
            local field_type = infer_type_from_name(field_name)
            local ok, count = add_to_batch(endpoint_id, vhost_id, field_name, field_type)
            if ok then
                fields_recorded = fields_recorded + 1
            end
        end
    end

    return fields_recorded
end

-- Flush batch to Redis (called by timer or when threshold reached)
function _M.flush_to_redis(red)
    if not learning_cache then
        return 0, "learning cache not available"
    end

    local keys = learning_cache:get_keys(1000)
    local flushed = 0
    local now = ngx.time()

    for _, key in ipairs(keys) do
        if key:match("^" .. KEYS.batch_queue) then
            local entry_json = learning_cache:get(key)
            if entry_json then
                local entry = cjson.decode(entry_json)
                if entry then
                    -- Update endpoint-level learning
                    if entry.endpoint_id then
                        local endpoint_key = string.format(KEYS.endpoint_fields, entry.endpoint_id)
                        local existing = red:hget(endpoint_key, entry.field_name)

                        local field_data
                        if existing and existing ~= ngx.null then
                            field_data = cjson.decode(existing) or {}
                        else
                            field_data = {
                                first_seen = now,
                                count = 0,
                                type = entry.field_type,
                            }
                        end

                        field_data.count = (field_data.count or 0) + (entry.count or 1)
                        field_data.last_seen = now
                        field_data.type = field_data.type or entry.field_type

                        red:hset(endpoint_key, entry.field_name, cjson.encode(field_data))
                        red:expire(endpoint_key, FIELD_TTL)
                    end

                    -- Update vhost-level aggregation
                    if entry.vhost_id then
                        local vhost_key = string.format(KEYS.vhost_fields, entry.vhost_id)
                        local existing = red:hget(vhost_key, entry.field_name)

                        local field_data
                        if existing and existing ~= ngx.null then
                            field_data = cjson.decode(existing) or {}
                        else
                            field_data = {
                                first_seen = now,
                                count = 0,
                                type = entry.field_type,
                                endpoints = {},
                            }
                        end

                        field_data.count = (field_data.count or 0) + (entry.count or 1)
                        field_data.last_seen = now
                        field_data.type = field_data.type or entry.field_type

                        -- Track which endpoints have this field
                        if entry.endpoint_id then
                            field_data.endpoints = field_data.endpoints or {}
                            local found = false
                            for _, ep in ipairs(field_data.endpoints) do
                                if ep == entry.endpoint_id then
                                    found = true
                                    break
                                end
                            end
                            if not found and #field_data.endpoints < 50 then
                                table.insert(field_data.endpoints, entry.endpoint_id)
                            end
                        end

                        red:hset(vhost_key, entry.field_name, cjson.encode(field_data))
                        red:expire(vhost_key, FIELD_TTL)
                    end

                    flushed = flushed + 1
                end

                -- Remove from batch
                learning_cache:delete(key)
            end
        end
    end

    -- Reset batch counter
    learning_cache:set(KEYS.batch_count, 0)

    return flushed
end

-- Get learned fields for an endpoint
function _M.get_endpoint_fields(red, endpoint_id)
    if not endpoint_id then
        return {}
    end

    local key = string.format(KEYS.endpoint_fields, endpoint_id)
    local fields = red:hgetall(key)

    if not fields or fields == ngx.null then
        return {}
    end

    local result = {}
    for i = 1, #fields, 2 do
        local field_name = fields[i]
        local field_data_json = fields[i + 1]
        local field_data = cjson.decode(field_data_json) or {}

        result[field_name] = {
            name = field_name,
            type = field_data.type or "unknown",
            count = field_data.count or 0,
            first_seen = field_data.first_seen,
            last_seen = field_data.last_seen,
        }
    end

    return result
end

-- Get learned fields for a vhost
function _M.get_vhost_fields(red, vhost_id)
    if not vhost_id then
        return {}
    end

    local key = string.format(KEYS.vhost_fields, vhost_id)
    local fields = red:hgetall(key)

    if not fields or fields == ngx.null then
        return {}
    end

    local result = {}
    for i = 1, #fields, 2 do
        local field_name = fields[i]
        local field_data_json = fields[i + 1]
        local field_data = cjson.decode(field_data_json) or {}

        result[field_name] = {
            name = field_name,
            type = field_data.type or "unknown",
            count = field_data.count or 0,
            first_seen = field_data.first_seen,
            last_seen = field_data.last_seen,
            endpoints = field_data.endpoints or {},
        }
    end

    return result
end

-- Clear learned fields for an endpoint
function _M.clear_endpoint_fields(red, endpoint_id)
    if not endpoint_id then
        return false
    end

    local key = string.format(KEYS.endpoint_fields, endpoint_id)
    red:del(key)
    return true
end

-- Clear learned fields for a vhost
function _M.clear_vhost_fields(red, vhost_id)
    if not vhost_id then
        return false
    end

    local key = string.format(KEYS.vhost_fields, vhost_id)
    red:del(key)
    return true
end

-- Get learning statistics
function _M.get_stats()
    local stats = {
        batch_count = 0,
        cache_available = learning_cache ~= nil,
    }

    if learning_cache then
        stats.batch_count = learning_cache:get(KEYS.batch_count) or 0
    end

    return stats
end

-- Check if batch should be flushed
function _M.should_flush()
    if not learning_cache then
        return false
    end

    local count = learning_cache:get(KEYS.batch_count) or 0
    return count >= BATCH_SIZE_THRESHOLD
end

-- Get flush interval for timer
function _M.get_flush_interval()
    return BATCH_FLUSH_INTERVAL
end

return _M
