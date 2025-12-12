-- metrics.lua
-- Prometheus metrics exporter

local _M = {}

-- Shared dictionaries
local keyword_cache = ngx.shared.keyword_cache
local hash_cache = ngx.shared.hash_cache
local rate_limit = ngx.shared.rate_limit

-- Generate Prometheus format metrics
function _M.get_prometheus()
    local lines = {}

    -- Helper to add metric
    local function add_metric(name, help, type, value, labels)
        table.insert(lines, "# HELP " .. name .. " " .. help)
        table.insert(lines, "# TYPE " .. name .. " " .. type)

        if labels then
            table.insert(lines, name .. "{" .. labels .. "} " .. tostring(value))
        else
            table.insert(lines, name .. " " .. tostring(value))
        end
    end

    -- Shared dict stats
    local function dict_stats(name, dict)
        if dict then
            local capacity = dict:capacity() or 0
            local free = dict:free_space() or 0
            local used = capacity - free

            add_metric(
                "waf_shared_dict_bytes",
                "Shared dictionary memory usage",
                "gauge",
                used,
                'dict="' .. name .. '"'
            )
            add_metric(
                "waf_shared_dict_capacity_bytes",
                "Shared dictionary capacity",
                "gauge",
                capacity,
                'dict="' .. name .. '"'
            )
        end
    end

    dict_stats("keyword_cache", keyword_cache)
    dict_stats("hash_cache", hash_cache)
    dict_stats("rate_limit", rate_limit)

    -- Worker info
    add_metric(
        "waf_worker_id",
        "Current worker ID",
        "gauge",
        ngx.worker.id()
    )

    add_metric(
        "waf_worker_count",
        "Total worker count",
        "gauge",
        ngx.worker.count()
    )

    -- Connection stats
    add_metric(
        "waf_connections_active",
        "Active connections",
        "gauge",
        ngx.var.connections_active or 0
    )

    add_metric(
        "waf_connections_reading",
        "Connections reading",
        "gauge",
        ngx.var.connections_reading or 0
    )

    add_metric(
        "waf_connections_writing",
        "Connections writing",
        "gauge",
        ngx.var.connections_writing or 0
    )

    add_metric(
        "waf_connections_waiting",
        "Connections waiting",
        "gauge",
        ngx.var.connections_waiting or 0
    )

    return table.concat(lines, "\n") .. "\n"
end

return _M
