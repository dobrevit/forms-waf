-- api_handlers/geoip.lua
-- GeoIP management handlers

local _M = {}

local utils = require "api_handlers.utils"
local cjson = require "cjson.safe"

-- Handlers table
_M.handlers = {}

-- GET /geoip/status - Get GeoIP feature status
_M.handlers["GET:/geoip/status"] = function()
    local geoip = require "geoip"
    return utils.json_response(geoip.get_status())
end

-- GET /geoip/config - Get GeoIP configuration
_M.handlers["GET:/geoip/config"] = function()
    local geoip = require "geoip"
    return utils.json_response(geoip.get_config_for_api())
end

-- PUT /geoip/config - Update GeoIP configuration
_M.handlers["PUT:/geoip/config"] = function()
    ngx.req.read_body()
    local body = ngx.req.get_body_data()
    local data = cjson.decode(body or "{}")

    if not data then
        return utils.error_response("Invalid JSON body")
    end

    local red, err = utils.get_redis()
    if not red then
        return utils.error_response("Redis connection failed: " .. err)
    end

    -- Get existing config and merge
    local existing_json = red:get("waf:config:geoip")
    local existing = {}
    if existing_json and existing_json ~= ngx.null then
        existing = cjson.decode(existing_json) or {}
    end

    -- Merge new config into existing
    for k, v in pairs(data) do
        existing[k] = v
    end

    -- Save updated config
    red:set("waf:config:geoip", cjson.encode(existing))
    utils.close_redis(red)

    -- Reload GeoIP module
    local geoip = require "geoip"
    geoip.reload()

    return utils.json_response({
        success = true,
        config = existing
    })
end

-- POST /geoip/reload - Reload GeoIP databases
_M.handlers["POST:/geoip/reload"] = function()
    local geoip = require "geoip"
    local success = geoip.reload()
    return utils.json_response({
        success = success,
        status = geoip.get_status()
    })
end

-- GET /geoip/lookup - Lookup GeoIP info for an IP
_M.handlers["GET:/geoip/lookup"] = function()
    local args = ngx.req.get_uri_args()
    local ip = args.ip

    if not ip or ip == "" then
        return utils.error_response("Missing 'ip' parameter")
    end

    local geoip = require "geoip"
    if not geoip.is_available() then
        return utils.json_response({
            available = false,
            message = "GeoIP feature not available (database not loaded or disabled)"
        })
    end

    local country = geoip.lookup_country(ip)
    local asn = geoip.lookup_asn(ip)
    local is_dc, dc_provider = false, nil

    if asn and asn.asn then
        is_dc, dc_provider = geoip.is_datacenter(asn.asn)
    end

    return utils.json_response({
        ip = ip,
        country = country,
        asn = asn,
        is_datacenter = is_dc,
        datacenter_provider = dc_provider
    })
end

return _M
