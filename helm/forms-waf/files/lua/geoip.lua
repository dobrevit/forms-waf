-- geoip.lua
-- GeoIP lookup module for country/ASN-based restrictions
-- This is an OPTIONAL feature - gracefully degrades if MaxMind DB is not available
--
-- Usage:
-- 1. Mount MaxMind GeoLite2 databases to /usr/share/GeoIP/
--    - GeoLite2-Country.mmdb (required for country lookups)
--    - GeoLite2-ASN.mmdb (required for ASN lookups)
-- 2. Configure via Redis waf:config:geoip
-- 3. If DB files are missing, feature is disabled (no errors)

local _M = {}

local cjson = require "cjson.safe"

-- Try to load maxminddb library (may not be available)
local mmdb_available, mmdb = pcall(require, "resty.maxminddb")

-- Database paths (can be overridden via config)
local DEFAULT_COUNTRY_DB = "/usr/share/GeoIP/GeoLite2-Country.mmdb"
local DEFAULT_ASN_DB = "/usr/share/GeoIP/GeoLite2-ASN.mmdb"

-- Module state
local databases_initialized = false
local init_attempted = false
local init_warning_logged = false
local country_db_available = false
local asn_db_available = false

-- Configuration defaults
local DEFAULT_CONFIG = {
    enabled = false,
    country_db_path = DEFAULT_COUNTRY_DB,
    asn_db_path = DEFAULT_ASN_DB,
    default_action = "allow",  -- allow, block, flag
    blocked_countries = {},    -- ISO country codes to block
    allowed_countries = {},    -- If non-empty, only these countries allowed
    flagged_countries = {},    -- Countries that add score but don't block
    flagged_country_score = 15,
    blocked_asns = {},         -- ASN numbers to block (datacenters, VPNs)
    flagged_asns = {},         -- ASNs that add score
    flagged_asn_score = 20,
    datacenter_asns = {},      -- Known datacenter ASNs (auto-populated with common ones)
    block_datacenters = false, -- Block all known datacenter IPs
    flag_datacenters = true,   -- Flag datacenter IPs (adds score)
    datacenter_score = 25,
}

-- Common datacenter/hosting ASNs (can be extended via config)
local KNOWN_DATACENTER_ASNS = {
    -- Major cloud providers
    [16509] = "Amazon",
    [14618] = "Amazon",
    [15169] = "Google",
    [396982] = "Google Cloud",
    [8075] = "Microsoft Azure",
    [13335] = "Cloudflare",
    [54113] = "Fastly",
    [20940] = "Akamai",
    [16276] = "OVH",
    [24940] = "Hetzner",
    [14061] = "DigitalOcean",
    [63949] = "Linode",
    [20473] = "Vultr",
    [46664] = "Vultr",
    [36352] = "ColoCrossing",
    [55286] = "Server Central",
    [30633] = "Leaseweb",
    [60781] = "Leaseweb",
    [51167] = "Contabo",
    [197540] = "Netcup",
    -- VPN providers
    [9009] = "M247 (VPN infrastructure)",
    [212238] = "Datacamp Limited (VPN)",
    [206092] = "IPXO (VPN/proxy)",
    [62904] = "Eonix Corporation",
    [398101] = "GoDaddy",
}

-- Module-level config cache
local config_cache = nil
local config_cache_time = 0
local CONFIG_CACHE_TTL = 60

-- Check if a file exists
local function file_exists(path)
    local f = io.open(path, "r")
    if f then
        f:close()
        return true
    end
    return false
end

-- Initialize databases using lua-resty-maxminddb API
-- This library uses mmdb.init(profiles) and mmdb.lookup(ip, path, profile)
local function init_databases()
    if init_attempted then
        return databases_initialized
    end
    init_attempted = true

    if not mmdb_available then
        if not init_warning_logged then
            ngx.log(ngx.WARN, "geoip: lua-resty-maxminddb not available, GeoIP features disabled")
            init_warning_logged = true
        end
        return false
    end

    local config = _M.get_config()

    -- Build profiles table for initialization
    local profiles = {}
    local has_profiles = false

    if file_exists(config.country_db_path) then
        profiles["country"] = config.country_db_path
        has_profiles = true
        ngx.log(ngx.INFO, "geoip: found country database at ", config.country_db_path)
    else
        ngx.log(ngx.INFO, "geoip: country database not found at ", config.country_db_path)
    end

    if file_exists(config.asn_db_path) then
        profiles["asn"] = config.asn_db_path
        has_profiles = true
        ngx.log(ngx.INFO, "geoip: found ASN database at ", config.asn_db_path)
    else
        ngx.log(ngx.INFO, "geoip: ASN database not found at ", config.asn_db_path)
    end

    if not has_profiles then
        ngx.log(ngx.INFO, "geoip: no databases found, GeoIP features disabled")
        init_warning_logged = true
        return false
    end

    -- Initialize the library with profiles
    local ok, err = mmdb.init(profiles)
    if not ok then
        ngx.log(ngx.WARN, "geoip: failed to initialize maxminddb: ", err)
        init_warning_logged = true
        return false
    end

    -- Check which databases were successfully loaded
    country_db_available = mmdb.has_profile("country")
    asn_db_available = mmdb.has_profile("asn")

    databases_initialized = country_db_available or asn_db_available

    if databases_initialized then
        ngx.log(ngx.INFO, "geoip: initialized (country=", tostring(country_db_available),
                ", asn=", tostring(asn_db_available), ")")
    end

    init_warning_logged = true
    return databases_initialized
end

-- Get configuration from Redis or defaults
function _M.get_config()
    local now = ngx.now()
    if config_cache and (now - config_cache_time) < CONFIG_CACHE_TTL then
        return config_cache
    end

    -- Try to load from Redis
    local redis_sync = require "redis_sync"
    local redis = redis_sync.get_connection()

    if redis then
        local config_json = redis:get("waf:config:geoip")
        if config_json and config_json ~= ngx.null then
            local parsed = cjson.decode(config_json)
            if parsed then
                -- Merge with defaults
                for k, v in pairs(DEFAULT_CONFIG) do
                    if parsed[k] == nil then
                        parsed[k] = v
                    end
                end
                -- Add known datacenter ASNs if not overridden
                if not parsed.datacenter_asns or next(parsed.datacenter_asns) == nil then
                    parsed.datacenter_asns = KNOWN_DATACENTER_ASNS
                end
                config_cache = parsed
                config_cache_time = now
                return config_cache
            end
        end
    end

    -- Use defaults with known datacenter ASNs
    local config = {}
    for k, v in pairs(DEFAULT_CONFIG) do
        config[k] = v
    end
    config.datacenter_asns = KNOWN_DATACENTER_ASNS
    config_cache = config
    config_cache_time = now
    return config_cache
end

-- Check if GeoIP is enabled and available
function _M.is_available()
    local config = _M.get_config()
    if not config.enabled then
        return false
    end
    return init_databases()
end

-- Lookup country code for IP
-- Returns: { country_code = "US", country_name = "United States" } or nil
function _M.lookup_country(ip)
    if not databases_initialized then
        if not init_databases() then
            return nil
        end
    end

    if not country_db_available then
        return nil
    end

    -- Use the lookup function with path to country data
    local result, err = mmdb.lookup(ip, {"country", "iso_code"}, "country")
    if err or not result then
        -- Try alternate lookup for full data
        result, err = mmdb.lookup(ip, nil, "country")
        if err or not result then
            return nil
        end
        -- Extract from full result
        if result.country then
            return {
                country_code = result.country.iso_code,
                country_name = result.country.names and result.country.names.en,
            }
        end
        return nil
    end

    -- If we got direct iso_code result
    if type(result) == "string" then
        return { country_code = result }
    end

    -- Handle nested result
    if result.country then
        return {
            country_code = result.country.iso_code,
            country_name = result.country.names and result.country.names.en,
        }
    end

    return { country_code = result }
end

-- Lookup ASN for IP
-- Returns: { asn = 12345, org = "Organization Name" } or nil
function _M.lookup_asn(ip)
    if not databases_initialized then
        if not init_databases() then
            return nil
        end
    end

    if not asn_db_available then
        return nil
    end

    -- Lookup ASN data
    local result, err = mmdb.lookup(ip, nil, "asn")
    if err or not result then
        return nil
    end

    return {
        asn = result.autonomous_system_number,
        org = result.autonomous_system_organization,
    }
end

-- Check if ASN is a known datacenter
function _M.is_datacenter(asn)
    if not asn then
        return false, nil
    end

    local config = _M.get_config()
    local dc_asns = config.datacenter_asns or KNOWN_DATACENTER_ASNS

    local provider = dc_asns[asn]
    if provider then
        return true, provider
    end

    return false, nil
end

-- Main check function - returns scoring result
-- Returns: { score = number, blocked = boolean, reason = string, flags = {}, geo = {} }
function _M.check_ip(ip, endpoint_config)
    local result = {
        score = 0,
        blocked = false,
        reason = nil,
        flags = {},
        geo = {
            country_code = nil,
            country_name = nil,
            asn = nil,
            asn_org = nil,
            is_datacenter = false,
            datacenter_provider = nil,
        }
    }

    local config = _M.get_config()

    if not config.enabled then
        return result
    end

    if not init_databases() then
        return result
    end

    -- Override config with endpoint-specific settings if provided
    if endpoint_config and endpoint_config.geoip then
        local ep_geo = endpoint_config.geoip
        if ep_geo.enabled == false then
            return result
        end
        if ep_geo.blocked_countries then
            config.blocked_countries = ep_geo.blocked_countries
        end
        if ep_geo.allowed_countries then
            config.allowed_countries = ep_geo.allowed_countries
        end
    end

    -- Lookup country
    local country_info = _M.lookup_country(ip)
    if country_info then
        result.geo.country_code = country_info.country_code
        result.geo.country_name = country_info.country_name

        local cc = country_info.country_code

        -- Check blocked countries
        if cc and config.blocked_countries and #config.blocked_countries > 0 then
            for _, blocked_cc in ipairs(config.blocked_countries) do
                if cc == blocked_cc then
                    result.blocked = true
                    result.reason = "blocked_country"
                    table.insert(result.flags, "geo:blocked_country:" .. cc)
                    return result
                end
            end
        end

        -- Check allowed countries (whitelist mode)
        if cc and config.allowed_countries and #config.allowed_countries > 0 then
            local allowed = false
            for _, allowed_cc in ipairs(config.allowed_countries) do
                if cc == allowed_cc then
                    allowed = true
                    break
                end
            end
            if not allowed then
                result.blocked = true
                result.reason = "country_not_allowed"
                table.insert(result.flags, "geo:country_not_allowed:" .. cc)
                return result
            end
        end

        -- Check flagged countries (score addition)
        if cc and config.flagged_countries and #config.flagged_countries > 0 then
            for _, flagged_cc in ipairs(config.flagged_countries) do
                if cc == flagged_cc then
                    result.score = result.score + (config.flagged_country_score or 15)
                    table.insert(result.flags, "geo:flagged_country:" .. cc)
                    break
                end
            end
        end
    end

    -- Lookup ASN
    local asn_info = _M.lookup_asn(ip)
    if asn_info and asn_info.asn then
        result.geo.asn = asn_info.asn
        result.geo.asn_org = asn_info.org

        local asn = asn_info.asn

        -- Check blocked ASNs
        if config.blocked_asns and #config.blocked_asns > 0 then
            for _, blocked_asn in ipairs(config.blocked_asns) do
                if asn == blocked_asn then
                    result.blocked = true
                    result.reason = "blocked_asn"
                    table.insert(result.flags, "geo:blocked_asn:" .. asn)
                    return result
                end
            end
        end

        -- Check flagged ASNs
        if config.flagged_asns and #config.flagged_asns > 0 then
            for _, flagged_asn in ipairs(config.flagged_asns) do
                if asn == flagged_asn then
                    result.score = result.score + (config.flagged_asn_score or 20)
                    table.insert(result.flags, "geo:flagged_asn:" .. asn)
                    break
                end
            end
        end

        -- Check datacenter ASN
        local is_dc, dc_provider = _M.is_datacenter(asn)
        if is_dc then
            result.geo.is_datacenter = true
            result.geo.datacenter_provider = dc_provider

            if config.block_datacenters then
                result.blocked = true
                result.reason = "datacenter_ip"
                table.insert(result.flags, "geo:datacenter:" .. (dc_provider or asn))
                return result
            elseif config.flag_datacenters then
                result.score = result.score + (config.datacenter_score or 25)
                table.insert(result.flags, "geo:datacenter:" .. (dc_provider or asn))
            end
        end
    end

    return result
end

-- Reload databases (for config changes)
function _M.reload()
    databases_initialized = false
    country_db_available = false
    asn_db_available = false
    init_attempted = false
    config_cache = nil
    config_cache_time = 0
    return init_databases()
end

-- Get status for admin API
function _M.get_status()
    local config = _M.get_config()
    local dc_count = 0
    if config.datacenter_asns then
        for _ in pairs(config.datacenter_asns) do
            dc_count = dc_count + 1
        end
    end

    -- Try to init if not already done
    if not init_attempted then
        init_databases()
    end

    return {
        enabled = config.enabled,
        mmdb_available = mmdb_available,
        country_db_loaded = country_db_available,
        asn_db_loaded = asn_db_available,
        country_db_path = config.country_db_path,
        asn_db_path = config.asn_db_path,
        datacenter_asns_count = dc_count,
    }
end

-- Helper to ensure arrays serialize as JSON arrays
local function ensure_array(tbl)
    if not tbl or type(tbl) ~= "table" then
        return setmetatable({}, cjson.array_mt)
    end
    if #tbl == 0 and next(tbl) == nil then
        return setmetatable({}, cjson.array_mt)
    end
    return tbl
end

-- Get JSON-safe config for admin API
-- Converts sparse tables (like datacenter_asns) to array format
function _M.get_config_for_api()
    local config = _M.get_config()

    -- Convert datacenter_asns from {[asn]=name} to [{asn=num, name=str}]
    local dc_asns_list = {}
    if config.datacenter_asns then
        for asn, name in pairs(config.datacenter_asns) do
            table.insert(dc_asns_list, { asn = asn, name = name })
        end
    end
    if #dc_asns_list == 0 then
        dc_asns_list = setmetatable({}, cjson.array_mt)
    end

    return {
        enabled = config.enabled,
        country_db_path = config.country_db_path,
        asn_db_path = config.asn_db_path,
        default_action = config.default_action,
        blocked_countries = ensure_array(config.blocked_countries),
        allowed_countries = ensure_array(config.allowed_countries),
        flagged_countries = ensure_array(config.flagged_countries),
        flagged_country_score = config.flagged_country_score,
        blocked_asns = ensure_array(config.blocked_asns),
        flagged_asns = ensure_array(config.flagged_asns),
        flagged_asn_score = config.flagged_asn_score,
        datacenter_asns = dc_asns_list,
        block_datacenters = config.block_datacenters,
        flag_datacenters = config.flag_datacenters,
        datacenter_score = config.datacenter_score,
    }
end

return _M
