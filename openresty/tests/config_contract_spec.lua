--[[
    Config contract check
    =====================
    Three shipped features were silently inert because a defense mechanism read a
    config shape that config_resolver never produces:

      defense_lines   dropped by resolve()'s explicit key allowlist
      honeypot        read config.honeypot.*, resolver emits fields.honeypot
                      and security.honeypot_*
      pattern_scan    requires a pattern_scanner module that does not exist

    Each failed the same way: no error, no log, just a score of 0 forever. Unit
    tests of the mechanisms alone would not have caught any of them, because each
    mechanism is self-consistent -- the defect is in the seam between the resolver
    and the mechanism.

    This asserts that seam: configure a feature, resolve the config the way the
    request path does, invoke the mechanism, and require that it does not report
    itself as skipped. A mechanism that cannot see configuration that is present
    is the bug we are guarding against.
]]

package.path = "/etc/nginx/lua/?.lua;/usr/local/openresty/lualib/?.lua;" .. package.path
package.cpath = "/usr/local/openresty/lualib/?.so;" .. package.cpath

-- Minimal ngx surface. Mechanisms only need logging, time and shared dicts here.
local function new_dict()
    local store = {}
    return {
        get = function(_, k) return store[k] end,
        set = function(_, k, v) store[k] = v; return true end,
        incr = function(_, k, n, init) store[k] = (store[k] or init or 0) + n; return store[k] end,
        delete = function(_, k) store[k] = nil end,
        get_keys = function() return {} end,
    }
end

_G.ngx = {
    shared = setmetatable({}, {__index = function(t, k) rawset(t, k, new_dict()); return rawget(t, k) end}),
    log = function() end,
    ERR = 1, WARN = 2, INFO = 3, DEBUG = 4, NOTICE = 5,
    time = function() return 1700000000 end,
    now = function() return 1700000000 end,
    null = setmetatable({}, {__tostring = function() return "null" end}),
    var = {}, ctx = {},
    req = { read_body = function() end, get_post_args = function() return {} end,
            get_method = function() return "POST" end, get_headers = function() return {} end },
    re = { match = function() return nil end, find = function() return nil end },
    md5 = function() return "0" end,
    escape_uri = function(v) return v end,
    worker = { id = function() return 0 end },
}

-- Keep the check hermetic: these reach Redis or MaxMind, which is a different
-- concern from whether a mechanism can read its own configuration.
local function fake_redis()
    local r = {}
    setmetatable(r, {__index = function() return function() return ngx.null end end})
    return r
end
package.loaded["resty.redis"] = { new = fake_redis }
-- resty.sha256 binds to OpenSSL symbols exported by the nginx binary, which the
-- luajit CLI does not have. Content hashing is not what this check is about.
package.loaded["resty.sha256"] = {
    new = function()
        return { update = function() return true end, final = function() return "\0" end, reset = function() end }
    end
}
package.loaded["resty.string"] = { to_hex = function() return "00000000" end }
package.loaded["http_utils"] = { request = function() return nil, "stub" end }
package.loaded["trusted_proxies"] = { get_client_ip = function() return "203.0.113.10" end }

local config_resolver = require "config_resolver"
local executor = require "defense_profile_executor"
require "defense_mechanisms"

-- An endpoint configuration that switches every config-driven feature ON, in the
-- canonical shape the Admin API stores.
local ENDPOINT_CONFIG = {
    id = "contract-probe",
    enabled = true,
    mode = "blocking",
    matching = { paths = {"/probe"}, methods = {"POST"} },
    fields = {
        honeypot = {"website", "url"},
        expected = {"name", "email", "message"},
        required = {"email"},
    },
    security = {
        honeypot_action = "block",
        honeypot_score = 100,
        check_disposable_email = true,
        disposable_email_action = "flag",
        disposable_email_score = 40,
        check_field_anomalies = true,
    },
    patterns = { enabled = true, inherit_global = true },
    keywords = { inherit_global = true, additional_blocked = {"blockedword"} },
    rate_limiting = { enabled = true, requests_per_minute = 60 },
    defense_lines = {
        { profile_id = "high-value", enabled = true, signature_ids = {"builtin_wordpress_login"} },
    },
}

-- Form data crafted so a working mechanism has something to find.
local FORM_DATA = {
    name = "Test User",
    email = "someone@mailinator.com",
    message = "hello blockedword <script>alert(1)</script> http://a.com http://b.com",
    website = "http://spam.example",
    unexpected_field = "surprise",
}

--[[ Mechanisms whose skipping is an environment fact, not a contract defect.
     They are still executed -- a crash is a failure -- but a skip is reported
     rather than failed. ]]
local ENVIRONMENT_DEPENDENT = {
    geoip = "needs MaxMind databases",
    ip_reputation = "needs Redis and/or an external provider",
    behavioral = "needs Redis",
    fingerprint = "needs fingerprint profiles from Redis",
    rate_limiter = "needs Redis counters",
    timing_token = "needs a signed cookie from a prior GET",
    ip_allowlist = "allowlist is empty by default",
    content_hash = "needs Redis for duplicate counts",
    header_consistency = "depends on request headers, not endpoint config",
}

local resolved = config_resolver.resolve(ENDPOINT_CONFIG)

local request_context = {
    endpoint_id = "contract-probe",
    vhost_id = "_default",
    endpoint_config = resolved,
    -- waf_handler passes the full resolution context; several mechanisms read
    -- their config through vhost_resolver accessors that expect it.
    context = { endpoint = resolved, vhost_config = {}, vhost = { vhost_id = "_default" } },
    form_data = FORM_DATA,
    client_ip = "203.0.113.10",
    user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    accept_language = "en-GB,en;q=0.9",
    accept_encoding = "gzip, deflate, br",
}

local failures, skipped, ok_count = {}, {}, 0

-- 1. Keys the Admin API stores must survive resolution. resolve() builds its
--    result from an explicit allowlist, so anything absent is silently dropped.
local MUST_SURVIVE = {
    { path = "defense_lines", get = function(c) return c.defense_lines end },
    { path = "fields.honeypot", get = function(c) return c.fields and c.fields.honeypot end },
    { path = "security.honeypot_action", get = function(c) return c.security and c.security.honeypot_action end },
    { path = "patterns.enabled", get = function(c) return c.patterns and c.patterns.enabled end },
    { path = "rate_limiting.enabled", get = function(c) return c.rate_limiting and c.rate_limiting.enabled end },
    { path = "fields.expected", get = function(c) return c.fields and c.fields.expected end },
}

for _, entry in ipairs(MUST_SURVIVE) do
    if entry.get(resolved) == nil then
        table.insert(failures, string.format(
            "config_resolver.resolve() dropped %q -- the request path can never see it", entry.path))
    else
        ok_count = ok_count + 1
    end
end

-- 2. Every registered mechanism must run, and must not claim to be unconfigured
--    when its configuration is present.
for _, name in ipairs(executor.list_defenses()) do
    local mechanism = executor.get_defense(name)
    local ran, result = pcall(mechanism, request_context, {})

    if not ran then
        table.insert(failures, string.format("mechanism %q raised: %s", name, tostring(result)))
    elseif type(result) ~= "table" then
        table.insert(failures, string.format("mechanism %q returned %s, expected a result table",
            name, type(result)))
    elseif result.details and result.details.skipped then
        local reason = tostring(result.details.reason or "unspecified")
        if ENVIRONMENT_DEPENDENT[name] then
            table.insert(skipped, string.format("%s (%s) -- %s", name, reason, ENVIRONMENT_DEPENDENT[name]))
        else
            table.insert(failures, string.format(
                "mechanism %q skipped with reason %q although its configuration is present",
                name, reason))
        end
    else
        ok_count = ok_count + 1
    end
end

print("Config contract check")
print("=====================")
print(string.format("  checks passed : %d", ok_count))
for _, s in ipairs(skipped) do print("  skipped       : " .. s) end
for _, f in ipairs(failures) do print("  FAIL          : " .. f) end

if #failures > 0 then
    print(string.format("\n%d contract violation(s).", #failures))
    os.exit(1)
end
print("\nAll config contracts hold.")
