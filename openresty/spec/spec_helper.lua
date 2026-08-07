--[[
    Shared test scaffolding.

    The modules under test run inside OpenResty and reach for ngx, shared
    dictionaries and Redis. Rather than each spec inventing its own stubs, this
    provides one honest minimum: enough ngx surface to load a module and drive
    pure logic, and no more. Anything needing real Redis or MaxMind belongs in
    the integration suite, not here.
]]
local M = {}

local function new_shared_dict()
    local store, ttl = {}, {}
    return {
        get = function(_, k) return store[k] end,
        set = function(_, k, v, exp) store[k] = v; ttl[k] = exp; return true end,
        add = function(_, k, v, exp)
            if store[k] ~= nil then return false, "exists" end  -- matches the real API's falsy + reason
            store[k] = v; ttl[k] = exp; return true
        end,
        -- Mirrors ngx.shared.DICT:incr(key, value, init?, init_ttl?).
        -- The real API is stricter than it looks, and a stub that is more
        -- permissive than production lets a test pass on code that fails live:
        --   absent key, no init      -> nil, "not found"
        --   absent key, with init    -> init + value
        --   existing non-numeric     -> nil, "not a number"
        incr = function(_, k, n, init, init_ttl)
            local current = store[k]
            if current == nil then
                if init == nil then
                    return nil, "not found"
                end
                current = init
                if init_ttl then ttl[k] = init_ttl end
            end
            if type(current) ~= "number" then
                return nil, "not a number"
            end
            store[k] = current + n
            return store[k]
        end,
        delete = function(_, k) store[k] = nil end,
        get_keys = function() local ks = {} for k in pairs(store) do ks[#ks+1] = k end return ks end,
        flush_all = function() store, ttl = {}, {} end,
    }
end

--- Install a minimal ngx global. Call before requiring any module under test.
-- @param opts table|nil  time (number), vars (table of ngx.var)
function M.install_ngx(opts)
    opts = opts or {}
    local now = opts.time or 1700000000

    _G.ngx = {
        shared = setmetatable({}, {
            __index = function(t, k)
                local d = new_shared_dict()
                rawset(t, k, d)
                return d
            end,
        }),
        -- Captured rather than printed, so a spec can assert on what was logged.
        logged = {},
        log = function(level, ...)
            local parts = {}
            for i = 1, select("#", ...) do parts[#parts+1] = tostring((select(i, ...))) end
            table.insert(_G.ngx.logged, { level = level, message = table.concat(parts) })
        end,
        ERR = 1, WARN = 2, NOTICE = 3, INFO = 4, DEBUG = 5,
        time = function() return now end,
        now = function() return now end,
        null = setmetatable({}, { __tostring = function() return "null" end }),
        var = opts.vars or {},
        ctx = {},
        req = {
            read_body = function() end,
            get_post_args = function() return {} end,
            get_method = function() return "POST" end,
            get_headers = function() return {} end,
            set_header = function() end,
        },
        re = { match = function() return nil end, find = function() return nil end },
        timer = { at = function() return true end },
        worker = { id = function() return 0 end },
        md5 = function() return "d41d8cd98f00b204e9800998ecf8427e" end,
        encode_base64 = function(s) return s end,
        decode_base64 = function(s) return s end,
        escape_uri = function(s) return s end,
        unescape_uri = function(s) return s end,
        exit = function() end,
        HTTP_FORBIDDEN = 403, HTTP_BAD_REQUEST = 400,
    }
    return _G.ngx
end

--- Replace modules that would otherwise reach the network or Redis.
function M.stub_external_modules()
    package.loaded["resty.redis"] = {
        new = function()
            local r = {}
            return setmetatable(r, { __index = function() return function() return ngx.null end end })
        end,
    }
    package.loaded["http_utils"] = { request = function() return nil, "stubbed in tests" end }
    package.loaded["trusted_proxies"] = {
        get_client_ip = function() return "203.0.113.10" end,
        is_trusted = function() return false end,
    }
    -- resty.sha256 binds to OpenSSL symbols exported by the nginx binary, which
    -- the standalone interpreter does not have.
    package.loaded["resty.sha256"] = {
        new = function()
            return { update = function() return true end, final = function() return "\0" end, reset = function() end }
        end,
    }
    package.loaded["resty.string"] = { to_hex = function() return "deadbeefdeadbeef" end }
    -- Password hashing binds crypto primitives from the nginx binary. Permission
    -- and matching logic does not exercise it, so stub the surface rather than
    -- reimplement PBKDF2.
    package.loaded["password_utils"] = {
        hash_password = function() return "pbkdf2:100000:73616c74:68617368" end,
        verify_password = function() return true end,
        generate_salt = function() return "73616c74" end,
        needs_upgrade = function() return false end,
        hmac_sha256 = function() return "\0" end,
        secure_compare = function(a, b) return a == b end,
        get_iterations = function() return 100000 end,
    }
end

--- Forget a module so the next require re-runs it against fresh stubs.
function M.reload(name)
    package.loaded[name] = nil
    return require(name)
end

return M
