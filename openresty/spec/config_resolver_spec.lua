--[[
    config_resolver builds the resolved endpoint config from an explicit
    allowlist of keys. Anything not named there is silently dropped, and the
    request path then cannot see it. Three shipped features were inert for
    exactly this reason: defense_lines, fields.honeypot and patterns.enabled.

    These are regression tests for that, plus the merge semantics the resolver
    is actually responsible for.
]]
local helper = require "spec_helper"

describe("config_resolver", function()
    local config_resolver

    before_each(function()
        helper.install_ngx()
        helper.stub_external_modules()
        package.loaded["config_resolver"] = nil
        package.loaded["waf_config"] = nil
        config_resolver = require "config_resolver"
    end)

    local function endpoint(overrides)
        local cfg = {
            id = "spec-endpoint",
            enabled = true,
            mode = "blocking",
            matching = { paths = { "/spec" }, methods = { "POST" } },
        }
        for k, v in pairs(overrides or {}) do cfg[k] = v end
        return cfg
    end

    describe("key preservation", function()
        -- Each of these was a real defect: the key existed in the stored config,
        -- was accepted by the API, and vanished during resolution.
        it("preserves defense_lines", function()
            local lines = { { profile_id = "high-value", enabled = true, signature_ids = { "sig" } } }
            local resolved = config_resolver.resolve(endpoint({ defense_lines = lines }))
            assert.is_table(resolved.defense_lines)
            assert.equals("high-value", resolved.defense_lines[1].profile_id)
        end)

        it("preserves fields.honeypot", function()
            local resolved = config_resolver.resolve(endpoint({
                fields = { honeypot = { "website", "url" } },
            }))
            assert.same({ "website", "url" }, resolved.fields.honeypot)
        end)

        it("preserves patterns.enabled", function()
            local resolved = config_resolver.resolve(endpoint({
                patterns = { enabled = true },
            }))
            assert.is_true(resolved.patterns.enabled)
        end)

        it("preserves the security block that carries honeypot action and score", function()
            local resolved = config_resolver.resolve(endpoint({
                security = { honeypot_action = "block", honeypot_score = 100 },
            }))
            assert.equals("block", resolved.security.honeypot_action)
            assert.equals(100, resolved.security.honeypot_score)
        end)

        it("preserves defense_profiles attachment", function()
            local attachment = { enabled = true, profiles = { { id = "legacy" } } }
            local resolved = config_resolver.resolve(endpoint({ defense_profiles = attachment }))
            assert.is_table(resolved.defense_profiles)
        end)
    end)

    describe("pattern scanning defaults", function()
        it("is on when the endpoint says nothing, so the advertised link and script checks run", function()
            local resolved = config_resolver.resolve(endpoint())
            assert.is_true(resolved.patterns.enabled)
        end)

        it("is on when there is no endpoint config at all", function()
            local resolved = config_resolver.resolve(nil)
            assert.is_true(resolved.patterns.enabled)
        end)

        it("can still be switched off explicitly", function()
            local resolved = config_resolver.resolve(endpoint({ patterns = { enabled = false } }))
            assert.is_false(resolved.patterns.enabled)
        end)
    end)

    describe("mode", function()
        it("defaults to blocking when unset", function()
            local cfg = endpoint()
            cfg.mode = nil
            assert.equals("blocking", config_resolver.resolve(cfg).mode)
        end)

        it("carries the configured mode through", function()
            assert.equals("monitoring", config_resolver.resolve(endpoint({ mode = "monitoring" })).mode)
        end)
    end)

    describe("field name compatibility", function()
        -- The resolver accepts a canonical and a legacy spelling for these.
        it("accepts fields.expected and the legacy expected_fields", function()
            local canonical = config_resolver.resolve(endpoint({ fields = { expected = { "a" } } }))
            local legacy = config_resolver.resolve(endpoint({ fields = { expected_fields = { "a" } } }))
            assert.same({ "a" }, canonical.fields.expected)
            assert.same({ "a" }, legacy.fields.expected)
        end)

        it("merges endpoint ignore fields on top of the defaults rather than replacing them", function()
            local resolved = config_resolver.resolve(endpoint({ fields = { ignore = { "my_field" } } }))
            local found_default, found_custom = false, false
            for _, f in ipairs(resolved.fields.ignore) do
                if f == "_csrf" then found_default = true end
                if f == "my_field" then found_custom = true end
            end
            assert.is_true(found_default, "default ignore fields should survive")
            assert.is_true(found_custom, "endpoint ignore fields should be added")
        end)
    end)
end)
