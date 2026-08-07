--[[
    rbac.check_permission default-denies any route with no mapping, so a handler
    that is registered but unmapped returns 403 for every role including admin,
    with no startup diagnostic. That is how the Slack endpoints shipped
    unreachable, and how five more routes were found later.

    get_endpoint_permission is pure table and pattern matching, so it tests
    directly.
]]
local helper = require "spec_helper"

describe("rbac", function()
    local rbac

    before_each(function()
        helper.install_ngx()
        helper.stub_external_modules()
        package.loaded["rbac"] = nil
        rbac = require "rbac"
    end)

    describe("get_endpoint_permission", function()
        it("maps a plain route", function()
            local perm = rbac.get_endpoint_permission("GET", "/status")
            assert.is_table(perm)
            assert.equals("status", perm.resource)
            assert.equals("read", perm.action)
        end)

        it("returns nil for an unmapped route, which is what makes it default-deny", function()
            assert.is_nil(rbac.get_endpoint_permission("GET", "/no/such/route"))
        end)

        it("maps parametric vhost routes", function()
            local perm, id, kind = rbac.get_endpoint_permission("GET", "/vhosts/example-com")
            assert.is_table(perm)
            assert.equals("example-com", id)
            assert.equals("vhost", kind)
        end)

        it("maps parametric endpoint routes", function()
            local perm, id, kind = rbac.get_endpoint_permission("DELETE", "/endpoints/contact-form")
            assert.is_table(perm)
            assert.equals("contact-form", id)
            assert.equals("endpoint", kind)
        end)

        -- These five were registered handlers with no mapping, so admin got 403.
        it("maps GET /timing/vhosts", function()
            assert.is_table(rbac.get_endpoint_permission("GET", "/timing/vhosts"))
        end)

        it("maps the defense-profile action sub-routes", function()
            for method, action in pairs({ POST = "clone", GET = "resolved" }) do
                local perm = rbac.get_endpoint_permission(method, "/defense-profiles/my-profile/" .. action)
                assert.is_table(perm, method .. " /defense-profiles/:id/" .. action .. " should be mapped")
                assert.equals("defense_profiles", perm.resource)
            end
            for _, action in ipairs({ "enable", "disable" }) do
                local perm = rbac.get_endpoint_permission("POST", "/defense-profiles/my-profile/" .. action)
                assert.is_table(perm, "POST /defense-profiles/:id/" .. action .. " should be mapped")
            end
        end)

        it("still maps a defense profile without an action segment", function()
            local perm, id = rbac.get_endpoint_permission("PUT", "/defense-profiles/my-profile")
            assert.is_table(perm)
            assert.equals("my-profile", id)
        end)

        it("does not treat collection routes as identifiers", function()
            -- /defense-profiles/builtins is a collection, not a profile called "builtins"
            local perm, id = rbac.get_endpoint_permission("GET", "/defense-profiles/builtins")
            if perm then assert.not_equals("builtins", id) end
        end)

        it("maps the slack routes granted to read-only roles", function()
            assert.is_table(rbac.get_endpoint_permission("GET", "/slack/config"))
            assert.equals("update", rbac.get_endpoint_permission("PUT", "/slack/config").action)
        end)
    end)

    describe("audit_route_coverage", function()
        it("reports a registered route with no permission mapping", function()
            local missing = rbac.audit_route_coverage({ "GET:/definitely-not-mapped" })
            assert.equals(1, missing)
        end)

        it("accepts routes that are mapped", function()
            assert.equals(0, rbac.audit_route_coverage({ "GET:/status", "GET:/slack/config" }))
        end)

        it("resolves :id placeholders rather than reporting the template as unmapped", function()
            assert.equals(0, rbac.audit_route_coverage({ "GET:/vhosts/:id", "PUT:/defense-profiles/:id" }))
        end)

        it("does not flag routes that are deliberately public", function()
            assert.equals(0, rbac.audit_route_coverage({ "GET:/auth/providers" }))
        end)
    end)

    describe("role permissions", function()
        it("grants admin the slack resource", function()
            assert.is_true(rbac.role_has_permission("admin", "slack", "update"))
        end)

        it("does not grant viewer write access to slack", function()
            assert.is_false(rbac.role_has_permission("viewer", "slack", "update"))
        end)

        it("grants viewer read access to slack", function()
            assert.is_true(rbac.role_has_permission("viewer", "slack", "read"))
        end)
    end)
end)
