--[[
    Suppression is a safety control that makes the WAF do less, so its failure
    modes run in the dangerous direction. Two properties carry the weight:

      * A suppression must not reach beyond its scope. An entry added for one
        vhost silently applying to another is a hole opened by accident.

      * Suppressing one detection must not clear a node that also fired for a
        reason nobody suppressed. Mechanisms report one aggregate score for all
        their flags, so there is no per-flag score to subtract -- which means the
        only safe rule is that a node keeps its verdict while any flag survives.
]]
local helper = require "spec_helper"

describe("suppressions", function()
    local suppressions

    local function install(entries)
        local cjson = require "cjson.safe"
        ngx.shared.suppression_cache:set("suppressions", cjson.encode(entries or {}))
    end

    before_each(function()
        helper.install_ngx()
        helper.stub_external_modules()
        package.loaded["suppressions"] = nil
        suppressions = require "suppressions"
        install({})
    end)

    describe("pattern matching", function()
        it("matches an exact flag", function()
            assert.is_true(suppressions.matches("kw:viagra", "kw:viagra"))
            assert.is_false(suppressions.matches("kw:viagra", "kw:casino"))
        end)

        it("matches a family with a trailing star", function()
            assert.is_true(suppressions.matches("kw:viagra", "kw:*"))
            assert.is_true(suppressions.matches("kw:casino", "kw:*"))
            assert.is_false(suppressions.matches("fp_flag:bot", "kw:*"))
        end)

        it("treats regex metacharacters as literals", function()
            -- An operator typing a rule name should not have to know that "-" and
            -- "." mean something. A flag containing them must match itself, and a
            -- pattern using them must not match anything else.
            assert.is_true(suppressions.matches("kw:crypto-investment", "kw:crypto-investment"))
            assert.is_false(suppressions.matches("kw:viagra", "kw:."))
            assert.is_false(suppressions.matches("kwXviagra", "kw.viagra"))
        end)

        it("rejects non-string input rather than erroring", function()
            assert.is_false(suppressions.matches(nil, "kw:*"))
            assert.is_false(suppressions.matches("kw:viagra", nil))
            assert.is_false(suppressions.matches(42, "kw:*"))
        end)
    end)

    describe("scoping", function()
        it("applies a global suppression everywhere", function()
            install({ { flag = "kw:viagra", scope_type = "global" } })
            local patterns = suppressions.active_patterns("any-vhost", "any-endpoint")
            assert.same({ "kw:viagra" }, patterns)
        end)

        it("does not leak a vhost suppression to another vhost", function()
            install({ { flag = "kw:viagra", scope_type = "vhost", scope_id = "pharmacy" } })
            assert.same({ "kw:viagra" }, suppressions.active_patterns("pharmacy", "contact"))
            assert.same({}, suppressions.active_patterns("other-site", "contact"))
        end)

        it("does not leak an endpoint suppression to another endpoint", function()
            install({ { flag = "honeypot:filled", scope_type = "endpoint", scope_id = "signup" } })
            assert.same({ "honeypot:filled" }, suppressions.active_patterns("v", "signup"))
            assert.same({}, suppressions.active_patterns("v", "contact"))
        end)

        it("accumulates scopes rather than the narrower one replacing the broader", function()
            install({
                { flag = "kw:viagra",      scope_type = "global" },
                { flag = "kw:casino",      scope_type = "vhost",    scope_id = "shop" },
                { flag = "honeypot:filled", scope_type = "endpoint", scope_id = "signup" },
            })
            local patterns = suppressions.active_patterns("shop", "signup")
            table.sort(patterns)
            assert.same({ "honeypot:filled", "kw:casino", "kw:viagra" }, patterns)
        end)

        it("ignores an unknown scope type instead of applying it", function()
            install({ { flag = "kw:viagra", scope_type = "everywhere-ish" } })
            assert.same({}, suppressions.active_patterns("v", "e"))
        end)
    end)

    describe("applying to a defense result", function()
        it("neutralises a node whose every flag was suppressed", function()
            install({ { flag = "kw:viagra", scope_type = "global" } })
            local result = { score = 0, blocked = true, block_reason = "keyword_blocked",
                             flags = { "kw:viagra" } }
            local out, removed = suppressions.apply(result, "v", "e")
            assert.is_false(out.blocked)
            assert.equals(0, out.score)
            assert.is_nil(out.block_reason)
            assert.same({ "kw:viagra" }, removed)
        end)

        it("leaves a node that also fired for an unsuppressed reason", function()
            -- The property that stops suppression being a back door: casino was
            -- not suppressed, so the block stands.
            install({ { flag = "kw:viagra", scope_type = "global" } })
            local result = { score = 35, blocked = true, block_reason = "keyword_blocked",
                             flags = { "kw:viagra", "kw:casino" } }
            local out = suppressions.apply(result, "v", "e")
            assert.is_true(out.blocked)
            assert.equals(35, out.score)
            assert.same({ "kw:casino" }, out.flags)
        end)

        it("records what it removed, so a detection never just vanishes", function()
            install({ { flag = "kw:*", scope_type = "global" } })
            local result = { score = 20, blocked = false, flags = { "kw:viagra", "fp_flag:bot" } }
            local out, removed = suppressions.apply(result, "v", "e")
            assert.same({ "kw:viagra" }, removed)
            assert.same({ "kw:viagra" }, out.details.suppressed)
            assert.same({ "fp_flag:bot" }, out.flags)
        end)

        it("is a no-op when nothing matches", function()
            install({ { flag = "kw:viagra", scope_type = "global" } })
            local result = { score = 40, blocked = true, flags = { "fp_flag:bot" } }
            local out, removed = suppressions.apply(result, "v", "e")
            assert.is_true(out.blocked)
            assert.equals(40, out.score)
            assert.is_nil(removed)
        end)

        it("is a no-op when no suppressions are configured", function()
            local result = { score = 40, blocked = true, flags = { "kw:viagra" } }
            local out, removed = suppressions.apply(result, "v", "e")
            assert.is_true(out.blocked)
            assert.is_nil(removed)
        end)

        it("leaves a flagless result alone", function()
            install({ { flag = "kw:*", scope_type = "global" } })
            local result = { score = 50, blocked = true, flags = {} }
            local out = suppressions.apply(result, "v", "e")
            assert.is_true(out.blocked, "a node with no flags has nothing to suppress")
            assert.equals(50, out.score)
        end)

        it("reports when it changed the verdict, and when it merely dropped a flag", function()
            -- The caller logs these differently: a suppression that turns a block
            -- into a pass is the answer to "why did this get through?", while one
            -- that drops a flag from a node that was not blocking is routine.
            install({ { flag = "kw:viagra", scope_type = "global" } })

            local blocked = { score = 0, blocked = true, flags = { "kw:viagra" } }
            local _, _, neutralised = suppressions.apply(blocked, "v", "e")
            assert.is_true(neutralised)

            local scored = { score = 30, blocked = false, flags = { "kw:viagra" } }
            local _, _, scored_neutralised = suppressions.apply(scored, "v", "e")
            assert.is_true(scored_neutralised, "zeroing a contributing score is a changed verdict")

            local harmless = { score = 0, blocked = false, flags = { "kw:viagra" } }
            local _, _, harmless_neutralised = suppressions.apply(harmless, "v", "e")
            assert.is_false(harmless_neutralised, "a node that was not going to block either way")

            local partial = { score = 30, blocked = true, flags = { "kw:viagra", "kw:casino" } }
            install({ { flag = "kw:viagra", scope_type = "global" } })
            local _, _, partial_neutralised = suppressions.apply(partial, "v", "e")
            assert.is_false(partial_neutralised, "casino survived, so the verdict stands")
        end)

        it("picks up a config change immediately despite caching the decode", function()
            -- apply() runs several times per request, so the decode is cached on
            -- the raw blob. A stale suppression is either traffic wrongly blocked
            -- or wrongly allowed, so the cache must turn over the moment
            -- redis_sync writes something new.
            install({ { flag = "kw:viagra", scope_type = "global" } })
            assert.same({ "kw:viagra" }, suppressions.active_patterns("v", "e"))

            install({ { flag = "kw:casino", scope_type = "global" } })
            assert.same({ "kw:casino" }, suppressions.active_patterns("v", "e"),
                "a new blob must not be served from the previous decode")

            install({})
            assert.same({}, suppressions.active_patterns("v", "e"))
        end)

        it("survives junk in the cache rather than failing open or erroring", function()
            ngx.shared.suppression_cache:set("suppressions", "not json at all")
            local result = { score = 40, blocked = true, flags = { "kw:viagra" } }
            local out = suppressions.apply(result, "v", "e")
            assert.is_true(out.blocked, "unreadable config must not suppress anything")
        end)
    end)
end)
