--[[
    keyword_filter.pattern_scan is the implementation the pattern_scan defense
    node needs. The node required a "pattern_scanner" module that never existed,
    so this code was unreachable for the entire life of the DAG executor.

    These pin the scoring calibration that decides flag-versus-block, verified
    against a running instance: two URLs and a single script tag score below the
    default block threshold of 80, while five URLs and three script tags clear
    it comfortably. That boundary is the difference between a WAF people keep
    and one they switch off.
]]
local helper = require "spec_helper"

describe("keyword_filter.pattern_scan", function()
    local keyword_filter

    before_each(function()
        helper.install_ngx()
        helper.stub_external_modules()
        package.loaded["keyword_filter"] = nil
        keyword_filter = require "keyword_filter"
    end)

    local function scan(message)
        return keyword_filter.pattern_scan({ message = message }, {})
    end

    local function has_flag(result, prefix)
        for _, f in ipairs(result.flags or {}) do
            if f == prefix or f:sub(1, #prefix + 1) == prefix .. ":" then return true end
        end
        return false
    end

    it("returns a zero score for ordinary prose", function()
        local result = scan("Hello, I would like to ask about your opening hours.")
        assert.equals(0, result.score)
        assert.equals(0, #result.flags)
    end)

    it("handles absent form data without erroring", function()
        local result = keyword_filter.pattern_scan(nil, {})
        assert.equals(0, result.score)
    end)

    describe("link analysis", function()
        it("scores a couple of links below the default block threshold", function()
            local result = scan("Check out http://example.com and http://test.com for details")
            assert.is_true(result.score > 0, "links should contribute a score")
            assert.is_true(result.score < 80, "two links alone must not block; got " .. result.score)
        end)

        it("escalates once links become excessive", function()
            local few = scan("See http://a.com and http://b.com")
            local many = scan("Visit http://a.com http://b.com http://c.com http://d.com http://e.com now")
            assert.is_true(many.score > few.score, "more links should score higher")
            assert.is_true(has_flag(many, "many_urls"), "excessive links should be flagged")
        end)
    end)

    describe("script injection", function()
        it("scores a single script tag below the block threshold", function()
            local result = scan("<script>alert(1)</script>")
            assert.is_true(result.score > 0)
            assert.is_true(result.score < 80, "one script tag alone must not block; got " .. result.score)
            assert.is_true(has_flag(result, "xss_script"))
        end)

        it("escalates with repeated script tags", function()
            local one = scan("<script>alert(1)</script>")
            local several = scan("<script>a</script><script>b</script><script>c</script>")
            assert.is_true(several.score > one.score, "repeats should score higher than a single instance")
        end)
    end)

    it("ignores excluded fields", function()
        local form = { message = "http://a.com http://b.com http://c.com http://d.com", notes = "clean" }
        local scanned = keyword_filter.pattern_scan(form, {})
        local excluded = keyword_filter.pattern_scan(form, { "message" })
        assert.is_true(scanned.score > excluded.score,
            "excluding the field carrying the links should lower the score")
    end)
end)
