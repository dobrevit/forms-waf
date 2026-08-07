--[[
    The helper's shared-dictionary stub is itself worth testing. A stub more
    permissive than the real ngx.shared.DICT will happily green-light code that
    returns nil in production, which is the opposite of what a test suite is for.
]]
local helper = require "spec_helper"

describe("spec_helper shared dict stub", function()
    local dict

    before_each(function()
        helper.install_ngx()
        dict = ngx.shared.some_dict
    end)

    describe("incr", function()
        it("returns nil, 'not found' for an absent key when no init is given", function()
            local value, err = dict:incr("missing", 1)
            assert.is_nil(value)
            assert.equals("not found", err)
        end)

        it("initialises to init + value when init is given", function()
            assert.equals(1, dict:incr("counter", 1, 0))
            assert.equals(6, dict:incr("from_five", 1, 5))
        end)

        it("increments an existing value", function()
            dict:incr("counter", 1, 0)
            assert.equals(3, dict:incr("counter", 2))
        end)

        it("decrements with a negative value", function()
            dict:incr("counter", 5, 0)
            assert.equals(3, dict:incr("counter", -2))
        end)

        it("returns nil, 'not a number' when the stored value is not numeric", function()
            dict:set("text", "hello")
            local value, err = dict:incr("text", 1, 0)
            assert.is_nil(value)
            assert.equals("not a number", err)
        end)
    end)

    describe("add", function()
        it("stores a value that is not present", function()
            assert.is_true(dict:add("fresh", "value"))
            assert.equals("value", dict:get("fresh"))
        end)

        it("refuses to overwrite and reports why", function()
            dict:add("taken", "first")
            local ok, err = dict:add("taken", "second")
            assert.is_falsy(ok)
            assert.equals("exists", err)
            assert.equals("first", dict:get("taken"))
        end)
    end)

    describe("log capture", function()
        it("records log calls so specs can assert on them", function()
            ngx.log(ngx.ERR, "something ", "broke")
            assert.equals(1, #ngx.logged)
            assert.equals("something broke", ngx.logged[1].message)
            assert.equals(ngx.ERR, ngx.logged[1].level)
        end)
    end)
end)
