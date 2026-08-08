--[[
    The decision log exists to answer "why was this blocked?", so the properties
    that matter are the ones that keep it answerable and bounded:

      * It must not record everything. A busy site posting valid forms would
        otherwise fill the buffer with records nobody will look up, and evict the
        ones somebody will.

      * The trace must stay small without dropping the entries that explain the
        verdict. A profile with thirty nodes mostly reports zeros; those are
        noise, and keeping them crowds out the mechanism that actually fired.
]]
local helper = require "spec_helper"

describe("decision_recorder", function()
    local recorder

    local function fake_redis()
        local calls = { lpush = {}, hincrby = {}, ltrim = 0, expire = 0 }
        return {
            calls = calls,
            lpush   = function(_, _, v) table.insert(calls.lpush, v); return 1 end,
            hincrby = function(_, k, f, n)
                calls.hincrby[k .. "/" .. f] = (calls.hincrby[k .. "/" .. f] or 0) + n
                return 1
            end,
            ltrim  = function() calls.ltrim = calls.ltrim + 1; return true end,
            expire = function() calls.expire = calls.expire + 1; return true end,
        }
    end

    local function a_decision(over)
        local d = {
            request_id = "req-1", vhost_id = "site", endpoint_id = "contact",
            client_ip = "203.0.113.10", host = "example.com", path = "/submit",
            method = "POST", action = "blocked", status = 403, score = 40,
            flags = { "kw:viagra" },
        }
        for k, v in pairs(over or {}) do d[k] = v end
        return d
    end

    before_each(function()
        helper.install_ngx()
        helper.stub_external_modules()
        package.loaded["decision_recorder"] = nil
        package.loaded["decision_buffer"] = nil
        recorder = require "decision_recorder"
        recorder._reset_config()
    end)

    describe("what is worth keeping", function()
        it("records anything that was acted on", function()
            assert.is_true(recorder.should_record("blocked", 0))
            assert.is_true(recorder.should_record("challenged", 0))
            assert.is_true(recorder.should_record("tarpit", 0))
            assert.is_true(recorder.should_record("would_block", 0))
        end)

        it("skips a clean allowed request", function()
            -- The common case on a healthy site. Recording it would evict the
            -- decisions somebody actually needs to look up.
            assert.is_false(recorder.should_record("allowed", 0))
        end)

        it("keeps an allowed request that scored, so a near-miss is explicable", function()
            assert.is_true(recorder.should_record("allowed", 5))
        end)
    end)

    describe("recording", function()
        it("buffers a decision without touching Redis", function()
            assert.is_true(recorder.record(a_decision()))
            assert.equals(1, recorder.buffer_depth())
        end)

        it("ignores anything that is not a decision table", function()
            assert.is_false(recorder.record(nil))
            assert.is_false(recorder.record("not a table"))
            assert.equals(0, recorder.buffer_depth())
        end)

        it("flushes to Redis and counts by action", function()
            recorder.record(a_decision())
            recorder.record(a_decision({ action = "allowed", score = 10 }))
            local red = fake_redis()
            assert.equals(2, recorder.flush(red))
            assert.equals(2, #red.calls.lpush)
            assert.equals(1, red.calls.hincrby["waf:decisions:stats/action:blocked"])
            assert.equals(1, red.calls.hincrby["waf:decisions:stats/action:allowed"])
            assert.equals(2, red.calls.hincrby["waf:decisions:stats/total"])
        end)

        it("clips a hostile path so one request cannot bloat the log", function()
            recorder.record(a_decision({ path = string.rep("A", 5000) }))
            local red = fake_redis()
            recorder.flush(red)
            assert.is_true(#red.calls.lpush[1] < 2000)
        end)
    end)

    describe("empty lists are omitted, not encoded as objects", function()
        -- cjson encodes an empty Lua table as {}, not []. The UI writes
        -- `flags ?? []`, which does not catch {} -- it is neither null nor
        -- undefined -- so .slice() on it is undefined and the page crashes.
        -- Omitting the field is what keeps the optional-array contract true.
        local function stored(decision)
            recorder.record(decision)
            local red = fake_redis()
            recorder.flush(red)
            return red.calls.lpush[1]
        end

        it("omits an empty flags list rather than storing {}", function()
            local raw = stored(a_decision({ flags = {} }))
            assert.is_nil(raw:find('"flags":{}', 1, true),
                "an empty flags list must not be stored as a JSON object")
            local cjson = require "cjson.safe"
            assert.is_nil(cjson.decode(raw).flags)
        end)

        it("omits an empty blocked_by list", function()
            local raw = stored(a_decision({ blocked_by = {} }))
            assert.is_nil(raw:find('"blocked_by":{}', 1, true))
        end)

        it("omits a trace with nothing significant in it", function()
            local raw = stored(a_decision({
                trace = { { node = "n1", defense = "honeypot", score = 0 } },
            }))
            assert.is_nil(raw:find('"trace":{}', 1, true))
            local cjson = require "cjson.safe"
            assert.is_nil(cjson.decode(raw).trace)
        end)

        it("still encodes a populated list as an array", function()
            local raw = stored(a_decision({ flags = { "kw:viagra" } }))
            assert.is_not_nil(raw:find('"flags":["kw:viagra"]', 1, true))
        end)
    end)

    describe("trace compaction", function()
        local function traced(trace)
            recorder.record(a_decision({ trace = trace }))
            local red = fake_redis()
            recorder.flush(red)
            local cjson = require "cjson.safe"
            return cjson.decode(red.calls.lpush[1]).trace
        end

        it("drops nodes that contributed nothing", function()
            local kept = traced({
                { node = "n1", defense = "honeypot",       score = 0 },
                { node = "n2", defense = "keyword_filter", score = 30, flags = { "kw:viagra" } },
                { node = "n3", defense = "geoip",          score = 0 },
            })
            assert.equals(1, #kept)
            assert.equals("keyword_filter", kept[1].defense)
        end)

        it("keeps a node that blocked without scoring", function()
            -- result_blocked carries score 0, so a score-only filter would throw
            -- away the very node that produced the verdict.
            local kept = traced({ { node = "n1", defense = "keyword_filter", score = 0, blocked = true } })
            assert.equals(1, #kept)
            assert.is_true(kept[1].blocked)
        end)

        it("keeps a node whose detections were suppressed", function()
            -- "Fired but suppressed" and "never fired" look identical without
            -- this, and they are the two different answers to "why did this get
            -- through?".
            local kept = traced({
                { node = "n1", defense = "keyword_filter", score = 0, suppressed = { "kw:viagra" } },
            })
            assert.equals(1, #kept)
            assert.same({ "kw:viagra" }, kept[1].suppressed)
        end)

        it("caps a runaway trace", function()
            local big = {}
            for i = 1, 100 do
                big[i] = { node = "n" .. i, defense = "d", score = 1, flags = { "f" } }
            end
            assert.is_true(#traced(big) <= 20)
        end)

        it("survives a malformed trace rather than erroring", function()
            local kept = traced({ 42, "nonsense", { node = "n", defense = "d", score = 5 } })
            assert.equals(1, #kept)
        end)
    end)
end)
