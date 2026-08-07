--[[
    The recorder buffers would-block decisions in a shared dict and a timer
    drains them. Two properties matter more than the rest:

      * The drain is claimed atomically. redis_sync's timer runs on every
        worker, and this box has 24 of them. Reading the tail, draining, then
        writing it back let every worker drain the same slots -- one decision
        became one record per worker, which would have overstated the impact of
        promoting an endpoint by up to 24x. That was a real defect, caught by
        counting records rather than trusting the code.

      * The buffer is bounded and says so. A WAF in monitoring mode on a busy
        site sees everything; silently dropping records would make the diff view
        claim completeness it does not have.
]]
local helper = require "spec_helper"

describe("shadow_recorder", function()
    local recorder

    -- Minimal Redis double that records what would have been written.
    local function fake_redis()
        local calls = { lpush = {}, hincrby = {}, ltrim = 0, expire = 0 }
        return {
            calls = calls,
            lpush = function(_, _, v) table.insert(calls.lpush, v); return 1 end,
            hincrby = function(_, key, field, n)
                calls.hincrby[key .. "/" .. field] = (calls.hincrby[key .. "/" .. field] or 0) + n
                return 1
            end,
            ltrim = function() calls.ltrim = calls.ltrim + 1; return true end,
            expire = function() calls.expire = calls.expire + 1; return true end,
        }
    end

    local function a_decision(overrides)
        local d = {
            vhost_id = "example-com", endpoint_id = "contact",
            client_ip = "203.0.113.9", host = "example.com", path = "/contact",
            method = "POST", score = 85,
            blocked_by = { "keyword_filter" }, flags = { "kw:viagra" },
        }
        for k, v in pairs(overrides or {}) do d[k] = v end
        return d
    end

    before_each(function()
        helper.install_ngx()
        helper.stub_external_modules()
        package.loaded["shadow_recorder"] = nil
        recorder = require "shadow_recorder"
    end)

    it("buffers a decision without touching Redis", function()
        assert.is_true(recorder.record(a_decision()))
        assert.equals(1, recorder.buffer_depth())
    end)

    it("ignores anything that is not a decision table", function()
        assert.is_false(recorder.record(nil))
        assert.is_false(recorder.record("not a table"))
        assert.equals(0, recorder.buffer_depth())
    end)

    it("flushes buffered decisions to Redis and empties the buffer", function()
        for i = 1, 3 do recorder.record(a_decision({ score = 80 + i })) end
        local red = fake_redis()
        assert.equals(3, recorder.flush(red))
        assert.equals(3, #red.calls.lpush)
        assert.equals(0, recorder.buffer_depth())
    end)

    it("does not re-flush what a previous drain already claimed", function()
        -- The defect this guards: a second drain seeing the same slots.
        for i = 1, 4 do recorder.record(a_decision()) end
        local first, second = fake_redis(), fake_redis()
        assert.equals(4, recorder.flush(first))
        assert.equals(0, recorder.flush(second))
        assert.equals(4, #first.calls.lpush)
        assert.equals(0, #second.calls.lpush)
    end)

    it("only one worker drains at a time", function()
        for i = 1, 5 do recorder.record(a_decision()) end
        assert.equals(5, recorder.buffer_depth())
        recorder.flush(fake_redis())
        assert.equals(0, recorder.buffer_depth(),
            "a completed drain must leave nothing for another worker")
    end)

    it("a concurrent drain never pushes the tail past the head", function()
        -- The defect this guards, and it is subtler than the duplicate it
        -- replaced. Claiming a range with incr(TAIL, pending) let a second
        -- worker claim slots the writer had not filled yet, leaving tail > head.
        -- Records written into that gap were then skipped for good: no
        -- duplicates, so the obvious test passed, while the sample silently lost
        -- records -- the one thing a shadow sample must not do.
        for i = 1, 5 do recorder.record(a_decision()) end

        -- Two workers reach flush together. The first holds the drain lock, so
        -- simulate the second arriving before the first has released it by
        -- calling flush again from inside the fake connection's first lpush.
        local second_result
        local red = fake_redis()
        local real_lpush = red.lpush
        local reentered = false
        red.lpush = function(self, ...)
            if not reentered then
                reentered = true
                second_result = recorder.flush(fake_redis())
            end
            return real_lpush(self, ...)
        end

        assert.equals(5, recorder.flush(red))
        assert.equals(0, second_result, "the second worker must drain nothing")
        assert.is_true(reentered, "the concurrent drain did not run; test is not proving anything")

        -- The real assertion: the buffer still works afterwards.
        for i = 1, 3 do recorder.record(a_decision()) end
        assert.equals(3, recorder.buffer_depth(),
            "records written after a concurrent drain must still be visible")
        local after = fake_redis()
        assert.equals(3, recorder.flush(after),
            "records written after a concurrent drain must still be flushed")
    end)

    it("resumes from the last completed slot rather than replaying or skipping", function()
        for i = 1, 6 do recorder.record(a_decision()) end
        -- A drain that dies part-way: fail the connection after 2 records.
        local red = fake_redis()
        local n = 0
        local real_lpush = red.lpush
        red.lpush = function(self, ...)
            n = n + 1
            if n > 2 then error("connection lost") end
            return real_lpush(self, ...)
        end
        pcall(recorder.flush, red)

        -- The 2 that landed must not come back; the other 4 must not be lost.
        local resumed = fake_redis()
        assert.equals(4, recorder.flush(resumed),
            "a resumed drain must pick up exactly the slots that did not complete")
    end)

    it("flushing an empty buffer is a no-op", function()
        local red = fake_redis()
        assert.equals(0, recorder.flush(red))
        assert.equals(0, #red.calls.lpush)
        assert.equals(0, red.calls.ltrim)
    end)

    it("counts each rule that contributed to the decision", function()
        recorder.record(a_decision({ blocked_by = { "keyword_filter", "honeypot" } }))
        local red = fake_redis()
        recorder.flush(red)
        assert.equals(1, red.calls.hincrby["waf:shadow:rules/keyword_filter"])
        assert.equals(1, red.calls.hincrby["waf:shadow:rules/honeypot"])
    end)

    it("aggregates by vhost and endpoint", function()
        recorder.record(a_decision())
        recorder.record(a_decision({ endpoint_id = "signup" }))
        local red = fake_redis()
        recorder.flush(red)
        assert.equals(1, red.calls.hincrby["waf:shadow:endpoints/example-com|contact"])
        assert.equals(1, red.calls.hincrby["waf:shadow:endpoints/example-com|signup"])
    end)

    it("counts detection flags, which are what name the rule to suppress", function()
        recorder.record(a_decision({ flags = { "legacy:kw:viagra", "legacy:fp_flag:bot" } }))
        recorder.record(a_decision({ flags = { "legacy:kw:viagra" } }))
        local red = fake_redis()
        recorder.flush(red)
        -- "legacy" as a rule name tells an operator nothing; the flag does.
        assert.equals(2, red.calls.hincrby["waf:shadow:flags/legacy:kw:viagra"])
        assert.equals(1, red.calls.hincrby["waf:shadow:flags/legacy:fp_flag:bot"])
    end)

    it("clips a flag, since part of it comes from the request", function()
        recorder.record(a_decision({ flags = { "legacy:kw:" .. string.rep("A", 900) } }))
        local red = fake_redis()
        recorder.flush(red)
        for field in pairs(red.calls.hincrby) do
            if field:find("^waf:shadow:flags/") then
                assert.is_true(#field < 300, "an unclipped flag would let one request bloat the hash")
            end
        end
    end)

    it("clips attacker-controlled values so one request cannot bloat storage", function()
        recorder.record(a_decision({ path = string.rep("A", 5000) }))
        local red = fake_redis()
        recorder.flush(red)
        assert.is_true(#red.calls.lpush[1] < 2000,
            "a 5000-character path must not be stored whole")
    end)

    it("drops rather than growing without bound, and counts what it dropped", function()
        for _ = 1, 600 do recorder.record(a_decision()) end   -- cap is 500
        local red = fake_redis()
        recorder.flush(red)
        assert.is_true(red.calls.hincrby["waf:shadow:stats/dropped_total"] > 0,
            "dropped records must be counted so the UI can say it is showing a sample")
    end)
end)
