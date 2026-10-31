-- Normal (non-looping) coroutine semantics must be preserved by the guards:
-- create/resume across yields, and wrap returning yielded/returned values.
local co = coroutine.create(function(a)
    local b = coroutine.yield(a + 1)
    return b + 10
end)
local ok1, v1 = coroutine.resume(co, 1)
local ok2, v2 = coroutine.resume(co, 5)
ngx.say("create=" .. tostring(ok1) .. "," .. tostring(v1) .. ","
        .. tostring(ok2) .. "," .. tostring(v2))

local f = coroutine.wrap(function(a)
    local b = coroutine.yield(a * 2)
    return b * 3
end)
local w1 = f(4)
local w2 = f(7)
ngx.say("wrap=" .. tostring(w1) .. "," .. tostring(w2))
