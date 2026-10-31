ngx.say("cowrap-start")
local f = coroutine.wrap(function()
    while true do end
end)
f()
ngx.say("cowrap-done")
