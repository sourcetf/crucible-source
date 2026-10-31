-- Infinite loop in a coroutine: needs its own count hook (main-thread hook
-- does not run while coroutine.resume() is executing the child lua_State).
ngx.say("co-start")
local co = coroutine.create(function()
    while true do end
end)
local ok, err = coroutine.resume(co)
if not ok then
    error(err)
end
ngx.say("co-done")
