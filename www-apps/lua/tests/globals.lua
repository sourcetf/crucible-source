-- Global / package.loaded pollution probe (route: /lua/tests/globals.lua).
-- Each request has its own lua_State, so a value written by request A must
-- never be observable by request B.
local q = ngx.var.query_string or ""
local op = string.match(q, "op=([a-z]+)") or "get"
local token = string.match(q, "token=([A-Za-z0-9_%-]+)") or "none"
if op == "set" then
    _G.leak = token
    package.loaded["crucible_probe_module"] = token
    ngx.say("SET=" .. token)
else
    ngx.say("LEAK=" .. tostring(_G.leak))
    ngx.say("LOADED=" .. tostring(package.loaded["crucible_probe_module"]))
end
