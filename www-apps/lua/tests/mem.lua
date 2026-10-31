-- Allocation bomb: default per-request Lua heap cap is 32MiB, so ?mb=64 must
-- fail with a clean 500 while the process RSS stays bounded.
local q = ngx.var.query_string or ""
local mb = tonumber(string.match(q, "mb=(%d+)")) or 64
ngx.say("alloc-begin")
local s = string.rep("x", mb * 1024 * 1024)
ngx.say("allocated=" .. tostring(#s))
