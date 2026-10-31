-- Response-body bomb: ngx.say accumulates in a C buffer; cap is 64MiB.
local q = ngx.var.query_string or ""
local mb = tonumber(string.match(q, "mb=(%d+)")) or 1
local chunk = string.rep("y", 1024 * 1024)
for i = 1, mb do
    ngx.say(chunk)
end
