-- POST body round-trip (route: /lua/tests/body.lua).
-- Response = "len=<n>\n" + exact request body bytes.
ngx.header["Content-Type"] = "application/octet-stream"
ngx.req.read_body()
local b = ngx.req.get_body_data()
if b == nil then
    b = ""
end
ngx.say("len=" .. tostring(#b))
ngx.print(b)
