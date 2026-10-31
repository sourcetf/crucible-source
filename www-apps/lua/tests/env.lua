-- Per-request header/env echo (route: /lua/tests/env.lua).
-- HDR is the caller's unique x-crucible-env-probe; a response containing a
-- different request's HDR proves cross-request state bleed.
local h = ngx.req.get_headers()
ngx.header["Content-Type"] = "text/plain"
ngx.say("HDR=" .. tostring(h["x-crucible-env-probe"]))
ngx.say("WINDOWMARK=" .. tostring(os.getenv("WINDOWMARK")))
ngx.say("SECRET_A=" .. tostring(os.getenv("SECRET_A")))
ngx.say("SECRET_B=" .. tostring(os.getenv("SECRET_B")))
ngx.say("BASE_MARK=" .. tostring(os.getenv("BASE_MARK")))
ngx.say("EMPTY_VALUE=" .. tostring(os.getenv("EMPTY_VALUE")))
ngx.say("URI=" .. tostring(ngx.var.uri))
