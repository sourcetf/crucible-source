-- os.setlocale changes process-global C locale; the engine allows queries but
-- rejects setting. A change must not be observable by another request.
local before = os.setlocale(nil)
local ok, err = pcall(function()
    os.setlocale("C")
end)
local after = os.setlocale(nil)
ngx.header["Content-Type"] = "text/plain"
ngx.say("SETLOCALE_OK=" .. tostring(ok))
ngx.say("LOCALE_SAME=" .. tostring(before == after))
ngx.say("LOCALE=" .. tostring(after))
