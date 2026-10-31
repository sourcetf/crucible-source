local m = require("tests.probe_module")
ngx.header["Content-Type"] = "text/plain"
ngx.say("MODULE=" .. tostring(m.name))
ngx.say("MODULE_WM=" .. tostring(m.env("WINDOWMARK")))
