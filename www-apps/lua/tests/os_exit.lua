-- os.exit(3) must not terminate the webserver process.
ngx.say("before-os-exit")
os.exit(7)
ngx.say("after-os-exit")
