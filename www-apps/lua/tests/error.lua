-- Uncaught error after output: must be 500 (fixed text), not 200 + partial.
ngx.say("partial-output")
error("boom: application failed after writing output")
