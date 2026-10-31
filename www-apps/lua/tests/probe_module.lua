-- Loaded through `require("tests.probe_module")`: proves package.path includes
-- the app docroot, and that os.getenv inside a module sees the same per-request
-- view as the main script.
return {
    name = "probe-module",
    env = function(k)
        return os.getenv(k)
    end,
}
