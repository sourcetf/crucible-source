import paramiko
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(
    "83.229.125.81",
    username="root",
    password="Yc4+uVpaU658m",
    timeout=30,
    allow_agent=False,
    look_for_keys=False,
)
cmd = r"""
find /crucible -type f | sort
echo ---
wc -l /crucible/src/server/h2.rs /crucible/src/config.rs /crucible/Cargo.toml
echo ---
grep -n 'BATCH_CAP\|worker_threads\|scrubBrand\|SO_BUSY_POLL\|handle_h2' /crucible/src/main.rs /crucible/src/server/h2.rs /crucible/src/server/mod.rs /crucible/src/server/admin_ui.html /crucible/libs/h2/src/lib.rs 2>/dev/null | head -40
echo ---
tail -n 30 /crucible/src/server/h2.rs
"""
stdin, stdout, stderr = c.exec_command(cmd)
print(stdout.read().decode())
err = stderr.read().decode()
if err:
    print("STDERR:", err)
c.close()
