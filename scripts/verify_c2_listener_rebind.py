#!/usr/bin/env python3
"""C-2 真机验证：listener 的 address 变更后 socket 必须**真的重绑**。

只碰 loopback（127.0.0.1 → 127.0.0.2），临时加一个 listener，最后还原 config.toml。
旧实现按 port 去重：改地址后 socket 不重建，仍绑 127.0.0.1（第 2 步就会现形）。
"""
import shutil
import subprocess
import time

CFG = "/crucible/config.toml"
BAK = "/tmp/config.toml.c2bak"

ENTRY = """
[[listeners]]
address = "127.0.0.1"
port = 18080
root = "/tmp/c2root"
http_versions = ["h1"]
server_name = "c2-test.local"
"""


def sh(cmd: str) -> str:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()


def listening() -> str:
    out = sh("netstat -ln -f inet | grep 18080")
    return " ".join(out.split()) if out else "(无 18080 监听)"


sh("mkdir -p /tmp/c2root && echo hi > /tmp/c2root/index.html")
shutil.copy(CFG, BAK)
try:
    with open(CFG, "a", encoding="utf-8") as f:
        f.write(ENTRY)
    time.sleep(6)
    print("1) 追加 127.0.0.1:18080 →", listening())
    print("   curl 127.0.0.1:18080 →", sh("curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:18080/") or "拒连")

    text = open(CFG, encoding="utf-8").read()
    text = text.replace('address = "127.0.0.1"\nport = 18080', 'address = "127.0.0.2"\nport = 18080')
    with open(CFG, "w", encoding="utf-8") as f:
        f.write(text)
    time.sleep(6)
    print("2) address 改成 127.0.0.2 →", listening())
    print("   curl 127.0.0.2:18080 →", sh("curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.2:18080/") or "拒连")
    print("   curl 127.0.0.1:18080 →", sh("curl -s -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:18080/") or "拒连")
finally:
    shutil.copy(BAK, CFG)
    time.sleep(6)
    print("3) 还原 config.toml →", listening())
