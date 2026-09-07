import re
p = r"c:\Users\Administrator\Desktop\crucible\deploy_core.py"
t = open(p, encoding="utf-8").read()
print("lines", t.count("\n"), "bytes", len(t))
keys = re.findall(r'"([^"]+)":\s*r?\'\'\'', t)
print("file keys", len(keys))
for k in keys:
    print(k)
