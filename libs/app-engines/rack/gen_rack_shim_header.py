#!/usr/bin/env python3
"""把 rack_shim.rb 生成为 C 头文件 rack_shim_rb.h（编进 libapp_rack.so）。

用法（仓库根目录或任意目录均可）：
    python3 libs/app-engines/rack/gen_rack_shim_header.py

rack_shim.rb 是唯一可读源文件；rack_shim_rb.h 是生成物，不要手改。
"""
import pathlib

here = pathlib.Path(__file__).resolve().parent
src = (here / "rack_shim.rb").read_text(encoding="utf-8")
out = here / "rack_shim_rb.h"

lines = [
    "/* 由 gen_rack_shim_header.py 从 rack_shim.rb 生成 —— 不要手改。",
    " * 重新生成：python3 libs/app-engines/rack/gen_rack_shim_header.py",
    " */",
    "#ifndef CRUCIBLE_RACK_SHIM_RB_H",
    "#define CRUCIBLE_RACK_SHIM_RB_H",
    "",
    "static const char rack_shim_rb[] =",
]
for raw in src.splitlines():
    esc = (
        raw.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\t", "\\t")
    )
    lines.append('    "%s\\n"' % esc)
lines += [
    "    ;",
    "",
    "#endif /* CRUCIBLE_RACK_SHIM_RB_H */",
    "",
]
out.write_text("\n".join(lines), encoding="utf-8")
print("wrote", out)
