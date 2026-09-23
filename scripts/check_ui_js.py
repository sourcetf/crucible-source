#!/usr/bin/env python3
"""构建前自检：admin_ui.html 里内联 JS 的语法 + 「调用了但没定义」的函数。

为什么需要它：`src/server/admin_ui.html` 是用 `include_str!` 编进二进制的，
**Rust 编译完全不检查它**。字符串或正则里混入一个真实换行，Rust 照样编译通过、
二进制照样产出，但整段内联脚本在浏览器里解析失败 —— 表现是整个面板全废
（所有 pre 停在占位「加载中…」、点标签没反应）。实测踩过，且一次踩了 5 处。

用法：python3 scripts/check_ui_js.py [admin_ui.html]
退出码：0 通过；1 有语法错误（可直接用作构建前门禁）。

依赖 esprima（纯 Python JS 解析器）：pip install esprima。
未安装时退化为「引号平衡」粗检，并明确提示。
"""
import io
import os
import re
import sys

HTML = sys.argv[1] if len(sys.argv) > 1 else "src/server/admin_ui.html"

# JS/浏览器内置全局 + 通过 id 直接可访问的东西，做「未定义调用」检查时跳过
BUILTINS = set("""
Array Object String Number Boolean Math JSON Date RegExp Error TypeError Promise Map Set
WeakMap WeakSet Symbol Proxy Reflect BigInt Intl parseFloat parseInt isNaN isFinite
encodeURIComponent decodeURIComponent encodeURI decodeURI eval Function setTimeout
setInterval clearTimeout clearInterval queueMicrotask structuredClone fetch Request Response
Headers URL URLSearchParams Blob File FileReader FormData AbortController TextEncoder
TextDecoder atob btoa alert confirm prompt console window document location history navigator
localStorage sessionStorage getComputedStyle requestAnimationFrame cancelAnimationFrame
customElements HTMLElement Event CustomEvent Option Image Audio XMLHttpRequest WebSocket
EventSource Worker MutationObserver IntersectionObserver ResizeObserver DOMParser Node NodeList
Element Text Range
""".split())

KEYWORDS = set("""
if else for while do switch case default break continue return function new typeof instanceof
in of delete void yield await async class extends super this try catch finally throw var let
const with debugger
""".split())

BACKSLASH = chr(92)
NL = chr(10)


def extract_inline_scripts(html):
    """返回 [(起始行号, 脚本文本)]，只取内联（无 src 属性）的 <script>。"""
    out = []
    for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html, re.S | re.I):
        out.append((html[: m.start(1)].count(NL) + 1, m.group(1)))
    return out


def odd_quote_lines(js):
    """粗检：单引号数为奇数的行（JS 字符串跨行的特征）。"""
    bad = []
    for i, line in enumerate(js.split(NL), 1):
        code = line.split("//")[0]
        n = 0
        for j, ch in enumerate(code):
            if ch == "'" and (j == 0 or code[j - 1] != BACKSLASH):
                n += 1
        if n % 2:
            bad.append((i, line.strip()[:120]))
    return bad


def defined_names(js):
    """脚本里「算作已定义」的名字。"""
    names = set()
    names |= set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)", js))
    names |= set(re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)", js))
    # window.X = / obj.X = 这类属性赋值同样是已定义（本页大量使用）。
    # 漏掉它会把定义过的函数报成「未定义」——误报会诱导人去改本来正确的代码。
    names |= set(re.findall(r"\.([A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function|\()", js))
    return names


def main():
    if not os.path.isfile(HTML):
        print("FAIL: 找不到 " + HTML)
        return 1
    html = io.open(HTML, encoding="utf-8").read()
    scripts = extract_inline_scripts(html)
    if not scripts:
        # 纯静态页（如 status_page.html）没有内联脚本是正常的，不算失败
        print("OK: " + HTML + " 没有内联 <script>（无需检查）")
        return 0

    try:
        import esprima  # type: ignore
    except Exception:
        esprima = None

    rc = 0
    for start_line, js in scripts:
        print("--- 内联脚本 @ 行 %d，%d 行 ---" % (start_line, len(js.split(NL))))

        if esprima is None:
            print("  (未安装 esprima，退化检查；pip install esprima 可获完整语法检查)")
            bad = odd_quote_lines(js)
            if bad:
                # 保持 rc=0：粗检对转义引号与正则（如 /^\/+/）会误判，
                # 门禁因假阳性失败比没有门禁更糟 —— 只提示，判定交给 esprima。
                print("  WARN: %d 行单引号不配对（疑似字符串跨行；也可能是转义/正则造成的误判，"
                      "装 esprima 可确证）" % len(bad))
                for ln, txt in bad[:10]:
                    print("    L%d: %s" % (start_line + ln - 1, txt))
            else:
                print("  OK: 未见跨行字符串")
            continue

        # esprima 4.0 只到 ES2018：ES2019 的可选 catch 绑定（catch {）会被误报为
        # "Unexpected token {"。浏览器都支持，所以先做兼容改写再解析 ——
        # 避免把合法代码当错误去「修」。
        js_probe = re.sub(r"catch\s*\{", "catch (__e) {", js)

        try:
            esprima.parseScript(js_probe)
        except Exception as e:
            rc = 1
            ln = getattr(e, "lineNumber", None)
            loc = ("（脚本内第 %d 行 → 文件第 %d 行）" % (ln, start_line + ln - 1)) if ln else ""
            print("  FAIL: %s%s" % (e, loc))
            lines = js.split(NL)
            if ln:
                for k in range(max(0, ln - 3), min(len(lines), ln + 2)):
                    print("    %d: %s" % (k + 1, lines[k][:140]))
            continue

        print("  OK: 语法有效")
        defined = defined_names(js)
        called = set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", js))
        unknown = sorted(n for n in called - defined - BUILTINS - KEYWORDS if not n.isupper())
        if unknown:
            print("  WARN: 调用了但本页未见定义（可能拼写错，也可能来自外部脚本）: "
                  + ", ".join(unknown[:12]))
        else:
            print("  OK: 未见未定义的函数调用")

    return rc


if __name__ == "__main__":
    sys.exit(main())
