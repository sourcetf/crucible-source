// 最小 real ASP.NET（hostfxr 进程内）样例。
//
// 运行路径：webserver → libapp_aspnet.so (appengine ABI) → hostfxr_* API →
//           本程序集 Handler.Render（UnmanagedCallersOnly）→ 返回渲染后的 .aspx。
// 没有任何 HTTP 服务器/Kestrel：TCP/HTTP 仍由 crucible 自己处理。
//
// 支持的模板语法（与 libs/aspnet-ffi/aspnet_engine.c 的 mini 渲染器同子集）：
//   <%@ ... %> / <% ... %> / <%-- ... --%>   丢弃
//   <%= Host.Framework %>                    .NET 运行时描述（只有真 CoreCLR 才有值）
//   <%= Host.Version %>                      Environment.Version
//   <%= Request.Path %> / Request.Method
//   <%= Request.QueryString("k") %> / Request("k")
//   <%= Request.Form("k") %>                 application/x-www-form-urlencoded
//   <%= "literal" %>
using System;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace Crucible.AspNet.Sample;

public static class Handler
{
    /// <summary>
    /// hostfxr 的 UNMANAGEDCALLERSONLY_METHOD 入口。
    /// 返回写入 out 的字节数（不含结尾 NUL），负数表示失败。
    /// </summary>
    [UnmanagedCallersOnly]
    public static unsafe int Render(
        IntPtr methodPtr,
        IntPtr pathPtr,
        IntPtr queryPtr,
        IntPtr bodyPtr,
        IntPtr sourcePtr,
        IntPtr outPtr,
        int outCap)
    {
        if (outPtr == IntPtr.Zero || outCap <= 0)
        {
            return -1;
        }
        try
        {
            string method = Marshal.PtrToStringUTF8(methodPtr) ?? "GET";
            string path = Marshal.PtrToStringUTF8(pathPtr) ?? "/";
            string query = Marshal.PtrToStringUTF8(queryPtr) ?? "";
            string body = Marshal.PtrToStringUTF8(bodyPtr) ?? "";
            string source = Marshal.PtrToStringUTF8(sourcePtr) ?? "";
            string rendered = RenderTemplate(source, method, path, query, body);
            byte[] bytes = Encoding.UTF8.GetBytes(rendered);
            if (bytes.Length + 1 > outCap)
            {
                return -2;
            }
            fixed (byte* p = bytes)
            {
                Buffer.MemoryCopy(p, (void*)outPtr, outCap, bytes.Length);
            }
            *((byte*)outPtr + bytes.Length) = 0;
            return bytes.Length;
        }
        catch (Exception)
        {
            return -3;
        }
    }

    private static string RenderTemplate(string src, string method, string path, string query, string body)
    {
        var post = ParseForm(body);
        var outSb = new StringBuilder(src.Length + 64);
        int i = 0;
        while (i < src.Length)
        {
            if (src[i] == '<' && i + 1 < src.Length && src[i + 1] == '%')
            {
                // 注释 <%-- --%>
                if (StartsWith(src, i, "<%--"))
                {
                    int e = src.IndexOf("--%>", i + 4, StringComparison.Ordinal);
                    i = e < 0 ? src.Length : e + 4;
                    continue;
                }
                // 指令 <%@ %> / 声明 <%! %>
                if (i + 2 < src.Length && (src[i + 2] == '@' || src[i + 2] == '!'))
                {
                    int e = src.IndexOf("%>", i + 3, StringComparison.Ordinal);
                    i = e < 0 ? src.Length : e + 2;
                    continue;
                }
                // 表达式 <%= %>
                if (i + 2 < src.Length && src[i + 2] == '=')
                {
                    int e = src.IndexOf("%>", i + 3, StringComparison.Ordinal);
                    if (e < 0)
                    {
                        break;
                    }
                    string expr = src.Substring(i + 3, e - (i + 3)).Trim();
                    outSb.Append(Eval(expr, method, path, query, post));
                    i = e + 2;
                    continue;
                }
                // 脚本块 <% %>（本最小样例不支持代码块，按 mini 语义丢弃）
                {
                    int e = src.IndexOf("%>", i + 2, StringComparison.Ordinal);
                    i = e < 0 ? src.Length : e + 2;
                    continue;
                }
            }
            outSb.Append(src[i]);
            i++;
        }
        return outSb.ToString();
    }

    private static string Eval(string expr, string method, string path, string query, System.Collections.Generic.Dictionary<string, string> form)
    {
        if (expr.Length == 0)
        {
            return "";
        }
        if (expr.Equals("Host.Framework", StringComparison.OrdinalIgnoreCase))
        {
            return RuntimeInformation.FrameworkDescription;
        }
        if (expr.Equals("Host.Version", StringComparison.OrdinalIgnoreCase))
        {
            return Environment.Version.ToString();
        }
        if (expr.Equals("Host.OS", StringComparison.OrdinalIgnoreCase))
        {
            return RuntimeInformation.OSDescription;
        }
        if (expr.Equals("Request.Path", StringComparison.OrdinalIgnoreCase)
            || expr.Equals("Request.PathInfo", StringComparison.OrdinalIgnoreCase))
        {
            return path;
        }
        if (expr.Equals("Request.Method", StringComparison.OrdinalIgnoreCase))
        {
            return method;
        }
        if (expr.Equals("Request.QueryString", StringComparison.OrdinalIgnoreCase))
        {
            return query;
        }
        string? key = ExtractStringArg(expr);
        if (key != null)
        {
            if (expr.Contains("Form", StringComparison.OrdinalIgnoreCase))
            {
                return form.TryGetValue(key, out var fv) ? fv : "";
            }
            return QueryValue(query, key);
        }
        // 字符串字面量："x" / 'x'
        if ((expr[0] == '"' && expr[^1] == '"') || (expr[0] == '\'' && expr[^1] == '\''))
        {
            return expr.Substring(1, expr.Length - 2);
        }
        return "";
    }

    private static string? ExtractStringArg(string expr)
    {
        int q = expr.IndexOf('"');
        char delim = '"';
        if (q < 0)
        {
            q = expr.IndexOf('\'');
            delim = '\'';
        }
        if (q < 0)
        {
            return null;
        }
        int q2 = expr.IndexOf(delim, q + 1);
        if (q2 < 0)
        {
            return null;
        }
        return expr.Substring(q + 1, q2 - q - 1);
    }

    private static string QueryValue(string query, string key)
    {
        foreach (string pair in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            string k = eq < 0 ? pair : pair[..eq];
            if (Uri.UnescapeDataString(k) == key)
            {
                return eq < 0 ? "" : Uri.UnescapeDataString(pair[(eq + 1)..].Replace('+', ' '));
            }
        }
        return "";
    }

    private static System.Collections.Generic.Dictionary<string, string> ParseForm(string body)
    {
        var d = new System.Collections.Generic.Dictionary<string, string>(StringComparer.Ordinal);
        if (string.IsNullOrEmpty(body))
        {
            return d;
        }
        foreach (string pair in body.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            string k = eq < 0 ? pair : pair[..eq];
            string v = eq < 0 ? "" : pair[(eq + 1)..];
            d[Uri.UnescapeDataString(k.Replace('+', ' '))] = Uri.UnescapeDataString(v.Replace('+', ' '));
        }
        return d;
    }

    private static bool StartsWith(string s, int at, string prefix)
    {
        return at + prefix.Length <= s.Length
            && string.CompareOrdinal(s, at, prefix, 0, prefix.Length) == 0;
    }
}
