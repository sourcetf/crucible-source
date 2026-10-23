//! Engine names and help strings for Admin UI option catalog.

/// One selectable engine entry for Admin dropdowns.
#[derive(Clone, Debug)]
pub struct EngineOption {
    pub id: &'static str,
    pub label: &'static str,
    pub help: &'static str,
    pub default_extensions: &'static [&'static str],
}

/// All application engines exposed in Admin.
pub fn app_engines() -> &'static [EngineOption] {
    &[
        EngineOption {
            id: "php",
            label: "PHP (php-fpm / php-cgi)",
            help: "FastCGI PHP via php-fpm with php-cgi fallback.",
            default_extensions: &["php"],
        },
        EngineOption {
            id: "fastcgi",
            label: "External FastCGI",
            help: "Proxy to an external FastCGI backend.",
            default_extensions: &["php"],
        },
        EngineOption {
            id: "c",
            label: "C plugin (FFI)",
            help: "In-process libapp_c.so or native HTTP sidecar.",
            default_extensions: &["c"],
        },
        EngineOption {
            id: "rust",
            label: "Rust plugin (FFI)",
            help: "In-process libapp_rust.so or native HTTP sidecar.",
            default_extensions: &["rs"],
        },
        EngineOption {
            id: "go",
            label: "Go plugin",
            help: "Go shared library or go-shm sidecar.",
            default_extensions: &["go"],
        },
        EngineOption {
            id: "lua",
            label: "Lua",
            help: "Embedded Lua via app-engines.",
            default_extensions: &["lua"],
        },
        EngineOption {
            id: "wsgi",
            label: "Python WSGI",
            help: "WSGI app-engine shared library.",
            default_extensions: &["py", "wsgi"],
        },
        EngineOption {
            id: "asgi",
            label: "Python ASGI",
            help: "ASGI app-engine shared library.",
            default_extensions: &["py", "asgi"],
        },
        EngineOption {
            id: "psgi",
            label: "Perl PSGI",
            help: "PSGI app-engine shared library.",
            default_extensions: &["pl", "psgi"],
        },
        EngineOption {
            id: "rack",
            label: "Ruby Rack",
            help: "Rack app-engine shared library.",
            default_extensions: &["rb", "ru"],
        },
        EngineOption {
            id: "cgi",
            label: "Legacy CGI",
            help: "Spawn CGI processes (discouraged for C/Go/Rust).",
            default_extensions: &["cgi"],
        },
        EngineOption {
            id: "uwsgi",
            label: "uWSGI protocol",
            help: "uWSGI app-engine shared library / protocol bridge.",
            default_extensions: &["py", "uwsgi"],
        },
        EngineOption {
            id: "python",
            label: "Python (script FFI)",
            help: "Embedded / script FFI Python handler.",
            default_extensions: &["py"],
        },
        EngineOption {
            id: "ruby",
            label: "Ruby (script FFI)",
            help: "Embedded / script FFI Ruby handler.",
            default_extensions: &["rb"],
        },
        EngineOption {
            id: "perl",
            label: "Perl (script FFI)",
            help: "Embedded / script FFI Perl handler.",
            default_extensions: &["pl", "pm"],
        },
        EngineOption {
            id: "jsp",
            label: "JSP (Jetty sidecar)",
            help: "Java JSP via Jetty UDS sidecar.",
            default_extensions: &["jsp"],
        },
        EngineOption {
            id: "asp",
            label: "Classic ASP (AxonASP)",
            help: "AxonASP FFI sidecar.",
            default_extensions: &["asp"],
        },
        // §3.3 的 21 类之一：`do` 是 Apache/Tomcat 风格的 JSP 别名，
        // 运行期与 jsp 同一派发路径（apps/mod.rs 的 "jsp" | "do" 分支）。
        EngineOption {
            id: "do",
            label: "DO (JSP alias)",
            help: "Apache/Tomcat-style JSP alias; dispatched exactly like jsp.",
            default_extensions: &["do", "jsp"],
        },
        EngineOption {
            id: "aspnet",
            label: "ASP.NET Core",
            help: "hostfxr / NativeAOT FFI.",
            default_extensions: &["cshtml", "aspx"],
        },
        EngineOption {
            id: "tsx",
            label: "TypeScript / TSX",
            help: "One-click compile + watch deploy.",
            default_extensions: &["tsx", "ts"],
        },
        // §3.3 的 21 类之一：显式 Unknown。配置可加载（向后兼容），请求期由
        // apps::dispatch 的兜底分支回 501 并点名引擎。
        EngineOption {
            id: "unknown",
            label: "Unknown / custom",
            help: "Unrecognized or custom engine id; config loads, requests return 501.",
            default_extensions: &[],
        },
    ]
}

/// Lookup help text for a given engine id (case-insensitive).
pub fn engine_help(id: &str) -> Option<&'static str> {
    let key = id.to_ascii_lowercase();
    app_engines()
        .iter()
        .find(|e| e.id == key)
        .map(|e| e.help)
}

/// Serialize engines as a JSON array for `/api/catalog`.
pub fn engines_json() -> String {
    let mut s = String::from("[\n");
    for (i, e) in app_engines().iter().enumerate() {
        if i > 0 {
            s.push_str(",\n");
        }
        let exts: Vec<String> = e
            .default_extensions
            .iter()
            .map(|x| format!("\"{x}\""))
            .collect();
        s.push_str(&format!(
            "  {{\"id\":\"{}\",\"label\":{},\"help\":{},\"default_extensions\":[{}]}}",
            e.id,
            json_escape(e.label),
            json_escape(e.help),
            exts.join(",")
        ));
    }
    s.push_str("\n]");
    s
}

/// Full catalog payload for `GET /api/catalog`.
pub fn catalog_json() -> String {
    format!("{{\n  \"engines\": {}\n}}", engines_json())
}

fn json_escape(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// §3.3：目录必须覆盖全部 21 类引擎（含 do / unknown），面板下拉据此生成。
    #[test]
    fn catalog_covers_all_21_engine_kinds() {
        let ids: Vec<&str> = app_engines().iter().map(|e| e.id).collect();
        assert_eq!(ids.len(), 21, "catalog 必须有 21 项: {ids:?}");
        for need in [
            "php", "fastcgi", "jsp", "asp", "do", "tsx", "aspnet", "python", "ruby",
            "perl", "lua", "wsgi", "asgi", "psgi", "cgi", "uwsgi", "rack", "c", "go",
            "rust", "unknown",
        ] {
            assert!(ids.contains(&need), "catalog 缺少引擎 {need}: {ids:?}");
        }
    }
}
