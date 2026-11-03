//! 应用引擎的**进程级沙箱**：OpenBSD `unveil(2)` + `pledge(2)` + `chroot(2)`。
//!
//! 为什么在这个位置做：所有「spawn 出去」的引擎（php-fpm、php-cgi、CGI 脚本、各
//! 常驻 sidecar、go-shm、tsx）最终都是一次 `fork` + `execve`。`unveil/pledge` 必须
//! 作用在**子进程自己**身上、且要在 `execve` **之前**施加（`execpromises` 才能被
//! 继承），所以用 `std::os::unix::process::CommandExt::pre_exec` 注册钩子 —— 钩子在
//! fork 之后、exec 之前的子进程里跑，不需要额外的小二进制。
//!
//! 语义（OpenBSD）：
//! * `unveil(path, perms)`：把子进程的**文件系统视图**收缩到列出的路径；`perms` 是
//!   `r`/`w`/`x`/`c` 的组合。第一次不给路径、`perms=NULL` 的调用（这里是 `unveil(NULL,
//!   NULL)`）是**锁定**：之后再 `unveil` 一律失败。锁定必须放在全部揭示之后。
//! * `pledge(promises, execpromises)`：把子进程可用的**系统调用集合**收缩到
//!   `promises`，之后它 `exec` 出来的孩子继承 `execpromises`（空串 = 孩子不能 exec）。
//! * `chroot(dir)`：FPM 自己有 pool 级 `chroot` 指令（见 `php.rs`），这里只对
//!   显式配置了 `chroot` 的引擎做。
//!
//! 安全取向：**fail-closed**。`unveil`/`pledge`/`chroot` 任一失败 ⇒ 子进程立刻
//! `_exit(127)`，于是该引擎起不来（对外 502），而不是悄悄以「无沙箱」方式跑起来。
//!
//! 非 OpenBSD：这些调用不存在（Linux 没有 unveil/pledge）。整个模块降级为 no-op ——
//! **不假装**做了隔离；`SandboxSpec::is_active()` 会如实返回 false，便于日志与验收
//! 区分「真的施加了」与「平台不支持」。

use std::path::{Path, PathBuf};

/// 单个被揭示的路径及其权限位（`r`/`w`/`x`/`c`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    pub path: PathBuf,
    pub perms: String,
}

/// 一个引擎子进程的沙箱规格（纯数据，便于单测）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SandboxSpec {
    /// `false` = 完全不施加（`apply()` 是 no-op）。配置里 `enabled = false` 时如此。
    pub enabled: bool,
    /// 引擎名/用途，仅用于子进程失败时的 stderr 诊断。
    pub engine_hint: String,
    pub reveals: Vec<Reveal>,
    /// `None` = 不调用 `pledge`（例如 JIT/线程模型复杂的 sidecar：unveil 仍生效）。
    pub pledge: Option<String>,
    /// 孩子进程 `exec` 时继承的 promise 集；默认空串 = **孩子不能再 exec**。
    pub pledge_exec: String,
    /// 可选：chroot 到该目录（要求 root；FPM 走自己的 pool 指令，不在这里设）。
    pub chroot: Option<PathBuf>,
    /// chroot 后的工作目录（默认 `/`）。
    pub chdir: Option<PathBuf>,
}

impl SandboxSpec {
    /// 该规格在当前平台上是否**真的**会产生隔离效果（OpenBSD 且 enabled）。
    pub fn is_active(&self) -> bool {
        self.enabled && cfg!(target_os = "openbsd")
    }

    /// 人类可读的一行摘要（日志/验收用；把「揭示了什么、pledge 了什么」写清楚，
    /// 避免运维以为开了沙箱却因为平台不匹配而实际没开）。
    pub fn summary(&self) -> String {
        let mut paths: Vec<String> = self
            .reveals
            .iter()
            .map(|r| format!("{}:{}", r.path.display(), r.perms))
            .collect();
        paths.sort();
        format!(
            "engine={} enabled={} active_here={} reveals=[{}] pledge={:?} pledge_exec={:?} chroot={:?}",
            self.engine_hint,
            self.enabled,
            self.is_active(),
            paths.join(" "),
            self.pledge.as_deref().unwrap_or("<none>"),
            self.pledge_exec,
            self.chroot.as_ref().map(|p| p.display().to_string()),
        )
    }

    /// 把沙箱挂到 `Command` 上（`pre_exec`）。
    ///
    /// 失败语义：`apply()` 自身只在**参数**非法的极端情况下报错；实际的
    /// `unveil`/`pledge` 失败发生在子进程里，会 `_exit(127)` 让引擎起不来。
    pub fn apply(&self, cmd: &mut std::process::Command) -> std::io::Result<()> {
        #[cfg(target_os = "openbsd")]
        {
            if !self.enabled {
                return Ok(());
            }
            let reveals: Vec<(std::ffi::CString, std::ffi::CString)> = self
                .reveals
                .iter()
                .map(|r| {
                    // 转换失败 ⇒ 报错而不是**丢掉**这条揭示：丢掉 = 少揭示一个路径，
                    // 引擎可能因此起不来（fail-closed），但静默丢弃会让规格与日志不符。
                    let p = std::ffi::CString::new(r.path.as_os_str().as_encoded_bytes())
                        .map_err(|_| {
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                format!("unveil 路径含 NUL: {:?}", r.path),
                            )
                        })?;
                    let m = std::ffi::CString::new(r.perms.as_str()).map_err(|_| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("unveil 权限含 NUL: {:?}", r.perms),
                        )
                    })?;
                    Ok((p, m))
                })
                .collect::<std::io::Result<_>>()?;
            let pledge = self
                .pledge
                .as_ref()
                .and_then(|p| std::ffi::CString::new(p.as_str()).ok());
            let pledge_exec = std::ffi::CString::new(self.pledge_exec.as_str()).ok();
            let chroot = self
                .chroot
                .as_ref()
                .and_then(|d| std::ffi::CString::new(d.as_os_str().as_encoded_bytes()).ok());
            let chdir = self
                .chdir
                .as_ref()
                .and_then(|d| std::ffi::CString::new(d.as_os_str().as_encoded_bytes()).ok());

            let engine = self.engine_hint.clone();
            unsafe {
                use std::os::unix::process::CommandExt;
                cmd.pre_exec(move || {
                    // ① 揭示路径（顺序无关，但必须在锁之前）。
                    for (p, m) in &reveals {
                        if libc::unveil(p.as_ptr(), m.as_ptr()) == -1 {
                            let e = std::io::Error::last_os_error();
                            eprintln!(
                                "crucible-sandbox[{engine}]: unveil({:?}, {:?}) 失败: {e}",
                                p, m
                            );
                            libc::_exit(127);
                        }
                    }
                    // ② 锁定：之后的 unveil 一律失败（防引擎自己扩大视图）。
                    if libc::unveil(std::ptr::null(), std::ptr::null()) == -1 {
                        let e = std::io::Error::last_os_error();
                        eprintln!("crucible-sandbox[{engine}]: unveil 锁定失败: {e}");
                        libc::_exit(127);
                    }
                    // ③ chroot（仅显式配置的引擎；FPM 用自己的 pool 指令）。
                    if let Some(d) = &chroot {
                        if libc::chroot(d.as_ptr()) == -1 {
                            let e = std::io::Error::last_os_error();
                            eprintln!("crucible-sandbox[{engine}]: chroot 失败: {e}");
                            libc::_exit(127);
                        }
                        let to = chdir
                            .as_ref()
                            .map(|c| c.as_ptr())
                            .unwrap_or(c"/".as_ptr());
                        if libc::chdir(to) == -1 {
                            let e = std::io::Error::last_os_error();
                            eprintln!("crucible-sandbox[{engine}]: chdir 失败: {e}");
                            libc::_exit(127);
                        }
                    }
                    // ④ pledge（最后一步：它之后连 unveil 都不能再调）。
                    if let Some(p) = &pledge {
                        let ep = pledge_exec
                            .as_ref()
                            .map(|c| c.as_ptr())
                            .unwrap_or(std::ptr::null());
                        if libc::pledge(p.as_ptr(), ep) == -1 {
                            let e = std::io::Error::last_os_error();
                            eprintln!("crucible-sandbox[{engine}]: pledge({p:?}) 失败: {e}");
                            libc::_exit(127);
                        }
                    }
                    Ok(())
                });
            }
            Ok(())
        }
        #[cfg(not(target_os = "openbsd"))]
        {
            let _ = cmd;
            Ok(())
        }
    }
}

/// 各 spawn 入口的统一接线：按应用配置组装规格、打一行可观测日志、挂到 `Command`。
///
/// 返回规格便于调用方记录/断言（例如 php 还要用 `spec.chroot`）。**失败只记日志、
/// 不阻断 spawn**：`apply()` 只在参数含 NUL 这类极端情况报错，而真正的隔离失败发生在
/// 子进程里（会 `_exit(127)`，引擎起不来 ⇒ 502），不会被静默忽略。
#[allow(clippy::too_many_arguments)]
pub fn apply_for_app(
    cmd: &mut std::process::Command,
    engine: &str,
    app_cfg: &SandboxConfig,
    docroot: Option<&Path>,
    state_dir: Option<&Path>,
    tmp_dir: Option<&Path>,
    bin: Option<&Path>,
) -> SandboxSpec {
    let mut interp = bin
        .map(|b| interp_roots_for(engine, b))
        .unwrap_or_default();
    interp.extend(engine_artifact_roots(engine, true));
    let spec = build_spec(engine, docroot, state_dir, tmp_dir, &interp, bin, app_cfg);
    log::info!("sandbox[{engine}]: {}", spec.summary());
    if let Err(e) = spec.apply(cmd) {
        log::warn!("sandbox[{engine}]: 挂钩失败（子进程将无隔离）: {e}");
    }
    spec
}

// ---------------------------------------------------------------- 策略表

/// 配置里每应用可覆盖的沙箱字段（`[listeners.apps.sandbox]`）。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SandboxConfig {
    /// 是否启用。默认 **true**（OpenBSD 上真正生效；其它平台 no-op）。
    #[serde(default = "default_sandbox_on")]
    pub enabled: bool,
    /// docroot 是否给写权限。默认 `false` = 只 `r`+`x`（**连 create 都不给**：RCE
    /// 无法往 docroot 丢 webshell 做持久化）；需要写上传/缓存目录的 app 才打开
    /// （⇒ `rwxc`）。上传目录也可以用 `extra_unveil = ["<dir>:rwxc"]` 单独放开。
    #[serde(default)]
    pub docroot_rw: bool,
    /// 额外的揭示项，形如 `"/path:rwc"`（`:` 后是权限位）。可用于给某个 app
    /// 放开它确实需要的目录（例如共享上传区、外部配置）。
    #[serde(default)]
    pub extra_unveil: Vec<String>,
    /// 覆盖 promise 集（空 = 用引擎默认）。传 `"none"` 表示**只 unveil 不 pledge**。
    #[serde(default)]
    pub pledge: Option<String>,
    /// 覆盖孩子进程继承的 promise 集（默认空串 = 孩子不能再 exec）。
    #[serde(default)]
    pub pledge_exec: Option<String>,
    /// 允许引擎 `exec`（把 `exec`/`prot_exec` 加进 promise 集）。默认 `false`：
    /// PHP/CGI 的 RCE 拿不到 shell 更值钱；确有需要（app 会 shell out）才打开。
    #[serde(default)]
    pub allow_exec: bool,
    /// 可选 chroot 目标目录（要求以 root 跑；FPM 有自己的 pool 级 `chroot`，
    /// 由 `php.rs` 直接写进池配置，不走这里）。
    #[serde(default)]
    pub chroot: Option<String>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            enabled: default_sandbox_on(),
            docroot_rw: false,
            extra_unveil: Vec::new(),
            pledge: None,
            pledge_exec: None,
            allow_exec: false,
            chroot: None,
        }
    }
}

fn default_sandbox_on() -> bool {
    true
}

/// 全局默认（`Config` 顶层 `[sandbox]`），每应用可以再覆盖。
pub type GlobalSandboxConfig = SandboxConfig;

/// 引擎默认 promise 集。
///
/// 判据是**该引擎运行时真正需要的系统调用面**，不是「越少越好」：承诺集给窄了
/// 引擎会 `SIGABRT`（pledge 违规），给宽了等于没做。这里只放「通用 web 应用需要、
/// 且与逃逸无关」的项，并**默认不含 `exec`**（`allow_exec` 才加）：
///
/// * `stdio/rpath/wpath/cpath/dpath` —— 读写文件与建目录（`dpath`=读目录）。
///   **刻意不含 `tmppath`**：本机 OpenBSD 的 pledge 不认该 token（逐 token 实测
///   `tmppath`→INVALID），混进承诺串会让**整条 `pledge()` 返回 EINVAL**、
///   子进程 `_exit(127)`、引擎全挂。临时文件用每应用自建、已被 reveal 的
///   `state/php/tmp/<key>`，不需 `/tmp` 权限。
/// * `inet/unix/dns` —— FastCGI 走 UDS（`unix`）、出网请求（`inet`+`dns`）
/// * `flock/fattr` —— 文件锁与属性（PHP 的 `flock`/`stat`）
/// * `getpw/proc` —— FPM 以 nobody 跑时的 `getpwnam`/`getgrnam`、进程信息
/// * `prot_exec` —— JIT/`mmap(PROT_EXEC)` 类（PHP opcache 在有 JIT 时需要；无 JIT
///   时多给一个 promise 也不构成逃逸面）
///
/// **不包含**：`chown`（改属主 = 可把别人的文件抢走）、`settime`、`ps`/`vminfo`
/// （侧信道）、`route`/`wroute`（改路由）、`bpf`/`tape`/`audio`/`video`（无关权限）、
/// `mount`/`unmount`（本就不在 pledge 里，chroot 后仍受特权限制）。
fn engine_pledge(engine: &str, allow_exec: bool) -> Option<&'static str> {
    let base = match engine {
        // 通用解释器型：覆盖 php / php-fpm / php-cgi / cgi / 各脚本型 sidecar。
        "php" | "fastcgi" | "cgi" | "perl" | "psgi" | "python" | "wsgi" | "asgi" | "uwsgi"
        | "ruby" | "rack" | "lua" | "asp" | "aspnet" | "do" | "tsx" => {
            // **不要 `tmppath`**：本机 OpenBSD 的 pledge 不认这个 token，混进承诺串会让
            // **整条 pledge() 返回 EINVAL**（子进程 _exit(127)，sidecar 全挂、502）。
            // 临时目录用每应用自建的 `state/php/tmp/<key>`（已 reveal），不需要 /tmp 权限：
            // `rpath/wpath/cpath/dpath` 足以覆盖在已 reveal 路径上的读写建目录。
            "stdio rpath wpath cpath dpath inet unix dns flock fattr getpw proc prot_exec"
        }
        // 原生编译产物（c/rust/go）：同样按 web 应用口径，但不需要解释器的额外项。
        "c" | "rust" | "go" => "stdio rpath wpath cpath dpath inet unix dns flock fattr",
        // 没见过的引擎名：**不给** pledge（只 unveil）。宁可少一层，也不要因为
        // 猜错承诺集把引擎打成起不来。
        _ => return None,
    };
    let _ = allow_exec; // 见 pledge_for：exec 在调用点按需追加
    Some(base)
}

/// 所有 web 应用都可能要、且**泄露不了秘密**的公共路径。
///
/// 这些不是「保险起见多给点」—— 少一个就会让正常功能 fail-closed 地崩掉：
/// * `/etc/localtime` + `/usr/share/zoneinfo`：`date()`/`DateTime` 解析时区
/// * `/etc/resolv.conf` + `/etc/hosts`：出网请求的域名解析（`dns` promise 之外还要能读文件）
/// * `/etc/services` + `/etc/protocols`：`getaddrinfo`
/// * `/etc/ssl/cert.pem` + `/etc/ssl/certs`：TLS 客户端校验用**公共根证书**。
///   注意**不揭示** `/etc/ssl` 整棵 —— 那会带出 `/etc/ssl/private/`（服务器私钥）。
/// * `/dev/null`（读写：日志/重定向）、`/dev/urandom`（随机数）
const BASE_REVEALS: &[(&str, &str)] = &[
    ("/etc/localtime", "r"),
    ("/usr/share/zoneinfo", "r"),
    ("/etc/resolv.conf", "r"),
    ("/etc/hosts", "r"),
    ("/etc/services", "r"),
    ("/etc/protocols", "r"),
    ("/etc/ssl/cert.pem", "r"),
    ("/etc/ssl/certs", "r"),
    ("/dev/null", "rw"),
    ("/dev/urandom", "r"),
];

/// 所有 spawn 出来的进程都要、但**不属于**「公共只读」一档的两组路径。
///
/// * `/bin`,`/sbin`,`/usr/bin`,`/usr/sbin`（`rx`）：sidecar 的 `deps/bin/index` 与
///   `www-apps/<app>/init.sh` 生成的**包装脚本**都是 `#!/bin/sh`；CGI 脚本同理。
///   unveil 里没有 `/bin` 时 `execve` 返回 EACCES —— 引擎起不来。真机 2026-11-04：
///   5 条路由 502，而日志里 sandbox 明明 `active_here=true`，reveals 里就是缺 `/bin`。
///   代价是这些进程能 exec 系统命令；缓解在于 `pledge` 默认**不放** `exec`
///   （`pledge_exec` 为空 ⇒ 它的子进程也不能 exec），需要更严可给应用开
///   `pledge = "..."` 覆盖或把本表在配置里关掉。
/// * `/etc/passwd`,`/etc/group`,`/etc/nsswitch.conf`,`/etc/login.conf`（`r`）：
///   解释器启动时 drop privileges（php-fpm 从 root 切到 nobody、ruby/python 的
///   `getpwnam`）。读不到就 `cannot get gid for group 'nobody'`，master 直接退出。
///   **只给读**：这些文件里没有可泄露的密钥（真实密码在 `/etc/master.passwd`）。
pub const BASE_UNIVERSE_REVEALS: &[(&str, &str)] = &[
    ("/bin", "rx"),
    ("/sbin", "rx"),
    ("/usr/bin", "rx"),
    ("/usr/sbin", "rx"),
    ("/etc/passwd", "r"),
    ("/etc/group", "r"),
    ("/etc/nsswitch.conf", "r"),
    ("/etc/login.conf", "r"),
];

/// PHP 解释器自身的只读目录（按二进制名推导版本）。
///
/// `php-fpm-8.5` ⇒ 额外揭示 `/etc/php-8.5`（php.ini 与 conf.d）与
/// `/usr/local/lib/php-8.5`（扩展 .so）。推导不出来（例如运维填了自定义路径）就只
/// 给通用库目录 —— 宁可少揭示（引擎起不来会立刻可见），也不要错给写权限。
pub fn php_interp_roots(bin: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/local/lib"),
    ];
    if let Some(dir) = bin.parent() {
        out.push(dir.to_path_buf());
    }
    let base = bin.file_name().and_then(|s| s.to_str()).unwrap_or("");
    // 取 `php-fpm-8.5` / `php-cgi-8.5` / `php-fpm85` 里的版本片段。
    let ver = base
        .rsplit_once('-')
        .map(|(_, v)| v)
        .filter(|v| v.starts_with(|c: char| c.is_ascii_digit()))
        .map(|v| v.trim_end_matches(|c: char| !c.is_ascii_digit() && c != '.').to_string())
        .or_else(|| {
            let digits: String = base.chars().rev().take_while(|c| c.is_ascii_digit()).collect();
            let digits: String = digits.chars().rev().collect();
            match digits.len() {
                2 => Some(format!("{}.{}", &digits[0..1], &digits[1..2])),
                3 => Some(format!("{}.{}", &digits[0..1], &digits[1..3])),
                _ => None,
            }
        });
    if let Some(v) = ver {
        for cand in [format!("/etc/php-{v}"), format!("/usr/local/lib/php-{v}")] {
            let p = PathBuf::from(cand);
            if p.exists() {
                out.push(p);
            }
        }
    }
    out
}

/// 应用自己的临时目录（`state/tmp/<key>`）。每个应用一个：彼此看不到对方的会话/
/// 上传临时文件；同时避免揭示整个 `/tmp`（那里有别的进程的文件）。
pub fn app_tmp_dir(state_dir: &Path, key: &str) -> PathBuf {
    state_dir.join("tmp").join(key)
}

/// 通用引擎的**只读**运行时目录（解释器/共享库/框架）。
///
/// 为什么必须按引擎给：`ld.so` 在 `exec` 时就要读这些目录，unveil 少一个 ⇒ 引擎
/// 起不来（fail-closed，能看到 502 与子进程 stderr）；给多了则把「RCE 后能读什么」
/// 放大。这里按引擎族列出**只读**（`r`+`x`）目录，写权限一律只给 docroot/state/tmp。
///
/// 注意：这些路径不存在的会被 `build_spec` 跳过，所以同一份表可跨平台复用。
pub fn interp_roots_for(engine: &str, bin: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = vec![
        PathBuf::from("/usr/lib"),
        PathBuf::from("/usr/local/lib"),
        PathBuf::from("/usr/libexec"),
    ];
    if let Some(dir) = bin.parent() {
        out.push(dir.to_path_buf());
    }
    let mut add = |p: &str| {
        let p = PathBuf::from(p);
        if p.exists() {
            out.push(p);
        }
    };
    match engine {
        // PHP 走 [php_interp_roots]（还要按版本找 /etc/php-X）。
        "php" | "fastcgi" => out.extend(php_interp_roots(bin)),
        "perl" | "psgi" | "cgi" => {
            add("/usr/libdata/perl5");
            add("/usr/local/libdata/perl5");
            add("/usr/local/lib/perl5");
            add("/usr/lib/perl5");
        }
        "python" | "wsgi" | "asgi" | "uwsgi" => {
            add("/usr/local/lib/python3");
            add("/usr/lib/python3");
            add("/usr/local/lib/python3.13");
            add("/usr/lib/python3.13");
            add("/usr/local/share/python3");
        }
        "ruby" | "rack" => {
            add("/usr/local/lib/ruby");
            add("/usr/local/share/gems");
            add("/usr/local/lib/ruby/gems");
            add("/usr/lib/ruby");
        }
        "lua" => {
            add("/usr/local/lib/lua");
            add("/usr/local/share/lua");
        }
        "jsp" | "do" => {
            // JVM：整个 JDK 树只读（模块/jimage 在 jdk 根下），jar 由 `bin` 之外
            // 的 extra_unveil 或 docroot 覆盖。
            add("/usr/local/jdk-17");
            add("/usr/local/share/java");
            add("/usr/local/lib/java");
        }
        "tsx" => {
            add("/usr/local/lib/node_modules");
            add("/usr/local/share/node");
        }
        "aspnet" => {
            add("/usr/local/share/dotnet");
            add("/usr/local/lib/dotnet");
        }
        // c/rust/go：静态/自包含，无额外运行时目录。
        _ => {}
    }
    out
}

/// 组装一个引擎的沙箱规格。
///
/// 参数：
/// * `engine` —— 引擎名（`php`/`cgi`/...）
/// * `docroot`/`state_dir`/`tmp_dir` —— 该应用自己的目录（揭示 `r`+`x`+`c`，按需 `w`）
/// * `interp_roots` —— 解释器自身的只读目录（`/usr/lib`、`/usr/local/lib`、php 的
///   `etc` 目录、以及**解释器二进制所在的父目录**）。这些必须是只读（`r`+`x`）：
///   给写权限等于让 RCE 改解释器/库文件。
/// * `bin` —— 将被 exec 的程序（要 `x`；若在已揭示目录内可省）
/// * `cfg` —— 每应用覆盖
pub fn build_spec(
    engine: &str,
    docroot: Option<&Path>,
    state_dir: Option<&Path>,
    tmp_dir: Option<&Path>,
    interp_roots: &[PathBuf],
    bin: Option<&Path>,
    cfg: &SandboxConfig,
) -> SandboxSpec {
    let mut reveals: Vec<Reveal> = Vec::new();
    // 默认**不给 `c`（create）也不给 `w`**：`rxc` 仍允许在 docroot 里**新建**文件
    // —— RCE 丢一个 `pwn.php` 进去就完成了持久化。默认 `rx` 只读+可执行；
    // 需要写 docroot 的应用（上传/缓存）显式开 `docroot_rw`（⇒ `rwxc`）。
    let doc_perms = if cfg.docroot_rw { "rwxc" } else { "rx" };

    if cfg.enabled {
        // ① 公共只读路径（时区/解析/TLS 根证书/设备）—— 不存在就跳过（不报错，
        //    否则裁剪过的系统上整个引擎都起不来）。
        for (p, m) in BASE_REVEALS.iter().chain(BASE_UNIVERSE_REVEALS.iter()) {
            let path = Path::new(p);
            if path.exists() {
                push_reveal(&mut reveals, path, m);
            }
        }
        // ② 解释器/库：只读 + 可执行（`ld.so` 装载共享库要读，二进制要 x）。
        for r in interp_roots {
            push_reveal(&mut reveals, r, "rx");
        }
        // ③ 将被 exec 的程序自身（可能在 interp_roots 之外，如 /usr/local/sbin）。
        if let Some(b) = bin {
            push_reveal(&mut reveals, b, "rx");
        }
        // ④ 应用自己的三块：docroot（默认只读+建文件）、状态目录、临时目录。
        if let Some(d) = docroot {
            push_reveal(&mut reveals, d, doc_perms);
        }
        if let Some(s) = state_dir {
            push_reveal(&mut reveals, s, "rwxc");
        }
        if let Some(t) = tmp_dir {
            push_reveal(&mut reveals, t, "rwxc");
        }
        // ⑤ 配置里显式追加的路径。
        for raw in &cfg.extra_unveil {
            if let Some((p, m)) = raw.split_once(':') {
                let (p, m) = (p.trim(), m.trim());
                if !p.is_empty() && !m.is_empty() {
                    push_reveal(&mut reveals, Path::new(p), m);
                }
            }
        }
    }

    // pledge：`pledge = "none"` 明确表示「只 unveil 不 pledge」；沙箱关闭时一律不给。
    let pledge = if !cfg.enabled {
        None
    } else {
        match cfg.pledge.as_deref().map(str::trim) {
            Some("none") | Some("off") | Some("-") => None,
            Some(other) if !other.is_empty() => Some(other.to_string()),
            _ => engine_pledge(engine, cfg.allow_exec).map(|s| {
                // **按整词**判断是否已有 `exec`：`prot_exec` 里含 `exec` 子串，
                // 用 `contains("exec")` 会误判成「已给 exec」而**少给一个承诺**
                //（本文件单测 `exec_and_pledge_overrides` 抓到的真实 bug）。
                let has_exec = s.split_whitespace().any(|tok| tok == "exec");
                if cfg.allow_exec && !has_exec {
                    format!("{s} exec")
                } else {
                    s.to_string()
                }
            }),
        }
    };

    SandboxSpec {
        enabled: cfg.enabled,
        engine_hint: engine.to_string(),
        reveals,
        pledge,
        // 默认：孩子不能再 exec（`pledge_exec` 为空串）。这是「RCE 拿不到 shell」
        // 的关键一半 —— 即使引擎自己需要 exec（allow_exec），孩子也不再继承。
        pledge_exec: cfg.pledge_exec.clone().unwrap_or_default(),
        // `chroot = "docroot"` 是哨兵：解析成**真实** docroot 路径再交给 pre_exec
        // （直接 chroot("docroot") 是相对路径，必然失败 → _exit(127) → 引擎起不来）。
        // PHP-FPM 不走这条：它用池级 `chroot =` 指令只关 **worker**（master 需要读
        // conf/pid/log，不能被 chroot），php.rs 传下来的 cfg 已把 chroot 清空。
        chroot: match cfg.chroot.as_deref().map(str::trim) {
            Some("docroot") | Some("app") => docroot.map(|d| d.to_path_buf()),
            Some("") | None | Some("none") | Some("off") => None,
            Some(other) => Some(PathBuf::from(other)),
        },
        chdir: None,
    }
}

/// 去重 + 保序地加一条揭示（多次揭示父目录与子目录时，OpenBSD 允许，但保留最短的
/// 集合更易读；这里只做**完全相同路径**的去重，不尝试做路径包含分析 —— 那会把
/// 「父目录 r + 子目录 rwc」这种**必要**的组合误合并掉）。
fn push_reveal(out: &mut Vec<Reveal>, path: &Path, perms: &str) {
    if let Some(slot) = out.iter_mut().find(|r| r.path == path) {
        // 同路径取权限并集（`rxc` 与 `rwc` ⇒ `rwxc`），并规范化顺序便于对比/日志。
        let mut set: Vec<char> = slot.perms.chars().collect();
        for c in perms.chars() {
            if !set.contains(&c) {
                set.push(c);
            }
        }
        slot.perms = canonical_perms(&set);
        return;
    }
    out.push(Reveal {
        path: path.to_path_buf(),
        perms: canonical_perms(&perms.chars().collect::<Vec<_>>()),
    });
}

/// 权限位规范化：固定按 `r`,`w`,`x`,`c` 顺序输出（unveil 不看顺序，只为可读/可比）。
fn canonical_perms(set: &[char]) -> String {
    let mut out = String::new();
    for c in ['r', 'w', 'x', 'c'] {
        if set.contains(&c) {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SandboxConfig {
        SandboxConfig::default()
    }

    /// 默认策略必须：docroot 只读、state/tmp 可写、expl 不含 `exec`。
    #[test]
    fn default_php_profile_is_least_privilege() {
        let spec = build_spec(
            "php",
            Some(Path::new("/srv/app/php")),
            Some(Path::new("/srv/state/php")),
            Some(Path::new("/srv/state/php/tmp/9095-0")),
            &[PathBuf::from("/usr/lib")],
            Some(Path::new("/usr/local/sbin/php-fpm-8.5")),
            &cfg(),
        );
        assert!(spec.enabled);
        let doc = spec
            .reveals
            .iter()
            .find(|r| r.path == Path::new("/srv/app/php"))
            .expect("docroot 必须被揭示");
        assert_eq!(doc.perms, "rx", "默认 docroot 连 create 都不给（webshell 落不下来）");
        let st = spec
            .reveals
            .iter()
            .find(|r| r.path == Path::new("/srv/state/php"))
            .expect("state 必须被揭示");
        assert_eq!(st.perms, "rwxc");
        let tmp = spec
            .reveals
            .iter()
            .find(|r| r.path == Path::new("/srv/state/php/tmp/9095-0"))
            .expect("每应用 tmp 必须被揭示");
        assert_eq!(tmp.perms, "rwxc");

        let p = spec.pledge.as_deref().expect("php 默认应给 pledge");
        assert!(p.contains("rpath") && p.contains("unix") && p.contains("inet"));
        assert!(!p.split(' ').any(|x| x == "exec"), "默认不许引擎自己 exec: {p}");
        assert!(!p.contains("chown"), "不该给改属主的能力: {p}");
        assert_eq!(spec.pledge_exec, "", "孩子进程默认不能再 exec");
    }

    /// `docroot_rw = true` 才给 `w`（上传类应用需要）。
    #[test]
    fn docroot_rw_opt_in() {
        let c = SandboxConfig {
            docroot_rw: true,
            ..cfg()
        };
        let spec = build_spec(
            "php",
            Some(Path::new("/srv/app")),
            None,
            None,
            &[],
            None,
            &c,
        );
        let doc = spec.reveals.iter().find(|r| r.path == Path::new("/srv/app")).unwrap();
        assert_eq!(doc.perms, "rwxc");
    }

    /// `allow_exec` 只加 `exec`，不动其它承诺；`pledge = "none"` 则完全不 pledge。
    #[test]
    fn exec_and_pledge_overrides() {
        let c = SandboxConfig {
            allow_exec: true,
            ..cfg()
        };
        let p = build_spec("cgi", None, None, None, &[], None, &c)
            .pledge
            .unwrap();
        assert!(p.split(' ').any(|x| x == "exec"), "{p}");

        let c = SandboxConfig {
            pledge: Some("none".into()),
            ..cfg()
        };
        let spec = build_spec("php", None, None, None, &[], None, &c);
        assert!(spec.pledge.is_none(), "pledge=none 应只 unveil 不 pledge");
        assert!(spec.enabled, "unveil 仍然生效");
    }

    /// 未知引擎**不猜**承诺集（只 unveil）：猜错会把引擎打成起不来。
    #[test]
    fn unknown_engine_gets_no_pledge() {
        let spec = build_spec("weird-engine", None, None, None, &[], None, &cfg());
        assert!(spec.pledge.is_none());
        assert!(spec.enabled);
    }

    /// `enabled = false` 时既不揭示也不 pledge（干净的 no-op）。
    #[test]
    fn disabled_is_noop() {
        let c = SandboxConfig {
            enabled: false,
            ..cfg()
        };
        let spec = build_spec(
            "php",
            Some(Path::new("/srv/app")),
            Some(Path::new("/srv/state")),
            None,
            &[PathBuf::from("/usr/lib")],
            None,
            &c,
        );
        assert!(!spec.enabled);
        assert!(spec.reveals.is_empty());
        assert!(spec.pledge.is_none());
    }

    /// 配置里 `extra_unveil = "/p:rwc"` 追加；同路径合并权限；坏格式忽略。
    #[test]
    fn extra_unveil_parsed_and_merged() {
        let c = SandboxConfig {
            extra_unveil: vec![
                "/srv/app:rwc".into(), // 与 docroot 同路径 ⇒ 权限并集
                "/srv/shared:r".into(),
                "bad-format".into(),
                ":/x".into(),
            ],
            ..cfg()
        };
        let spec = build_spec("php", Some(Path::new("/srv/app")), None, None, &[], None, &c);
        let app = spec.reveals.iter().find(|r| r.path == Path::new("/srv/app")).unwrap();
        assert_eq!(app.perms, "rwxc", "同路径取并集");
        assert!(spec.reveals.iter().any(|r| r.path == Path::new("/srv/shared")));
        assert_eq!(spec.reveals.len(), 2 + BASE_reveals_existing().len());
    }

    /// 只统计**本机真实存在**的基础揭示项（不同系统上 /etc/ssl 等可能不存在）。
    fn BASE_reveals_existing() -> Vec<PathBuf> {
        BASE_REVEALS
            .iter()
            .chain(BASE_UNIVERSE_REVEALS.iter())
            .map(|(p, _)| PathBuf::from(p))
            .filter(|p| p.exists())
            .collect()
    }

    /// chroot 字段透传（php 用 "docroot" 哨兵，在 php.rs 里解析成真实路径）。
    #[test]
    fn chroot_passthrough() {
        let c = SandboxConfig {
            chroot: Some("/srv/app".into()),
            ..cfg()
        };
        let spec = build_spec("php", None, None, None, &[], None, &c);
        assert_eq!(spec.chroot.as_deref(), Some(Path::new("/srv/app")));
    }

    /// 引擎族 → pledge 表的关键差异（php 有 prot_exec，go 没有解释器项）。
    #[test]
    fn engine_pledge_table() {
        let php = engine_pledge("php", false).unwrap();
        assert!(php.contains("prot_exec"));
        let go = engine_pledge("go", false).unwrap();
        assert!(!go.contains("getpw"));
        assert!(engine_pledge("unknown", false).is_none());
    }

    /// PHP 版本目录推导：`php-fpm-8.5` ⇒ 尝试 /etc/php-8.5。
    #[test]
    fn php_version_dirs() {
        let roots = php_interp_roots(Path::new("/usr/local/sbin/php-fpm-8.5"));
        assert!(roots.iter().any(|p| p == Path::new("/usr/local/sbin")));
        assert!(roots.iter().any(|p| p == Path::new("/usr/lib")));
    }
}

/// 引擎带着跑的**运行时资产**目录（不是解释器本身，而是它启动时会去读/执行的文件）。
///
/// 这些是解释器进程**启动期**就要打开的东西 —— unveil 挡住 ⇒ 引擎起不来，而日志面上
/// 通常只看到「sidecar 未就绪」，很难从现象反推到「jar 不可见」。按引擎族补：
/// * `jsp`/`do`：`java -jar .../libs/jsp-sidecar/target/jsp-sidecar.jar`
/// * `go`：`go-shm-server` 位于 `target/app-engines/`
///
/// 不存在的路径自动跳过（揭示不存在的路径本身不会失败，但漏掉真实存在的就会 fail-closed）。
pub fn engine_artifact_roots(engine: &str, _cwd_is_crucible: bool) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = Vec::new();
    let mut push = |r: &str| {
        let p = PathBuf::from(r);
        if p.exists() {
            roots.push(p);
        }
    };
    match engine {
        "jsp" | "do" => {
            push("/crucible/libs/jsp-sidecar/target");
            push("/crucible/libs/jsp-sidecar");
        }
        "go" => {
            push("/crucible/target/app-engines");
        }
        _ => {}
    }
    roots
}
