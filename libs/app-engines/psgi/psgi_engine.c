/*
 * PSGI app-engine —— 进程内嵌入 Perl（静态嵌入，无每请求 spawn）。
 *
 * 旧实现：把 runner 写到 /tmp 再 popen("perl runner")（每请求 spawn 解释器，spec
 * 明令禁止），失败即 appengine_fill_hello（假成功）。本机（OpenBSD）已装 perl 且
 * CORE 头文件在 /usr/libdata/perl5/amd64-openbsd/CORE/perl.h、库在
 * /usr/lib/libperl.so.27.0，因此嵌入在原理上可行。
 *
 * 现状（务必读）：
 *   - 默认构建**不**定义 CRUCIBLE_HAVE_PERL：build_app_engines.sh 不做 perl 探测
 *     （该脚本不在本目录的改动范围内），既没有 -I CORE 也没有 -lperl；而 app_ffi 用
 *     dlopen(RTLD_NOW|RTLD_GLOBAL) 加载引擎，直接引用 perl_* 链接期符号会让 .so
 *     加载期就失败。此时本引擎返回显式错误 "not built with embedded Perl"，
 *     绝不 spawn、绝不假 hello。
 *   - 定义 CRUCIBLE_HAVE_PERL 才编译下面的真实嵌入代码。启用方式（属于本目录之外
 *     的构建脚本改动）：
 *         CFLAGS += $(perl -MExtUtils::Embed -e ccopts) -DCRUCIBLE_HAVE_PERL
 *         LIBS   += $(perl -MExtUtils::Embed -e ldopts)     # 必须带 -lperl，
 *                                                          # 使 .so 带 DT_NEEDED
 *     并把 psgi 从 build_stub_engine 的通用命令里单独拿出来。
 *   - 该嵌入路径**未在目标机编译/运行验证**：此处没有 OpenBSD 工具链、无法确认该
 *     perl 是否带 PERL_IMPLICIT_CONTEXT（线程化 perl 的调用约定随 my_perl 变化，
 *     perl.h 的宏会据此自动处理，但未实测），也无法跑 PSGI 冒烟测试。启用前必须先
 *     编译并通过冒烟测试。
 *   - 不调用 perl_destruct/perl_free：解释器随进程常驻（与 pyembed 同一约定，
 *     避免在任意线程里销毁解释器）。
 */
#include "appengine.h"
#include "appengine_common.h"
#include "crucible_embed.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifndef _WIN32
#include <pthread.h>
static pthread_mutex_t g_psgi_lock = PTHREAD_MUTEX_INITIALIZER;
#define PSGI_LOCK()   pthread_mutex_lock(&g_psgi_lock)
#define PSGI_UNLOCK() pthread_mutex_unlock(&g_psgi_lock)
#else
#define PSGI_LOCK()   ((void)0)
#define PSGI_UNLOCK() ((void)0)
#endif

static int g_inited;

/* 引擎级失败：填 out->error 并返回 -1（app_ffi 会把它变成 502 文本）。 */
static int crucible_err(AppEngineResult *out, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;

    if (out == NULL)
        return -1;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    appengine_result_alloc(out);
    appengine_result_set_error(out, buf);
    return -1;
}

static int is_regular_file(const char *p)
{
    struct stat st;

    return p != NULL && p[0] != '\0' && stat(p, &st) == 0 && S_ISREG(st.st_mode);
}

/* 脚本解析：显式 script → docroot/index.psgi → docroot/app.psgi → docroot/index.pl。 */
static const char *resolve_script(const char *script, const char *docroot, char *out,
                                  size_t outsz)
{
    if (is_regular_file(script)) {
        snprintf(out, outsz, "%s", script);
        return out;
    }
    if (docroot != NULL && docroot[0] != '\0') {
        snprintf(out, outsz, "%s/index.psgi", docroot);
        if (is_regular_file(out))
            return out;
        snprintf(out, outsz, "%s/app.psgi", docroot);
        if (is_regular_file(out))
            return out;
        snprintf(out, outsz, "%s/index.pl", docroot);
        if (is_regular_file(out))
            return out;
    }
    return NULL;
}

#ifdef CRUCIBLE_HAVE_PERL

#include <EXTERN.h>
#include <perl.h>

/* perl.h 的嵌入 API 宏（aTHX 等）要求解释器变量就叫 my_perl。 */
static PerlInterpreter *my_perl;

/* 请求值经私有包哈希传入，不用 %ENV：不污染进程环境，也不与 Rust 侧 env_lock 竞争。 */
#define PSGI_REQ_HV "Crucible::req"
#define PSGI_RES_HV "Crucible::res"

/*
 * 应用加载 + 调用 + body 捕获都在**同进程内**的 Perl 里完成（eval_pv），C 侧只做：
 *   1) 请求值塞进 %Crucible::req；
 *   2) eval_pv 驱动片段（返回 body 字符串；status/headers 落 %Crucible::res）；
 *   3) 读回 %Crucible::res 组装响应头。
 * 驱动片段每请求重新编译（约 1.5KB，百微秒级），换来的是不必在 C 里做 AV/HV 栈宏。
 */
/*
 * 驱动片段（同进程内 eval_pv 执行，不是 spawn）。
 * 注意 $S 的处理：相对路径补 "./" —— Perl 5.26 起 @INC 不再含 '.'，`do` 相对路径
 * 会直接失败，而 docroot 拼出来的正是相对路径。$S 只作为**值**参与拼接，不进代码。
 * 应用加载 + 调用 + body 捕获都在 Perl 里完成，C 侧只读回 %Crucible::res 与 body。
 * 驱动片段每请求重新编译（约 1.5KB，百微秒级），换来的是不必在 C 里做 AV/HV 栈宏。
 */
static const char *psgi_driver =
    "do {\n"
    "    my $S = $Crucible::req{script};\n"
    "    my $mt = (stat($S))[9];\n"
    "    if (!defined $Crucible::app || !defined $Crucible::app_mtime\n"
    "        || $Crucible::app_mtime ne $mt) {\n"
    "        my $p = ($S =~ m{^/}) ? $S : \"./$S\";\n"
    "        my $a = do $p;\n"
    "        die $@ if $@;\n"
    "        die \"psgi: 无法读取 $S: $!\\n\" unless defined($a) || -e $S;\n"
    "        $a = \\&main::app if ref($a) ne 'CODE' && defined(&main::app);\n"
    "        $a = \\&main::application\n"
    "            if ref($a) ne 'CODE' && defined(&main::application);\n"
    "        die \"psgi: $S 未返回 PSGI 应用（CODE ref）\\n\"\n"
    "            unless ref($a) eq 'CODE';\n"
    "        $Crucible::app = $a;\n"
    "        $Crucible::app_mtime = $mt;\n"
    "    }\n"
    "    my $env = {\n"
    "        REQUEST_METHOD => $Crucible::req{method},\n"
    "        PATH_INFO => $Crucible::req{path},\n"
    "        QUERY_STRING => $Crucible::req{query},\n"
    "        CONTENT_TYPE => $Crucible::req{content_type},\n"
    "        CONTENT_LENGTH => $Crucible::req{content_length},\n"
    "        SERVER_NAME => $Crucible::req{server_name},\n"
    "        SERVER_PORT => $Crucible::req{server_port},\n"
    "        SERVER_PROTOCOL => 'HTTP/1.1',\n"
    "        REMOTE_ADDR => $Crucible::req{remote},\n"
    "        'psgi.version' => [1, 1],\n"
    "        'psgi.url_scheme' => 'http',\n"
    "        'psgi.multithread' => 0,\n"
    "        'psgi.multiprocess' => 0,\n"
    "        'psgi.run_once' => 0,\n"
    "        'psgi.input' => do { open my $in, '<', \\$Crucible::req{body}; $in },\n"
    "        'psgi.errors' => \\*STDERR,\n"
    "    };\n"
    "    my $r = $Crucible::app->($env);\n"
    "    die \"psgi: 应用未返回 [status, headers, body] 数组引用\\n\"\n"
    "        unless ref($r) eq 'ARRAY';\n"
    "    $Crucible::res{status} = $r->[0];\n"
    "    $Crucible::res{headers} = $r->[1];\n"
    "    my $body = $r->[2];\n"
    "    open my $out, '>', \\(my $buf = '');\n"
    "    my $old = select $out;\n"
    "    if (ref($body) eq 'ARRAY') { print join('', @$body); }\n"
    "    elsif (ref($body)) { while (defined(my $c = $body->getline)) { print $c; } }\n"
    "    elsif (defined($body)) { print $body; }\n"
    "    select $old;\n"
    "    $buf;\n"
    "}";

/* 一次 Perl 初始化：PERL_SYS_INIT3 + perl_alloc + perl_construct + perl_parse。
 * "-e 0"：不作为脚本运行——PSGI 应用由驱动片段的 do $script 加载。 */
static int perl_ensure_locked(char *err, size_t errsz)
{
    static char *embedding[] = {"", "-e", "0"};
    int argc = 3;
    char **argv = embedding;
    char **env = NULL;

    if (my_perl != NULL)
        return 0;
    PERL_SYS_INIT3(&argc, &argv, &env);
    my_perl = perl_alloc();
    if (my_perl == NULL) {
        snprintf(err, errsz, "perl_alloc 失败");
        return -1;
    }
    perl_construct(my_perl);
    if (perl_parse(my_perl, NULL, 3, embedding, NULL) != 0) {
        snprintf(err, errsz, "perl_parse(-e 0) 失败");
        my_perl = NULL;
        return -1;
    }
    (void)perl_run(my_perl);
    return 0;
}

static void psgi_hv_put(HV *hv, const char *key, const char *val)
{
    if (hv == NULL || key == NULL)
        return;
    (void)hv_store(hv, key, (I32)strlen(key), newSVpv(val != NULL ? val : "", 0), 0);
}

/* 请求头块（PSGI 头可为 arrayref [k,v,...] 或 hashref）写入 out。 */
static void psgi_emit_headers(crucible_buf *out, SV *hsv)
{
    SV *inner;

    if (out == NULL || hsv == NULL || !SvROK(hsv))
        return;
    inner = SvRV(hsv);
    if (SvTYPE(inner) == SVt_PVAV) {
        AV *av = (AV *)inner;
        SSize_t i, n = av_len(av);

        for (i = 0; i + 1 <= n; i += 2) {
            SV **kp = av_fetch(av, i, 0);
            SV **vp = av_fetch(av, i + 1, 0);
            STRLEN klen = 0, vlen = 0;
            char *k, *v;

            if (kp == NULL || vp == NULL)
                continue;
            k = SvPV(*kp, klen);
            v = SvPV(*vp, vlen);
            if (k != NULL && klen > 0) {
                (void)crucible_buf_append(out, k, (size_t)klen);
                (void)crucible_buf_puts(out, ": ");
                (void)crucible_buf_append(out, v != NULL ? v : "", (size_t)vlen);
                (void)crucible_buf_puts(out, "\r\n");
            }
        }
        return;
    }
    if (SvTYPE(inner) == SVt_PVHV) {
        HV *hv = (HV *)inner;
        HE *he;

        (void)hv_iterinit(hv);
        while ((he = hv_iternext(hv)) != NULL) {
            STRLEN klen = 0, vlen = 0;
            char *k = hv_iterkey(he, &klen);
            char *v = SvPV(hv_iterval(hv, he), vlen);

            if (k != NULL && klen > 0) {
                (void)crucible_buf_append(out, k, (size_t)klen);
                (void)crucible_buf_puts(out, ": ");
                (void)crucible_buf_append(out, v != NULL ? v : "", (size_t)vlen);
                (void)crucible_buf_puts(out, "\r\n");
            }
        }
    }
}

/* 一次 PSGI 请求：0 = out 已填（应用异常 → 500 + 错误文本）；-1 = 显式引擎失败。 */
static int psgi_request(const char *script, const char *method, const char *path,
                        const char *query, const char *content_type, const char *body,
                        size_t body_len, const char *remote, const char *server_name,
                        int server_port, AppEngineResult *out)
{
    crucible_buf hb;
    char errbuf[1024];
    char portbuf[16];
    char lenbuf[32];
    SV *driver_ret;
    HV *req, *res;

    memset(&hb, 0, sizeof(hb));
    PSGI_LOCK();
    if (perl_ensure_locked(errbuf, sizeof(errbuf)) != 0) {
        PSGI_UNLOCK();
        return crucible_err(out, "psgi: 嵌入式 Perl 不可用: %s", errbuf);
    }
    req = get_hv(PSGI_REQ_HV, GV_ADD);
    res = get_hv(PSGI_RES_HV, GV_ADD);
    if (req == NULL || res == NULL) {
        PSGI_UNLOCK();
        return crucible_err(out, "psgi: 无法创建 %s / %s", PSGI_REQ_HV, PSGI_RES_HV);
    }
    (void)hv_clear(res);
    (void)hv_clear(req);
    snprintf(portbuf, sizeof(portbuf), "%d", server_port > 0 ? server_port : 80);
    snprintf(lenbuf, sizeof(lenbuf), "%lu", (unsigned long)body_len);
    psgi_hv_put(req, "script", script);
    psgi_hv_put(req, "method", method != NULL ? method : "GET");
    psgi_hv_put(req, "path", path != NULL ? path : "/");
    psgi_hv_put(req, "query", query != NULL ? query : "");
    psgi_hv_put(req, "content_type", content_type != NULL ? content_type : "");
    psgi_hv_put(req, "content_length", lenbuf);
    psgi_hv_put(req, "remote", remote != NULL ? remote : "");
    psgi_hv_put(req, "server_name",
                server_name != NULL && server_name[0] != '\0' ? server_name : "crucible");
    psgi_hv_put(req, "server_port", portbuf);
    psgi_hv_put(req, "body", body != NULL ? body : "");

    driver_ret = eval_pv(psgi_driver, 0);
    if (driver_ret == NULL || SvTRUE(ERRSV)) {
        STRLEN elen = 0;
        char *emsg = SvPV(ERRSV, elen);
        char *trace = NULL;

        if (emsg != NULL && elen > 0) {
            trace = (char *)malloc((size_t)elen + 1);
            if (trace != NULL) {
                memcpy(trace, emsg, (size_t)elen);
                trace[elen] = '\0';
            }
        }
        if (appengine_result_alloc(out) != 0) {
            free(trace);
            PSGI_UNLOCK();
            return -1;
        }
        /* 应用/脚本错误 → 500 + Perl 错误文本（引擎可用，故不是 rc != 0）。 */
        out->status = 500;
        appengine_result_set_headers(out,
                                     "Content-Type: text/plain; charset=utf-8\r\n");
        appengine_result_set_body(out, trace != NULL ? trace : "psgi error",
                                  trace != NULL ? strlen(trace) : 10);
        appengine_result_set_error(out, trace != NULL ? trace : "psgi error");
        free(trace);
        PSGI_UNLOCK();
        crucible_buf_free(&hb);
        return 0;
    }
    {
        STRLEN blen = 0;
        char *bstr = SvPV(driver_ret, blen);
        SV **svp;

        svp = hv_fetch(res, "headers", 7, 0);
        if (svp != NULL)
            psgi_emit_headers(&hb, *svp);
        svp = hv_fetch(res, "status", 6, 0);
        if (appengine_result_alloc(out) != 0) {
            PSGI_UNLOCK();
            crucible_buf_free(&hb);
            return -1;
        }
        out->status = svp != NULL && SvOK(*svp) ? (int)SvIV(*svp) : 200;
        if (out->status < 100 || out->status > 599)
            out->status = 200;
        if (hb.len == 0)
            (void)crucible_buf_puts(&hb, "Content-Type: text/plain; charset=utf-8\r\n");
        appengine_result_set_headers(out, hb.p != NULL ? hb.p : "");
        appengine_result_set_body(out, bstr != NULL ? bstr : "", (size_t)blen);
    }
    PSGI_UNLOCK();
    crucible_buf_free(&hb);
    return 0;
}

#endif /* CRUCIBLE_HAVE_PERL */

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    (void)lib_hint;
    g_inited = 1;
#ifndef CRUCIBLE_HAVE_PERL
    fprintf(stderr,
            "libapp_psgi: 构建时未嵌入 Perl（缺 -DCRUCIBLE_HAVE_PERL）；perl 嵌入需 "
            "CORE 头文件与 -lperl，见 psgi_engine.c 文件头\n");
#endif
    return 0;
}

int appengine_execute(
    const char *script,
    const char *docroot,
    const char *method,
    const char *path,
    const char *query,
    const char *content_type,
    const char *body,
    size_t body_len,
    const char *remote,
    const char *server_name,
    int server_port,
    const char *extra,
    AppEngineResult *out)
{
    char pathbuf[1024];
    const char *use;

    (void)extra; /* .env 变量由 Rust 侧注入进程环境；嵌入式解释器继承同一进程环境 */

    if (!g_inited || out == NULL)
        return -1;

#ifdef CRUCIBLE_HAVE_PERL
    use = resolve_script(script, docroot, pathbuf, sizeof(pathbuf));
    if (use == NULL)
        return crucible_err(out,
                            "psgi: 未找到 PSGI 脚本（script=%s docroot=%s，尝试过 "
                            "index.psgi / app.psgi / index.pl）",
                            script != NULL ? script : "(null)",
                            docroot != NULL ? docroot : "(null)");
    return psgi_request(use, method, path, query, content_type, body, body_len, remote,
                        server_name, server_port, out);
#else
    (void)script;
    (void)docroot;
    (void)method;
    (void)path;
    (void)query;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    /*
     * 显式失败：不 spawn、不假装成功。
     * 本机 perl 与 CORE 头文件确实存在
     * （/usr/libdata/perl5/amd64-openbsd/CORE/perl.h、/usr/lib/libperl.so.27.0），
     * 所以这是构建配置缺口，不是平台限制。
     */
    return crucible_err(out,
                        "psgi: 本引擎构建时未嵌入 Perl（not built with embedded Perl）。"
                        "需要 perl -MExtUtils::Embed -e ccopts / -e ldopts（-I CORE 与 "
                        "-lperl）并定义 -DCRUCIBLE_HAVE_PERL 重新构建 libapp_psgi.so；"
                        "psgi 禁止每请求 spawn 解释器，故不回退到 popen");
#endif
}

void appengine_shutdown(void)
{
    g_inited = 0;
    /* 不 perl_destruct/perl_free：解释器随进程常驻（见文件头）。 */
}
