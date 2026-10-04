/*
 * Rack app-engine —— 进程内嵌入 MRI Ruby（静态嵌入，无每请求 spawn）。
 *
 * 旧实现：写 Ruby runner 到 /tmp 再 popen("ruby runner")——每请求 spawn 解释器
 * （spec §7.3 明令禁止：Ruby 必须嵌入），而且失败即 appengine_fill_hello（假成功）。
 * 现在：解释器在进程内初始化一次（ruby_init / ruby_init_loadpath，只做一次），
 * 之后每请求在**同一线程**里构造 Rack env → 调 app.call(env) → 收集
 * [status, headers, body]（body 二进制安全，上限 32MiB，超限截断并标注）。
 *
 * 线程模型：MRI 必须串行进入同一 VM（app_ffi 已给 rack 配了单线程池，本引擎再用
 * pthread_mutex 兜底），所以不需要 GVL 穿越；不调用 ruby_cleanup —— 解释器随进程
 * 常驻（与 pyembed/psgi 同一约定），且 dlclose 卸载引擎 .so 时有 RTLD_NODELETE
 * 钉住 libruby，避免把仍在跑定时器线程的 libruby 解除映射（见 rack_pin_libruby）。
 *
 * rack gem 取舍：宿主装了 rack 就 require 并用真正的 Rack::Builder.parse_file；
 * 没装（或真 Builder 处理不了「裸 lambda」config.ru）时用编进 .so 的最小兼容层
 * rack_shim.rb（run/use/map 子集 + 裸 lambda 入口）——目标机可能没有网络装 gem，
 * 内置层保证 .ru 应用仍能真正服务，绝不 spawn、不返回假 hello。
 *
 * 失败语义：脚本缺失 / Ruby 初始化失败 / 应用（或加载）抛异常 → rc != 0 且细节
 * （异常消息 + traceback）只写进 out->error（Rust 侧节流记日志）；客户端拿到的是
 * app_ffi 统一生成的固定 502 文本，绝不回显绝对路径或堆栈。
 *
 * 构建：scripts/build_script_ffi.sh 的 detect_ruby 探测到 ruby.h（OpenBSD:
 * /usr/local/include/ruby-3.4，库 -lruby34）后以 -DCRUCIBLE_HAVE_RUBY 重编本文件；
 * 未定义宏时保留「未嵌入 Ruby」的诚实失败文本（语义不变）。另外这里做了一次
 * 编译期兜底：若构建脚本因参数拼接问题漏掉 -D 但 -I 里确实有 ruby.h（目标机
 * 现状），自动启用嵌入，避免引擎永远停在诚实失败。
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <pthread.h>
#endif

/*
 * 编译期兜底：__has_include 需要编译器支持（gcc/clang 均有）。
 * 只有 ruby.h 真的在 include 路径里（= 构建脚本已把 -I 传进来）才启用；
 * 此时 .so 也带 -lruby34（见 build_script_ffi.sh 的 RB_LIBS）。
 */
#if !defined(CRUCIBLE_HAVE_RUBY) && defined(__has_include)
#  if __has_include(<ruby.h>)
#    define CRUCIBLE_HAVE_RUBY 1
#    define CRUCIBLE_HAVE_RUBY_AUTO 1
#  endif
#endif

#ifdef CRUCIBLE_HAVE_RUBY
#include <ruby.h>
#include <ruby/version.h> /* ruby_version[]（Ruby 3.4 起 RUBY_VERSION 宏不再进 C 头） */
#ifndef _WIN32
#include <dlfcn.h>
#include <pthread.h>
#endif
/* 由 gen_rack_shim_header.py 从 rack_shim.rb 生成（编进 .so，不落盘、不写 /tmp）。 */
#include "rack_shim_rb.h"

/* MRI 必须串行进入同一 VM（app_ffi 已给 rack 配单线程池，这里再兜底一层）。 */
#ifndef _WIN32
static pthread_mutex_t g_rack_lock = PTHREAD_MUTEX_INITIALIZER;
#define RACK_LOCK()   pthread_mutex_lock(&g_rack_lock)
#define RACK_UNLOCK() pthread_mutex_unlock(&g_rack_lock)
#else
#define RACK_LOCK()   ((void)0)
#define RACK_UNLOCK() ((void)0)
#endif
#endif /* CRUCIBLE_HAVE_RUBY */

static int g_inited;

/* 引擎级失败：填 out->error 并返回 -1（app_ffi 会把它变成 502 固定文本）。 */
static int rack_fail(AppEngineResult *out, const char *fmt, ...)
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

/* 脚本解析：显式 script → docroot/config.ru → docroot/index.ru → docroot/app.rb。 */
static const char *resolve_script(const char *script, const char *docroot, char *out,
                                  size_t outsz)
{
    if (is_regular_file(script)) {
        snprintf(out, outsz, "%s", script);
        return out;
    }
    if (docroot != NULL && docroot[0] != '\0') {
        snprintf(out, outsz, "%s/config.ru", docroot);
        if (is_regular_file(out))
            return out;
        snprintf(out, outsz, "%s/index.ru", docroot);
        if (is_regular_file(out))
            return out;
        snprintf(out, outsz, "%s/app.rb", docroot);
        if (is_regular_file(out))
            return out;
    }
    return NULL;
}

#ifdef CRUCIBLE_HAVE_RUBY

static int g_ruby_ready;
static void *g_libruby_pin; /* RTLD_NODELETE 句柄，故意不 dlclose */

/* 把当前 Ruby 异常（rb_errinfo / $!）格式化成多行文本；格式化本身失败时写 fallback。 */
static void rack_capture_error(char *buf, size_t cap, const char *fallback)
{
    static const char fmt[] =
        "begin\n"
        "  e = $crucible_err\n"
        "  if e.is_a?(Exception)\n"
        "    bt = e.backtrace || []\n"
        "    bt = bt.first(20) if bt.respond_to?(:first)\n"
        "    \"#{e.class}: #{e.message}\\n#{bt.join(\"\\n\")}\"\n"
        "  else\n"
        "    e.to_s\n"
        "  end\n"
        "rescue Exception => x\n"
        "  \"ruby error: #{x.class}: #{x.message}\"\n"
        "end";
    int state = 0;
    VALUE s;

    if (cap == 0)
        return;
    rb_gv_set("$crucible_err", rb_errinfo());
    s = rb_eval_string_protect(fmt, &state);
    if (state != 0 || !RB_TYPE_P(s, T_STRING)) {
        snprintf(buf, cap, "%s", fallback);
        return;
    }
    {
        long n = RSTRING_LEN(s);

        if (n < 0)
            n = 0;
        if ((size_t)n >= cap)
            n = (long)cap - 1;
        memcpy(buf, RSTRING_PTR(s), (size_t)n);
        buf[n] = '\0';
    }
    if (buf[0] == '\0')
        snprintf(buf, cap, "%s", fallback);
}

/*
 * 钉住 libruby：app_ffi 热卸载引擎时会 dlclose(libapp_rack.so)，libruby34 是它的
 * DT_NEEDED，若引用计数归零就会被解除映射——而 MRI 的定时器线程还活在 libruby 里，
 * 之后必 SIGSEGV。RTLD_NODELETE 让映射常驻（本引擎自己从不关闭这个句柄）。
 * 拿名字用 RbConfig::CONFIG['LIBRUBY_SO']（OpenBSD: libruby34.so.0.0），失败给候补。
 */
static void rack_pin_libruby(void)
{
#ifdef RTLD_NODELETE
    char soname[128];
    const char *cands[6];
    int n = 0;
    int state = 0;
    int i;
    VALUE v;

    v = rb_eval_string_protect(
        "(defined?(RbConfig) ? RbConfig::CONFIG['LIBRUBY_SO'] : nil).to_s", &state);
    if (state == 0 && RB_TYPE_P(v, T_STRING)) {
        long len = RSTRING_LEN(v);

        if (len > 0 && (size_t)len < sizeof(soname)) {
            memcpy(soname, RSTRING_PTR(v), (size_t)len);
            soname[len] = '\0';
            cands[n++] = soname;
        }
    }
    cands[n++] = "libruby34.so.0.0";
    cands[n++] = "libruby34.so";
    cands[n++] = "libruby.so.3.4";
    cands[n++] = "libruby.so";
    cands[n++] = "/usr/local/lib/libruby34.so.0.0";
    for (i = 0; i < n; i++) {
        void *h = dlopen(cands[i], RTLD_NOW | RTLD_GLOBAL | RTLD_NODELETE);

        if (h != NULL) {
            g_libruby_pin = h;
            return;
        }
    }
#else
    (void)g_libruby_pin;
#endif
}

/* 一次初始化：ruby_init / ruby_init_loadpath / ruby_options + 载入 shim
 *（含 try require 'rack'）。必须持有 g_rack_lock。 */
static int rack_ruby_ensure_locked(char *err, size_t errsz)
{
    int state = 0;
    VALUE v;

    if (g_ruby_ready)
        return 0;
    /* RUBY_INIT_STACK：本线程是 app_ffi 的池线程（不是进程 main 线程），
     * 不标记栈底会让 GC 的保守扫描/栈深检查拿到错误的边界。 */
#ifdef RUBY_INIT_STACK
    RUBY_INIT_STACK;
#endif
    ruby_init();
    ruby_init_loadpath();
    /*
     * 完整启动解释器。**只调 ruby_init 是不够的**：Ruby 3.4（OpenBSD ruby34，Prism
     * 解析器）下这种半启动 VM 的方法查找不完整，实测 1.class / 1.frozen? 这类
     * 核心方法会抛 NoMethodError 且错误信息里的方法名是垃圾 Symbol；ruby_options
     * （加载 prelude / RubyGems / 静态扩展）之后才恢复正常。三条纪律：
     *   - 不调用 ruby_run：它会 ruby_cleanup，把常驻解释器整个拆掉（本引擎约定
     *     随进程常驻，且另一个 .so 可能正在用这个 VM）；
     *   - ruby_options 重复调用会 SIGSEGV，故用**进程级 env 标记**保证只走一次
     *     （dlclose 后重新 dlopen 本 .so 时静态变量归零，而 VM 还在）；
     *   - $VERBOSE=nil 抑制 ruby_init + ruby_options 二次加载 prelude 的
     *     "already initialized constant" 告警；临时摘掉 RUBYOPT，不把宿主环境
     *     里的 ruby 选项注进引擎启动（可能加载任意代码或直接 exit）。
     */
    rb_gv_set("$VERBOSE", Qnil);
    if (getenv("CRUCIBLE_EMBED_RUBY_BOOTED") == NULL) {
        static char *embedding[] = {"libapp_rack", "-e", "0"};
        char *rubyopt = getenv("RUBYOPT");
        char *saved = rubyopt != NULL ? appengine_strdup(rubyopt) : NULL;

        unsetenv("RUBYOPT");
        (void)ruby_options(3, embedding);
        setenv("CRUCIBLE_EMBED_RUBY_BOOTED", "1", 1);
        if (saved != NULL) {
            setenv("RUBYOPT", saved, 1);
            free(saved);
        }
    }

    v = rb_eval_string_protect(rack_shim_rb, &state);
    if (state != 0 || v == Qnil) {
        rack_capture_error(err, errsz, "rack shim 加载失败（异常无法格式化）");
        return -1;
    }
    rack_pin_libruby();
    g_ruby_ready = 1;
    fprintf(stderr, "libapp_rack: 嵌入式 MRI Ruby %s 就绪（rack gem %s）\n", ruby_version,
            RTEST(rb_gv_get("$crucible_have_rack")) ? "已加载，用真 Rack::Builder"
                                                    : "未安装，用内置 Builder 兼容层");
    return 0;
}

/* 一次 Rack 请求（在 g_rack_lock 内）：0 = out 已填；-1 = 显式引擎失败（rc != 0）。 */
static int rack_request(const char *script, const char *method, const char *path,
                        const char *query, const char *content_type, const char *body,
                        size_t body_len, const char *remote, const char *server_name,
                        int server_port, const char *headers, AppEngineResult *out)
{
    char portbuf[16];
    char lenbuf[32];
    char errbuf[1024];
    int state = 0;
    VALUE req, res, vs, vh, vb, vt;

    RACK_LOCK();
    if (rack_ruby_ensure_locked(errbuf, sizeof(errbuf)) != 0) {
        RACK_UNLOCK();
        return rack_fail(out, "rack: 嵌入式 MRI Ruby 初始化失败: %s", errbuf);
    }

    /* 请求值经全局哈希 $crucible_req 传入（不碰进程 ENV；.env 已由 Rust 侧临时注入）。 */
    snprintf(portbuf, sizeof(portbuf), "%d", server_port > 0 ? server_port : 80);
    snprintf(lenbuf, sizeof(lenbuf), "%lu", (unsigned long)body_len);
    req = rb_hash_new();
    rb_hash_aset(req, rb_str_new_cstr("script"), rb_str_new_cstr(script));
    rb_hash_aset(req, rb_str_new_cstr("method"),
                 rb_str_new_cstr(method != NULL ? method : "GET"));
    rb_hash_aset(req, rb_str_new_cstr("path"), rb_str_new_cstr(path != NULL ? path : "/"));
    rb_hash_aset(req, rb_str_new_cstr("query"), rb_str_new_cstr(query != NULL ? query : ""));
    rb_hash_aset(req, rb_str_new_cstr("content_type"),
                 rb_str_new_cstr(content_type != NULL ? content_type : ""));
    rb_hash_aset(req, rb_str_new_cstr("content_length"), rb_str_new_cstr(lenbuf));
    rb_hash_aset(req, rb_str_new_cstr("remote"),
                 rb_str_new_cstr(remote != NULL ? remote : ""));
    rb_hash_aset(req, rb_str_new_cstr("server_name"),
                 rb_str_new_cstr(server_name != NULL && server_name[0] != '\0'
                                     ? server_name
                                     : "crucible"));
    rb_hash_aset(req, rb_str_new_cstr("server_port"), rb_str_new_cstr(portbuf));
    /* body 二进制安全（rb_str_new 保留 NUL 字节），供 rack.input 使用。 */
    rb_hash_aset(req, rb_str_new_cstr("body"),
                 body != NULL ? rb_str_new(body, (long)body_len) : rb_str_new("", 0));
    /* ABI 请求头块；shim 展开为 env 的 HTTP_*（Cookie/Authorization 等）。 */
    rb_hash_aset(req, rb_str_new_cstr("headers"),
                 headers != NULL ? rb_str_new_cstr(headers) : rb_str_new("", 0));
    rb_gv_set("$crucible_req", req);

    /* 全部加载/调用逻辑在 shim 的 CrucibleRack.dispatch 里（读 $crucible_req）。
     * 异常被 protect 接住 → rc != 0 + 细节只进 out->error。 */
    res = rb_eval_string_protect("CrucibleRack.dispatch($crucible_req)", &state);
    if (state != 0) {
        char detail[2048];
        VALUE le = rb_gv_get("$crucible_last_error");

        /* shim 在 dispatch 的 rescue 里就地格式化好异常（消息+backtrace）；拿不到
         * 时才用 C 侧格式化兜底。两者都只进 out->error（服务端日志），不回显客户端。 */
        if (RB_TYPE_P(le, T_STRING) && RSTRING_LEN(le) > 0) {
            long n = RSTRING_LEN(le);

            if ((size_t)n >= sizeof(detail))
                n = (long)sizeof(detail) - 1;
            memcpy(detail, RSTRING_PTR(le), (size_t)n);
            detail[n] = '\0';
        } else {
            rack_capture_error(detail, sizeof(detail),
                               "rack: 应用或加载脚本抛出异常（无法格式化）");
        }
        RACK_UNLOCK();
        return rack_fail(out, "rack: 脚本执行失败（script=%s）：%s", script, detail);
    }
    if (!RB_TYPE_P(res, T_ARRAY) || RARRAY_LEN(res) < 3) {
        RACK_UNLOCK();
        return rack_fail(out, "rack: 驱动未返回 [status, headers, body]（script=%s）", script);
    }
    vs = rb_ary_entry(res, 0);
    vh = rb_ary_entry(res, 1);
    vb = rb_ary_entry(res, 2);
    vt = rb_ary_entry(res, 3);
    if (!RB_INTEGER_TYPE_P(vs) || !RB_TYPE_P(vh, T_STRING) || !RB_TYPE_P(vb, T_STRING)) {
        RACK_UNLOCK();
        return rack_fail(out, "rack: 驱动返回类型非法（script=%s）", script);
    }
    if (appengine_result_alloc(out) != 0) {
        RACK_UNLOCK();
        return -1;
    }
    out->status = NUM2INT(vs); /* shim 已把 status 规整到 100..599，转换不会 raise */
    appengine_result_set_headers(out, RSTRING_PTR(vh)); /* MRI 保证 NUL 结尾 */
    appengine_result_set_body(out, RSTRING_PTR(vb), (size_t)RSTRING_LEN(vb));
    /* 第 4 个元素只在响应体被截断等「服务到了但要留痕」的场合非空（rc 仍为 0）。 */
    if (RB_TYPE_P(vt, T_STRING) && RSTRING_LEN(vt) > 0)
        appengine_result_set_error(out, RSTRING_PTR(vt));
    RACK_UNLOCK();
    return 0;
}

#endif /* CRUCIBLE_HAVE_RUBY */

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    (void)lib_hint;
    g_inited = 1;
#ifndef CRUCIBLE_HAVE_RUBY
    fprintf(stderr,
            "libapp_rack: 未嵌入 Ruby——构建时没有可用的 ruby 头文件/libruby（见 rack_engine.c "
            "文件头）；请求将得到显式错误\n");
#elif defined(CRUCIBLE_HAVE_RUBY_AUTO)
    fprintf(stderr,
            "libapp_rack: 构建脚本未定义 CRUCIBLE_HAVE_RUBY，已按 include 路径里的 ruby.h "
            "自动启用嵌入（见 rack_engine.c 文件头）\n");
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
    const char *headers,
    AppEngineResult *out)
{
    char pathbuf[1024];
    const char *use;

    (void)extra; /* .env 变量由 Rust 侧注入进程环境；嵌入式解释器继承同一进程环境 */

    if (!g_inited || out == NULL)
        return -1;

    use = resolve_script(script, docroot, pathbuf, sizeof(pathbuf));
    if (use == NULL)
        return rack_fail(out,
                         "rack: 未找到 Rack 脚本（script=%s docroot=%s，尝试过 "
                         "config.ru / index.ru / app.rb）",
                         script != NULL ? script : "(null)",
                         docroot != NULL ? docroot : "(null)");

#ifdef CRUCIBLE_HAVE_RUBY
    return rack_request(use, method, path, query, content_type, body, body_len, remote,
                        server_name, server_port, headers, out);
#else
    (void)method;
    (void)path;
    (void)query;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)headers;
    /*
     * 显式失败，不 spawn、不假 hello：
     * spec 要求 Ruby 静态嵌入（禁止每请求 spawn 解释器），而构建时没有 ruby 头文件/
     * libruby，无法嵌入；唯一正确的结果是把这个事实报给调用方（502 固定文本 + error）。
     */
    return rack_fail(out,
                     "rack: 未嵌入 Ruby（not built with embedded MRI Ruby），无法服务 %s。"
                     "需要构建时探测到 ruby.h 与 libruby（scripts/build_script_ffi.sh 的 "
                     "detect_ruby）并以 -DCRUCIBLE_HAVE_RUBY 重新构建 libapp_rack.so；"
                     "每请求 spawn ruby 被 spec 禁止，故不提供 popen 回退",
                     use);
#endif
}

void appengine_shutdown(void)
{
    g_inited = 0;
    /* 不 ruby_cleanup：解释器随进程常驻（与 pyembed/psgi 同一约定，避免在任意线程里
     * 销毁 VM；也避免卸载 .so 后其它嵌入引擎的 Ruby 调用踩空）。 */
}
