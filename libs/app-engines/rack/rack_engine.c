/*
 * Rack app-engine —— 诚实失败（no embedded Ruby on this host）。
 *
 * 旧实现：写 Ruby runner 到 /tmp 再 popen("ruby runner")——每请求 spawn 解释器
 * （spec 明令禁止：Ruby 必须静态嵌入），而且失败即 appengine_fill_hello（假成功）。
 * 本机（OpenBSD）**没有安装 ruby，也没有 libruby**，MRI 嵌入在目标机上不可行：
 *   - 没有 libruby 可 dlopen，也没有 ruby 头文件（ruby.h / ruby/Ruby.h）；
 *   - Rack 还需要 rack gem + Rack::Builder 才能解释 config.ru 的 run/use DSL。
 *
 * 因此本引擎的做法：
 *   1) 不再 spawn（popen 已删除），不假装成功；
 *   2) 返回显式错误（rc != 0 + error 文本），说明需要什么才能启用；
 *   3) 不写"看起来能跑"的 MRI 代码：在既无头文件、又无法编译/运行验证、且目标机
 *      根本没有 libruby 的前提下，那只会制造误导。
 *
 * 未来在装有 ruby 的宿主上启用 MRI 嵌入的做法（需改 scripts/build_app_engines.sh，
 * 属于本目录之外的改动）：
 *      CFLAGS += $(pkg-config --cflags ruby) -DCRUCIBLE_HAVE_RUBY
 *      LIBS   += $(pkg-config --libs ruby)              # 或 -lruby，使 .so 带 DT_NEEDED
 *   嵌入 API：ruby_init / ruby_init_loadpath / rb_require("rack") /
 *   rb_eval_string_protect（参见 libs/script-ffi/script_engine.c 的 Ruby 分支写法），
 *   应用加载用 Rack::Builder.parse_file(script)。
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int g_inited;

/* 引擎级失败：填 out->error 并返回 -1（app_ffi 会把它变成 502 文本）。 */
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

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    (void)lib_hint;
    g_inited = 1;
    fprintf(stderr,
            "libapp_rack: 未嵌入 Ruby——本机没有 ruby/libruby（Rack 需要 MRI + rack "
            "gem），见 rack_engine.c 文件头；请求将得到显式错误\n");
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

    (void)method;
    (void)path;
    (void)query;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)extra;

    if (!g_inited || out == NULL)
        return -1;

    use = resolve_script(script, docroot, pathbuf, sizeof(pathbuf));
    if (use == NULL)
        return rack_fail(out,
                         "rack: 未找到 Rack 脚本（script=%s docroot=%s，尝试过 "
                         "config.ru / index.ru / app.rb）",
                         script != NULL ? script : "(null)",
                         docroot != NULL ? docroot : "(null)");
    /*
     * 显式失败，不 spawn、不假 hello：
     * spec 要求 Ruby 静态嵌入（禁止每请求 spawn 解释器），而本机没有 ruby/libruby，
     * 无法嵌入；唯一正确的结果是把这个事实报给调用方（502 + 本消息）。
     */
    return rack_fail(out,
                     "rack: 未嵌入 Ruby（not built with embedded MRI Ruby），且本机未安装 "
                     "ruby/libruby，无法服务 %s。Rack 需要 MRI + rack gem；启用嵌入需 "
                     "pkg-config --cflags/--libs ruby（-lruby 让 .so 带 DT_NEEDED）加 "
                     "-DCRUCIBLE_HAVE_RUBY 重新构建 libapp_rack.so；每请求 spawn ruby 被 "
                     "spec 禁止，故不再提供 popen 回退",
                     use);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
