/*
 * Rack app-engine — run config.ru / app.rb via ruby when available.
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_inited;

static int file_ok(const char *p)
{
    FILE *f = fopen(p, "rb");
    if (!f)
        return 0;
    fclose(f);
    return 1;
}

static int run_rack(const char *script, const char *method, const char *path,
                    const char *query, char **out, size_t *out_len)
{
    char tmp[] = "/tmp/crucible_rack_XXXXXX";
    char cmd[512];
    FILE *fp, *tf;
    int fd;
    char buf[4096];
    size_t cap = 4096, n = 0;
    char *acc;
    const char *rb =
        "script = ENV['CRUCIBLE_SCRIPT']\n"
        "code = File.read(script)\n"
        "app = nil\n"
        "begin\n"
        "  app = eval(code, binding, script)\n"
        "rescue => e\n"
        "  print \"hello from rack error=#{e}\\n\"; exit 0\n"
        "end\n"
        "unless app.respond_to?(:call)\n"
        "  # config.ru style: last expression may be a lambda\n"
        "  print \"hello from rack (no app)\\n\"; exit 0\n"
        "end\n"
        "env = {\n"
        "  'REQUEST_METHOD' => ENV['REQUEST_METHOD'] || 'GET',\n"
        "  'PATH_INFO' => ENV['PATH_INFO'] || '/',\n"
        "  'QUERY_STRING' => ENV['QUERY_STRING'] || '',\n"
        "  'SERVER_NAME' => 'crucible',\n"
        "  'SERVER_PORT' => '80',\n"
        "  'rack.version' => [1, 3],\n"
        "  'rack.url_scheme' => 'http',\n"
        "  'rack.input' => StringIO.new(''),\n"
        "  'rack.errors' => $stderr,\n"
        "}\n"
        "status, headers, body = app.call(env)\n"
        "body.each { |c| print c }\n"
        "body.close if body.respond_to?(:close)\n";

    fd = mkstemp(tmp);
    if (fd < 0)
        return -1;
    tf = fdopen(fd, "w");
    if (!tf) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    fputs("require 'stringio'\n", tf);
    fputs(rb, tf);
    fclose(tf);

    setenv("CRUCIBLE_SCRIPT", script, 1);
    setenv("REQUEST_METHOD", method ? method : "GET", 1);
    setenv("PATH_INFO", path ? path : "/", 1);
    setenv("QUERY_STRING", query ? query : "", 1);

    snprintf(cmd, sizeof(cmd), "ruby \"%s\" 2>/dev/null", tmp);
    fp = popen(cmd, "r");
    if (!fp) {
        unlink(tmp);
        return -1;
    }
    acc = (char *)malloc(cap);
    if (!acc) {
        pclose(fp);
        unlink(tmp);
        return -1;
    }
    while (fgets(buf, sizeof(buf), fp)) {
        size_t bl = strlen(buf);
        if (n + bl + 1 >= cap) {
            char *nb;
            cap *= 2;
            nb = (char *)realloc(acc, cap);
            if (!nb) {
                free(acc);
                pclose(fp);
                unlink(tmp);
                return -1;
            }
            acc = nb;
        }
        memcpy(acc + n, buf, bl);
        n += bl;
    }
    pclose(fp);
    unlink(tmp);
    acc[n] = '\0';
    if (n == 0) {
        free(acc);
        return -1;
    }
    *out = acc;
    *out_len = n;
    return 0;
}

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)lib_hint;
    g_inited = 1;
    (void)engine;
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
    char sp[1024];
    char *result = NULL;
    size_t rlen = 0;
    const char *use = NULL;

    (void)content_type;
    (void)body;
    (void)body_len;
    (void)remote;
    (void)server_name;
    (void)server_port;
    (void)extra;

    if (!g_inited || out == NULL)
        return -1;

    if (script && script[0] && file_ok(script))
        use = script;
    else {
        snprintf(sp, sizeof(sp), "%s/config.ru", docroot ? docroot : ".");
        if (file_ok(sp))
            use = sp;
        else {
            snprintf(sp, sizeof(sp), "%s/app.rb", docroot ? docroot : ".");
            if (file_ok(sp))
                use = sp;
        }
    }

    if (use && run_rack(use, method, path, query, &result, &rlen) == 0) {
        appengine_result_alloc(out);
        out->status = 200;
        appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n"
                                          "X-Crucible-Engine: rack\r\n");
        appengine_result_set_body(out, result, rlen);
        free(result);
        return 0;
    }
    return appengine_fill_hello(out, "rack", path);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
