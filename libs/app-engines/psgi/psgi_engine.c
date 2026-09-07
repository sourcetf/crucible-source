/*
 * PSGI app-engine — run app.psgi / index.pl via perl when available.
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

static int run_psgi(const char *script, const char *method, const char *path,
                    const char *query, char **out, size_t *out_len)
{
    char tmp[] = "/tmp/crucible_psgi_XXXXXX";
    char cmd[512];
    FILE *fp, *tf;
    int fd;
    char buf[4096];
    size_t cap = 4096, n = 0;
    char *acc;
    const char *pl =
        "my $script = $ENV{CRUCIBLE_SCRIPT};\n"
        "my $app = do $script;\n"
        "die $@ if $@;\n"
        "unless (ref $app eq 'CODE') {\n"
        "  print \"hello from psgi (no app)\\n\"; exit 0;\n"
        "}\n"
        "my $env = {\n"
        "  REQUEST_METHOD => $ENV{REQUEST_METHOD} || 'GET',\n"
        "  PATH_INFO => $ENV{PATH_INFO} || '/',\n"
        "  QUERY_STRING => $ENV{QUERY_STRING} || '',\n"
        "  SERVER_NAME => 'crucible',\n"
        "  SERVER_PORT => 80,\n"
        "  'psgi.version' => [1,1],\n"
        "  'psgi.url_scheme' => 'http',\n"
        "  'psgi.input' => \\*STDIN,\n"
        "  'psgi.errors' => \\*STDERR,\n"
        "};\n"
        "my $res = $app->($env);\n"
        "my $body = $res->[2];\n"
        "if (ref $body eq 'ARRAY') { print join('', @$body); }\n"
        "elsif (ref $body) { while (defined(my $c = $body->getline)) { print $c } }\n"
        "else { print $body; }\n";

    fd = mkstemp(tmp);
    if (fd < 0)
        return -1;
    tf = fdopen(fd, "w");
    if (!tf) {
        close(fd);
        unlink(tmp);
        return -1;
    }
    fputs(pl, tf);
    fclose(tf);

    setenv("CRUCIBLE_SCRIPT", script, 1);
    setenv("REQUEST_METHOD", method ? method : "GET", 1);
    setenv("PATH_INFO", path ? path : "/", 1);
    setenv("QUERY_STRING", query ? query : "", 1);

    snprintf(cmd, sizeof(cmd), "perl \"%s\" 2>/dev/null", tmp);
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
        snprintf(sp, sizeof(sp), "%s/app.psgi", docroot ? docroot : ".");
        if (file_ok(sp))
            use = sp;
        else {
            snprintf(sp, sizeof(sp), "%s/index.pl", docroot ? docroot : ".");
            if (file_ok(sp))
                use = sp;
        }
    }

    if (use && run_psgi(use, method, path, query, &result, &rlen) == 0) {
        appengine_result_alloc(out);
        out->status = 200;
        appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n"
                                          "X-Crucible-Engine: psgi\r\n");
        appengine_result_set_body(out, result, rlen);
        free(result);
        return 0;
    }
    return appengine_fill_hello(out, "psgi", path);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
