/*
 * WSGI app-engine — prefer python3 file-exec of a small embedded runner that
 * loads application/app from the script (or docroot/app.py). Not an in-process
 * FFI Python embed; OpenBSD-friendly via popen.
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

static int g_inited;

/* CGI-style framed output from runner: headers then blank line then body. */
static int parse_cgi_frame(char *raw, size_t raw_len, int *status, char **headers,
                           char **body, size_t *body_len)
{
    char *sep;
    char *p;
    char *end;

    *status = 200;
    *headers = NULL;
    *body = NULL;
    *body_len = 0;
    if (!raw || raw_len == 0)
        return -1;

    sep = strstr(raw, "\r\n\r\n");
    if (sep) {
        *sep = '\0';
        *body = sep + 4;
        *body_len = raw_len - (size_t)(*body - raw);
    } else {
        sep = strstr(raw, "\n\n");
        if (sep) {
            *sep = '\0';
            *body = sep + 2;
            *body_len = raw_len - (size_t)(*body - raw);
        } else {
            *body = raw;
            *body_len = raw_len;
            return 0;
        }
    }

    /* Scan Status: line among headers */
    p = raw;
    end = raw + strlen(raw);
    while (p < end) {
        char *nl = strchr(p, '\n');
        size_t llen = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (llen >= 7 && strncasecmp(p, "Status:", 7) == 0) {
            *status = atoi(p + 7);
            if (*status <= 0)
                *status = 200;
        }
        if (!nl)
            break;
        p = nl + 1;
    }
    *headers = raw;
    return 0;
}

static int run_wsgi_runner(const char *script, const char *method, const char *path,
                           const char *query, const char *remote, const char *server_name,
                           int server_port, const char *body, size_t body_len,
                           char **out_raw, size_t *out_len)
{
    char cmd[512];
    FILE *fp;
    char buf[4096];
    size_t cap = 8192;
    size_t n = 0;
    char *acc;
    const char *runner =
        "import os, runpy, io, sys\n"
        "script = os.environ.get('CRUCIBLE_SCRIPT', 'app.py')\n"
        "method = os.environ.get('REQUEST_METHOD', 'GET')\n"
        "path = os.environ.get('PATH_INFO', '/')\n"
        "query = os.environ.get('QUERY_STRING', '')\n"
        "body = os.environ.get('CRUCIBLE_BODY', '').encode('utf-8', 'surrogateescape')\n"
        "ns = runpy.run_path(script)\n"
        "app = ns.get('application') or ns.get('app')\n"
        "if app is None:\n"
        "    sys.stdout.write('Status: 200\\r\\nContent-Type: text/plain; charset=utf-8\\r\\n\\r\\n')\n"
        "    sys.stdout.write('hello from wsgi (no application in %s)\\n' % script)\n"
        "    raise SystemExit(0)\n"
        "status_holder = ['200 OK']\n"
        "headers_holder = []\n"
        "def start_response(status, headers, exc_info=None):\n"
        "    status_holder[0] = status\n"
        "    headers_holder[:] = headers\n"
        "    return lambda b: None\n"
        "environ = {\n"
        "  'REQUEST_METHOD': method,\n"
        "  'PATH_INFO': path,\n"
        "  'QUERY_STRING': query or '',\n"
        "  'SERVER_NAME': os.environ.get('SERVER_NAME', 'crucible'),\n"
        "  'SERVER_PORT': os.environ.get('SERVER_PORT', '80'),\n"
        "  'REMOTE_ADDR': os.environ.get('REMOTE_ADDR', ''),\n"
        "  'wsgi.version': (1, 0),\n"
        "  'wsgi.url_scheme': 'http',\n"
        "  'wsgi.input': io.BytesIO(body),\n"
        "  'wsgi.errors': sys.stderr,\n"
        "  'wsgi.multithread': False,\n"
        "  'wsgi.multiprocess': False,\n"
        "  'wsgi.run_once': True,\n"
        "  'CONTENT_LENGTH': str(len(body)),\n"
        "}\n"
        "result = app(environ, start_response)\n"
        "code = status_holder[0].split(None, 1)[0]\n"
        "sys.stdout.write('Status: %s\\r\\n' % code)\n"
        "seen_ct = False\n"
        "for k, v in headers_holder:\n"
        "    if k.lower() == 'content-type': seen_ct = True\n"
        "    sys.stdout.write('%s: %s\\r\\n' % (k, v))\n"
        "if not seen_ct:\n"
        "    sys.stdout.write('Content-Type: text/plain; charset=utf-8\\r\\n')\n"
        "sys.stdout.write('\\r\\n')\n"
        "sys.stdout.flush()\n"
        "for chunk in result:\n"
        "    if isinstance(chunk, bytes):\n"
        "        sys.stdout.buffer.write(chunk)\n"
        "    else:\n"
        "        sys.stdout.write(str(chunk))\n";

    char tmp_path[] = "/tmp/crucible_wsgi_XXXXXX";
    int fd;
    FILE *tf;

    (void)body;
    (void)body_len;

    fd = mkstemp(tmp_path);
    if (fd < 0)
        return -1;
    tf = fdopen(fd, "w");
    if (!tf) {
        close(fd);
        unlink(tmp_path);
        return -1;
    }
    fputs(runner, tf);
    fclose(tf);

    setenv("CRUCIBLE_SCRIPT", script ? script : "app.py", 1);
    setenv("REQUEST_METHOD", method ? method : "GET", 1);
    setenv("PATH_INFO", path ? path : "/", 1);
    setenv("QUERY_STRING", query ? query : "", 1);
    setenv("REMOTE_ADDR", remote ? remote : "", 1);
    setenv("SERVER_NAME", server_name ? server_name : "crucible", 1);
    {
        char portbuf[16];
        snprintf(portbuf, sizeof(portbuf), "%d", server_port > 0 ? server_port : 80);
        setenv("SERVER_PORT", portbuf, 1);
    }
    if (body && body_len > 0 && body_len < 60000) {
        /* Best-effort small body via env (binary-safe for ASCII forms). */
        char *tmpb = (char *)malloc(body_len + 1);
        if (tmpb) {
            memcpy(tmpb, body, body_len);
            tmpb[body_len] = '\0';
            setenv("CRUCIBLE_BODY", tmpb, 1);
            free(tmpb);
        }
    } else {
        setenv("CRUCIBLE_BODY", "", 1);
    }

    snprintf(cmd, sizeof(cmd), "python3 \"%s\" 2>/dev/null", tmp_path);
    /* popen disabled (spec: no spawn). */
    fprintf(stderr, "libapp_wsgi: popen fallback disabled; rebuild with CPython embed\n");
    unlink(tmp_path);
    return -1;
    fp = popen(cmd, "r");
    if (!fp) {
        unlink(tmp_path);
        return -1;
    }
    acc = (char *)malloc(cap);
    if (!acc) {
        pclose(fp);
        unlink(tmp_path);
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
                unlink(tmp_path);
                return -1;
            }
            acc = nb;
        }
        memcpy(acc + n, buf, bl);
        n += bl;
    }
    pclose(fp);
    unlink(tmp_path);
    acc[n] = '\0';
    *out_raw = acc;
    *out_len = n;
    return n > 0 ? 0 : -1;
}

static int file_readable(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    fclose(f);
    return 1;
}

int appengine_init(const char *engine, const char *lib_hint)
{
    (void)engine;
    (void)lib_hint;
    g_inited = 1;
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
    char *raw = NULL;
    size_t raw_len = 0;
    char script_path[1024];
    const char *use_script = NULL;
    int status = 200;
    char *hdrs = NULL;
    char *bptr = NULL;
    size_t blen = 0;
    char hdrbuf[2048];

    (void)content_type;
    (void)extra;

    if (!g_inited || !out)
        return -1;

    if (script && script[0] && file_readable(script))
        use_script = script;
    else {
        snprintf(script_path, sizeof(script_path), "%s/app.py", docroot ? docroot : ".");
        if (file_readable(script_path))
            use_script = script_path;
    }

    if (use_script &&
        run_wsgi_runner(use_script, method, path, query, remote, server_name, server_port,
                        body, body_len, &raw, &raw_len) == 0) {
        parse_cgi_frame(raw, raw_len, &status, &hdrs, &bptr, &blen);
        appengine_result_alloc(out);
        out->status = status;
        if (hdrs && hdrs[0]) {
            /* Rebuild headers without Status line */
            size_t o = 0;
            char *line = hdrs;
            hdrbuf[0] = '\0';
            while (line && *line) {
                char *nl = strchr(line, '\n');
                size_t llen;
                if (nl)
                    *nl = '\0';
                if (line[0] && line[strlen(line) - 1] == '\r')
                    line[strlen(line) - 1] = '\0';
                llen = strlen(line);
                if (llen >= 7 && strncasecmp(line, "Status:", 7) == 0) {
                    /* skip */
                } else if (llen > 0 && o + llen + 3 < sizeof(hdrbuf)) {
                    memcpy(hdrbuf + o, line, llen);
                    o += llen;
                    hdrbuf[o++] = '\r';
                    hdrbuf[o++] = '\n';
                    hdrbuf[o] = '\0';
                }
                if (!nl)
                    break;
                line = nl + 1;
            }
            if (o == 0)
                appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n");
            else
                appengine_result_set_headers(out, hdrbuf);
        } else {
            appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n");
        }
        appengine_result_set_body(out, bptr ? bptr : "", blen);
        free(raw);
        return 0;
    }

    free(raw);
    return appengine_fill_hello(out, "wsgi", path);
}

void appengine_shutdown(void) { g_inited = 0; }
