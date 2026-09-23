/*
 * CGI app-engine —— 真实 argv exec（无 shell 字符串、无命令注入面）。
 *
 * CGI 的本质就是"每请求起一个进程"，这一条对 CGI 是正当的（spec 的禁 spawn 针对
 * 解释器嵌入类引擎：python/ruby/perl/lua/wsgi/asgi/psgi/rack/uwsgi/tsx）。
 * 但旧实现有两个真问题：
 *   1) popen("\"%s\" …") / popen("/bin/sh \"%s\" …")——把**请求派生**的脚本路径插进
 *      shell 字符串。路径里出现 `"`、`$`、反引号或 `\` 就能逃出引号执行任意命令
 *      （docroot/script 只做了目录穿越校验，不校验引号），是命令注入漏洞。
 *   2) 失败即 appengine_fill_hello（假成功），且不发 CONTENT_LENGTH、不喂 stdin
 *      （POST body 永远到不了 CGI）。
 *
 * 现在：envp 在父进程里按 CGI 规范拼好（不在 fork 后 setenv，避免多线程 fork 后
 * 撞 malloc 锁），fork + execve(script, {script,NULL}, envp)；非可执行/无 shebang
 * 时退回 execve("/bin/sh", {"/bin/sh", script, NULL}, envp)——仍是 argv 数组，
 * 请求数据永远不经过 shell 解析。stdin=请求体、stdout=响应、stderr=诊断（进入错误
 * 文本）。poll 循环同时收发，避免 body 大时管道互锁；带 30s 墙钟超时与 32MiB 响应
 * 上限（超限/超时都 kill+reap 子进程并显式报错）。
 * 输出为空 / 子进程异常退出 → 显式错误（含退出码与 stderr），不再假 hello。
 *
 * 注：向已关闭的管道写入需要 SIGPIPE 被忽略（Rust 运行时默认 SIG_IGN），EPIPE 会
 * 作为普通写错误处理（写端随即关闭）。
 */
#include "appengine.h"
#include "appengine_common.h"
#include "crucible_embed.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

#define CGI_POLL_SLICE_MS 1000
#define CGI_TIMEOUT_MS    30000
#define CGI_OUT_CAP       (32u * 1024u * 1024u)
#define CGI_ERR_KEEP      4096

static int g_inited;

static int cgi_fail(AppEngineResult *out, const char *fmt, ...)
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

/* 脚本解析：显式 script → docroot/index.cgi → docroot/cgi-bin/index.cgi。 */
static const char *resolve_script(const char *script, const char *docroot, char *out,
                                  size_t outsz)
{
    if (is_regular_file(script)) {
        snprintf(out, outsz, "%s", script);
        return out;
    }
    if (docroot != NULL && docroot[0] != '\0') {
        snprintf(out, outsz, "%s/index.cgi", docroot);
        if (is_regular_file(out))
            return out;
        snprintf(out, outsz, "%s/cgi-bin/index.cgi", docroot);
        if (is_regular_file(out))
            return out;
    }
    return NULL;
}

/* ------------------------------------------------------------- envp 构造 --- */

/* 会被我们覆盖的键：继承 environ 时跳过（避免重复键）。 */
static const char *const cgi_own_keys[] = {
    "GATEWAY_INTERFACE", "REQUEST_METHOD", "PATH_INFO", "QUERY_STRING",
    "SCRIPT_FILENAME", "SCRIPT_NAME", "REMOTE_ADDR", "SERVER_NAME",
    "SERVER_PORT", "SERVER_PROTOCOL", "CONTENT_TYPE", "CONTENT_LENGTH", NULL
};

static int cgi_key_is_ours(const char *entry)
{
    const char *eq = strchr(entry, '=');
    size_t klen;
    int i;

    if (eq == NULL)
        return 0;
    klen = (size_t)(eq - entry);
    for (i = 0; cgi_own_keys[i] != NULL; i++) {
        if (strlen(cgi_own_keys[i]) == klen &&
            strncmp(entry, cgi_own_keys[i], klen) == 0)
            return 1;
    }
    return 0;
}

static char *cgi_kv(const char *k, const char *v)
{
    size_t n = strlen(k) + strlen(v) + 2;
    char *s = (char *)malloc(n);

    if (s == NULL)
        return NULL;
    snprintf(s, n, "%s=%s", k, v);
    return s;
}

/* ---------------------------------------------------------------- 子进程 --- */

typedef struct {
    pid_t pid;
    int in_fd;  /* 写请求体 */
    int out_fd; /* 读响应 */
    int err_fd; /* 读 stderr */
} cgi_proc;

/* 父进程侧的三个 fd 设为非阻塞：cgi_pump 用 poll 单线程收发，阻塞 fd 会在
 * "子进程狂写 stdout 而我们正在写大 body" 时互锁。管道两端是各自独立的
 * open file description，父端 O_NONBLOCK 不会影响子进程那端。 */
static void cgi_set_nonblock(int fd)
{
    int fl;

    if (fd < 0)
        return;
    fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int cgi_spawn(const char *script, char **envp, cgi_proc *p)
{
    int inpipe[2], outpipe[2], errpipe[2];
    pid_t pid;

    if (pipe(inpipe) != 0)
        return -1;
    if (pipe(outpipe) != 0) {
        close(inpipe[0]);
        close(inpipe[1]);
        return -1;
    }
    if (pipe(errpipe) != 0) {
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);
        return -1;
    }
    pid = fork();
    if (pid < 0) {
        close(inpipe[0]);
        close(inpipe[1]);
        close(outpipe[0]);
        close(outpipe[1]);
        close(errpipe[0]);
        close(errpipe[1]);
        return -1;
    }
    if (pid == 0) {
        /* 子进程只做 dup2 + execve（不再 malloc/setenv，避免多线程 fork 后死锁）。 */
        char *argv[3];

        close(inpipe[1]);
        close(outpipe[0]);
        close(errpipe[0]);
        if (dup2(inpipe[0], STDIN_FILENO) < 0 || dup2(outpipe[1], STDOUT_FILENO) < 0 ||
            dup2(errpipe[1], STDERR_FILENO) < 0)
            _exit(127);
        close(inpipe[0]);
        close(outpipe[1]);
        close(errpipe[1]);

        argv[0] = (char *)script;
        argv[1] = NULL;
        execve(script, argv, envp);
        /* 无 shebang / 不可执行：退回 /bin/sh 以 argv 形式执行同一文件（无 shell 串）。 */
        argv[0] = "/bin/sh";
        argv[1] = (char *)script;
        argv[2] = NULL;
        execve("/bin/sh", argv, envp);
        _exit(127);
    }
    close(inpipe[0]);
    close(outpipe[1]);
    close(errpipe[1]);
    cgi_set_nonblock(inpipe[1]);
    cgi_set_nonblock(outpipe[0]);
    cgi_set_nonblock(errpipe[0]);
    p->pid = pid;
    p->in_fd = inpipe[1];
    p->out_fd = outpipe[0];
    p->err_fd = errpipe[0];
    return 0;
}

static void cgi_close_pipes(cgi_proc *p)
{
    if (p->in_fd >= 0)
        close(p->in_fd);
    if (p->out_fd >= 0)
        close(p->out_fd);
    if (p->err_fd >= 0)
        close(p->err_fd);
    p->in_fd = p->out_fd = p->err_fd = -1;
}

/* 失败路径统一收尾：kill + reap，绝不留僵尸或失控进程。 */
static void cgi_kill_reap(cgi_proc *p)
{
    int status = 0;

    cgi_close_pipes(p);
    if (p->pid > 0) {
        (void)kill(p->pid, SIGKILL);
        while (waitpid(p->pid, &status, 0) < 0 && errno == EINTR)
            ;
        p->pid = 0;
    }
}

static long cgi_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (long)(ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
}

/* poll 循环：边喂 body 边收 stdout/stderr，直到管道关闭 / 超时 / 超限。 */
static int cgi_pump(cgi_proc *p, const char *body, size_t body_len, crucible_buf *out,
                    crucible_buf *errout, long *exit_code, char *why, size_t whysz)
{
    size_t sent = 0;
    long start = cgi_now_ms();

    while (p->in_fd >= 0 || p->out_fd >= 0 || p->err_fd >= 0) {
        struct pollfd fds[3];
        int nfds = 0, wi = -1, oi = -1, ei = -1, rc;

        if (p->in_fd >= 0 && sent >= body_len) { /* body 已送完/无 body → 立即给 EOF */
            close(p->in_fd);
            p->in_fd = -1;
        }
        if (p->in_fd >= 0) {
            wi = nfds;
            fds[nfds].fd = p->in_fd;
            fds[nfds].events = POLLOUT;
            fds[nfds].revents = 0;
            nfds++;
        }
        if (p->out_fd >= 0) {
            oi = nfds;
            fds[nfds].fd = p->out_fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }
        if (p->err_fd >= 0) {
            ei = nfds;
            fds[nfds].fd = p->err_fd;
            fds[nfds].events = POLLIN;
            fds[nfds].revents = 0;
            nfds++;
        }
        if (nfds == 0)
            break;
        if (cgi_now_ms() - start >= CGI_TIMEOUT_MS) {
            snprintf(why, whysz, "CGI 超时（%d ms）", CGI_TIMEOUT_MS);
            cgi_kill_reap(p);
            return -1;
        }
        rc = poll(fds, (nfds_t)nfds, CGI_POLL_SLICE_MS);
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            snprintf(why, whysz, "poll 失败: %s", strerror(errno));
            cgi_kill_reap(p);
            return -1;
        }

        /* 1) 喂请求体 */
        if (wi >= 0 && p->in_fd >= 0 &&
            (fds[wi].revents & (POLLOUT | POLLERR | POLLHUP)) != 0) {
            ssize_t w = write(p->in_fd, body + sent, body_len - sent);
            if (w > 0) {
                sent += (size_t)w;
            } else if (w < 0 && (errno == EAGAIN || errno == EINTR)) {
                ; /* 稍后重试 */
            } else {
                /* EPIPE 等：子进程不再读 stdin（可能已退出），放弃写端继续收输出。 */
                close(p->in_fd);
                p->in_fd = -1;
            }
        }

        /* 2) 收 stdout */
        if (oi >= 0 && p->out_fd >= 0 &&
            (fds[oi].revents & (POLLIN | POLLERR | POLLHUP)) != 0) {
            char buf[8192];
            ssize_t r = read(p->out_fd, buf, sizeof(buf));

            if (r > 0) {
                if (out->len + (size_t)r > CGI_OUT_CAP) {
                    snprintf(why, whysz, "CGI 响应超过 %u 字节上限", CGI_OUT_CAP);
                    cgi_kill_reap(p);
                    return -1;
                }
                if (crucible_buf_append(out, buf, (size_t)r) != 0) {
                    snprintf(why, whysz, "内存不足（累积 CGI 响应）");
                    cgi_kill_reap(p);
                    return -1;
                }
            } else if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
                close(p->out_fd);
                p->out_fd = -1;
            }
        }

        /* 3) 收 stderr：只保留前 CGI_ERR_KEEP 字节，其余读掉丢弃（不能让管道堵住） */
        if (ei >= 0 && p->err_fd >= 0 &&
            (fds[ei].revents & (POLLIN | POLLERR | POLLHUP)) != 0) {
            char buf[4096];
            ssize_t r = read(p->err_fd, buf, sizeof(buf));

            if (r > 0) {
                if (errout->len < CGI_ERR_KEEP)
                    (void)crucible_buf_append(errout, buf, (size_t)r);
            } else if (r == 0 || (r < 0 && errno != EAGAIN && errno != EINTR)) {
                close(p->err_fd);
                p->err_fd = -1;
            }
        }
    }

    {
        int status = 0;
        pid_t w;

        do {
            w = waitpid(p->pid, &status, 0);
        } while (w < 0 && errno == EINTR);
        if (w < 0) {
            snprintf(why, whysz, "waitpid 失败: %s", strerror(errno));
            return -1;
        }
        p->pid = 0;
        if (WIFEXITED(status))
            *exit_code = (long)WEXITSTATUS(status);
        else if (WIFSIGNALED(status))
            *exit_code = -1 - (long)WTERMSIG(status);
        else
            *exit_code = -1;
    }
    return 0;
}

/* CGI 输出（可选 `Status:` + 头块 + 空行 + body）→ AppEngineResult。 */
static void cgi_apply_output(AppEngineResult *out, crucible_buf *raw)
{
    char *sep, *body, *line;
    size_t blen;
    int status = 200;
    char hdrbuf[2048];
    size_t o = 0;

    appengine_result_alloc(out);
    if (raw == NULL || raw->p == NULL || raw->len == 0)
        return;

    sep = strstr(raw->p, "\r\n\r\n");
    if (sep != NULL) {
        *sep = '\0';
        body = sep + 4;
    } else {
        sep = strstr(raw->p, "\n\n");
        if (sep != NULL) {
            *sep = '\0';
            body = sep + 2;
        } else {
            /* 没有头块：整体当 body（text/plain），与 CGI 语义一致。 */
            out->status = 200;
            appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n"
                                               "X-Crucible-Engine: cgi\r\n");
            appengine_result_set_body(out, raw->p, raw->len);
            return;
        }
    }
    blen = raw->len - (size_t)(body - raw->p);
    if (blen > 0 && body[blen - 1] == '\0')
        blen--; /* CGI 输出自身以 NUL 结尾（异常输出）时不计入 body 长度 */

    line = raw->p;
    hdrbuf[0] = '\0';
    while (line != NULL && *line != '\0') {
        char *nl = strchr(line, '\n');
        size_t llen;

        if (nl != NULL)
            *nl = '\0';
        llen = strlen(line);
        if (llen > 0 && line[llen - 1] == '\r')
            line[--llen] = '\0';
        if (llen >= 7 && strncasecmp(line, "Status:", 7) == 0) {
            status = atoi(line + 7);
            if (status <= 0)
                status = 200;
        } else if (llen > 0 && o + llen + 3 < sizeof(hdrbuf)) {
            memcpy(hdrbuf + o, line, llen);
            o += llen;
            hdrbuf[o++] = '\r';
            hdrbuf[o++] = '\n';
            hdrbuf[o] = '\0';
        }
        if (nl == NULL)
            break;
        line = nl + 1;
    }

    out->status = status;
    if (o == 0)
        appengine_result_set_headers(out, "Content-Type: text/plain; charset=utf-8\r\n"
                                           "X-Crucible-Engine: cgi\r\n");
    else
        appengine_result_set_headers(out, hdrbuf);
    appengine_result_set_body(out, body, blen);
}

/* ------------------------------------------------------------ 请求入口 --- */

static int cgi_execute(const char *script, const char *method, const char *path,
                       const char *query, const char *content_type, const char *body,
                       size_t body_len, const char *remote, const char *server_name,
                       int server_port, AppEngineResult *out)
{
    crucible_buf raw, errbuf;
    char *own[12];
    size_t own_n = 0, nenv = 0, i;
    char **envp = NULL;
    char portbuf[16];
    char lenbuf[32];
    char why[256];
    cgi_proc proc;
    long exit_code = 0;
    int rc = -1;

    memset(&raw, 0, sizeof(raw));
    memset(&errbuf, 0, sizeof(errbuf));
    memset(&proc, 0, sizeof(proc));
    proc.in_fd = proc.out_fd = proc.err_fd = -1;
    why[0] = '\0';
    if (body == NULL)
        body_len = 0;

    snprintf(portbuf, sizeof(portbuf), "%d", server_port > 0 ? server_port : 80);
    snprintf(lenbuf, sizeof(lenbuf), "%lu", (unsigned long)body_len);
    own[own_n++] = cgi_kv("GATEWAY_INTERFACE", "CGI/1.1");
    own[own_n++] = cgi_kv("REQUEST_METHOD", method != NULL ? method : "GET");
    own[own_n++] = cgi_kv("PATH_INFO", path != NULL ? path : "/");
    own[own_n++] = cgi_kv("QUERY_STRING", query != NULL ? query : "");
    own[own_n++] = cgi_kv("SCRIPT_FILENAME", script);
    own[own_n++] = cgi_kv("SCRIPT_NAME", script);
    own[own_n++] = cgi_kv("REMOTE_ADDR", remote != NULL ? remote : "");
    own[own_n++] = cgi_kv("SERVER_NAME", server_name != NULL && server_name[0] != '\0'
                                              ? server_name
                                              : "crucible");
    own[own_n++] = cgi_kv("SERVER_PORT", portbuf);
    own[own_n++] = cgi_kv("SERVER_PROTOCOL", "HTTP/1.1");
    if (content_type != NULL && content_type[0] != '\0')
        own[own_n++] = cgi_kv("CONTENT_TYPE", content_type);
    own[own_n++] = cgi_kv("CONTENT_LENGTH", lenbuf);
    for (i = 0; i < own_n; i++) {
        if (own[i] == NULL) {
            rc = cgi_fail(out, "cgi: 内存不足（构造请求环境）");
            goto cleanup;
        }
    }

    for (i = 0; environ != NULL && environ[i] != NULL; i++) {
        if (!cgi_key_is_ours(environ[i]))
            nenv++;
    }
    envp = (char **)malloc(sizeof(char *) * (nenv + own_n + 1));
    if (envp == NULL) {
        rc = cgi_fail(out, "cgi: 内存不足（构造请求环境）");
        goto cleanup;
    }
    nenv = 0;
    for (i = 0; environ != NULL && environ[i] != NULL; i++) {
        if (!cgi_key_is_ours(environ[i]))
            envp[nenv++] = environ[i];
    }
    for (i = 0; i < own_n; i++)
        envp[nenv++] = own[i];
    envp[nenv] = NULL;

    if (cgi_spawn(script, envp, &proc) != 0) {
        rc = cgi_fail(out, "cgi: fork/exec 失败: %s", strerror(errno));
        goto cleanup;
    }
    if (cgi_pump(&proc, body, body_len, &raw, &errbuf, &exit_code, why, sizeof(why)) != 0) {
        rc = cgi_fail(out, "cgi: %s（script=%s）", why, script);
        goto cleanup;
    }

    if (raw.len == 0) {
        /* 无输出：不假 hello，把退出码与 stderr 报出来。 */
        rc = cgi_fail(out, "cgi: %s 未产生输出（exit=%ld%s%.*s）", script, exit_code,
                      errbuf.len > 0 ? ", stderr: " : "",
                      errbuf.len > 0 ? (int)errbuf.len : 0,
                      errbuf.len > 0 ? errbuf.p : "");
        goto cleanup;
    }
    cgi_apply_output(out, &raw);
    rc = 0;

cleanup:
    if (proc.pid > 0)
        cgi_kill_reap(&proc);
    for (i = 0; i < own_n; i++)
        free(own[i]);
    free(envp);
    crucible_buf_free(&raw);
    crucible_buf_free(&errbuf);
    return rc;
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
    char pathbuf[1024];
    const char *use;

    if (!g_inited || out == NULL)
        return -1;
    /* P1-1：extra 携带的 .env 变量注入进程环境（子进程继承）；legacy 输入 no-op。 */
    (void)appengine_apply_extra(extra);

    use = resolve_script(script, docroot, pathbuf, sizeof(pathbuf));
    if (use == NULL)
        return cgi_fail(out,
                        "cgi: 未找到 CGI 脚本（script=%s docroot=%s，尝试过 index.cgi / "
                        "cgi-bin/index.cgi）",
                        script != NULL ? script : "(null)",
                        docroot != NULL ? docroot : "(null)");
    return cgi_execute(use, method, path, query, content_type, body, body_len, remote,
                       server_name, server_port, out);
}

void appengine_shutdown(void)
{
    g_inited = 0;
}
