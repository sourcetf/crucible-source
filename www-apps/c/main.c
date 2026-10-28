/*
 * Crucible C 样例 —— 常驻 UDS HTTP/1.1 sidecar（规格 §16.9）。
 *
 * 为什么不是「CGI 风格 printf 后退出」：§16.9 要求 C 样例体现
 *   * 一次拉起、长期驻留（不是 per-request CGI spawn）；
 *   * **pthread per connection**（不是 prefork 占死 worker）；
 *   * HTTP/1.1 keep-alive。
 * 旧 main.c 只打印一段 CGI 头就退出，`/c` 实际一直走 in-process FFI
 * `libapp_c.so`，规格要求的 sidecar 形态在样例里完全看不到。
 *
 * 本程序由 www-apps/c/init.sh 用 `cc -O2 -pthread` 编译到
 * `deps/bin/index`，宿主（src/server/apps/native_http.rs）在**没有 .so**
 * 时把它当持久 sidecar 拉起：
 *
 *   WEBSERVER_LISTEN_UNIX  UDS 绝对路径（必需，缺省见 main）
 *   WEBSERVER_WORKERS      仅记录（本实现是 pthread-per-connection，
 *                          不是固定 worker 池；不存在 prefork 假死）
 *   DOCUMENT_ROOT          docroot（仅用于 CGI 环境展示）
 *   GATEWAY_INTERFACE      CGI/1.1
 *   .env 的键值             由宿主在 spawn 时注入进程 environ
 *
 * 支持 GET / HEAD / POST / PUT；其余方法 405。响应是标准 HTTP/1.1
 * （带 Content-Length），同时把 CGI 语义变量按 `HTTP_*` / `REQUEST_METHOD` /
 * `PATH_INFO` / `QUERY_STRING` / `CONTENT_TYPE` / `CONTENT_LENGTH` 暴露给
 * `?dump=1`（与环境变量同名者优先，便于同一份代码在 CGI 下复用）。
 *
 * 调试/验证用查询参数（均为样例行为，不影响正常路径）：
 *   ?dump=1         返回 CGI 环境摘要（含 APP_HELLO 等 .env 键）
 *   ?echo=1         原样回显请求体
 *   ?delay_ms=N     延迟 N 毫秒（≤5000；仅用于并发验证）
 */

#define _POSIX_C_SOURCE 200809L

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/* 与宿主的上限同量级：header 64KiB、body 32MiB、每连接最多 1000 个请求。 */
#define MAX_LINE_BYTES 8192
#define MAX_HEADER_BYTES (64 * 1024)
#define MAX_HEADERS 64
#define MAX_HEADER_NAME 128
#define MAX_HEADER_VALUE 4096
#define MAX_BODY_BYTES (32 * 1024 * 1024)
#define DEFAULT_MAX_REQUESTS 1000
#define DEFAULT_IDLE_TIMEOUT_SECS 30
#define REQUEST_TIMEOUT_MS 60000
/* 并发 accept 的排队上限：Linux SOMAXCONN=4096，OpenBSD=128（内核会夹取）。
 * 固定 128 在 100 并发下会偶发 EAGAIN（宿主 502），所以用平台上限。 */
#ifndef SOMAXCONN
#define SOMAXCONN 128
#endif
#define LISTEN_BACKLOG SOMAXCONN

typedef struct {
    int fd;
    unsigned char buf[8192];
    size_t off;
    size_t len;
    long long deadline_ms; /* 0 = 不检查（仅连接空闲阶段） */
} Reader;

typedef struct {
    char name[MAX_HEADER_NAME];
    char value[MAX_HEADER_VALUE];
} Header;

typedef struct {
    int fd;
    unsigned long conn_id;
} ConnArg;

typedef struct {
    char *p;
    size_t len;
    size_t cap;
} Buf;

static long long now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;
}

/* pthread_t 在 Linux 是整数、OpenBSD 是指针：统一走 uintptr_t 再转 ulong。 */
static unsigned long thread_id(void)
{
    return (unsigned long)(uintptr_t)pthread_self();
}

static int buf_reserve(Buf *b, size_t extra)
{
    size_t need = b->len + extra + 1;
    char *np;
    size_t cap;

    if (need <= b->cap)
        return 0;
    cap = b->cap ? b->cap : 256;
    while (cap < need)
        cap *= 2;
    np = realloc(b->p, cap);
    if (np == NULL)
        return -1;
    b->p = np;
    b->cap = cap;
    return 0;
}

static int buf_put(Buf *b, const void *data, size_t n)
{
    if (buf_reserve(b, n) != 0)
        return -1;
    memcpy(b->p + b->len, data, n);
    b->len += n;
    b->p[b->len] = '\0';
    return 0;
}

static int buf_puts(Buf *b, const char *s)
{
    return buf_put(b, s, strlen(s));
}

static int buf_printf(Buf *b, const char *fmt, ...)
{
    va_list ap;
    va_list ap2;
    int n;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    n = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (n < 0) {
        va_end(ap2);
        return -1;
    }
    if (buf_reserve(b, (size_t)n) != 0) {
        va_end(ap2);
        return -1;
    }
    vsnprintf(b->p + b->len, b->cap - b->len, fmt, ap2);
    va_end(ap2);
    b->len += (size_t)n;
    return 0;
}

/* ------------------------------------------------------------------ I/O --- */

static int write_all(int fd, const void *data, size_t n)
{
    const char *p = (const char *)data;

    while (n > 0) {
        ssize_t w = write(fd, p, n);
        if (w > 0) {
            p += w;
            n -= (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        return -1;
    }
    return 0;
}

/*
 * 关闭前把对端已发出的输入读掉（有界 50ms）。
 *
 * 为什么需要：Linux 在「接收缓冲还有未读数据」时 close() 会发 RST，客户端可能
 * 因此丢掉我们刚写的 400/413/431 响应（真机：70KB 超长头 → 客户端只看到
 * ECONNRESET）。CGI/sidecar 关闭一个错误请求前把管道排空是标准做法。
 */
static void drain_input(int fd)
{
    char tmp[4096];
    long long deadline = now_ms() + 50;
    int fl = fcntl(fd, F_GETFL, 0);

    if (fl >= 0)
        (void)fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    while (now_ms() < deadline) {
        ssize_t n = recv(fd, tmp, sizeof(tmp), 0);
        if (n > 0)
            continue;
        if (n == 0)
            break;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            struct timespec ts = {0, 1000000L}; /* 1ms */
            nanosleep(&ts, NULL);
            continue;
        }
        if (errno == EINTR)
            continue;
        break;
    }
}

/*
 * 设置每连接的内核 I/O 超时（兜底）。
 *
 * 读路径另用 poll() 按请求 deadline 精确计时；这里是最后一道保险：
 * 即使 poll/read 之间出现不可预期的情况（或写侧对端长期不读导致发送缓冲
 * 满），read/write 也会在 60s 后返回 EAGAIN，而不是让线程永久挂住。
 */
static void set_conn_timeouts(int fd)
{
    struct timeval tv;

    tv.tv_sec = REQUEST_TIMEOUT_MS / 1000;
    tv.tv_usec = 0;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/*
 * 等 fd 可读直到 deadline（CLOCK_MONOTONIC 毫秒）。0 = 可读/已关闭，
 * -1 = 超时或 poll 错误（errno=ETIMEDOUT 表示 deadline 到点）。
 *
 * 为什么不能只靠 read()：阻塞 socket 上的 read() 在**完全没有数据**时
 * 会永久阻塞，函数入口处的 deadline 检查也就永远轮不到 —— 一个连上
 * 不发请求（或只发了半个头）的客户端能永久占住一个 pthread。100 个
 * 这样的连接就把 pthread-per-connection 的并发打满（slowloris）。
 * poll 把等待切成有时间上限的小段，每一段结束后重算剩余时间。
 */
static int reader_wait(int fd, long long deadline_ms)
{
    for (;;) {
        struct pollfd pfd;
        long long remain;
        int pr;

        if (deadline_ms <= 0)
            return 0; /* 无 deadline：维持阻塞语义 */
        remain = deadline_ms - now_ms();
        if (remain <= 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (remain > 60000)
            remain = 60000; /* 单次 poll 上限；醒来后外层重算 */
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        pr = poll(&pfd, 1, (int)remain);
        if (pr > 0)
            return 0; /* 可读 / EOF / 错误：交给 read() 判定 */
        if (pr == 0) {
            errno = ETIMEDOUT;
            return -1;
        }
        if (errno == EINTR)
            continue;
        return -1;
    }
}

static int reader_fill(Reader *r)
{
    for (;;) {
        ssize_t n;

        if (reader_wait(r->fd, r->deadline_ms) != 0)
            return -1;
        n = read(r->fd, r->buf, sizeof(r->buf));
        if (n > 0) {
            r->off = 0;
            r->len = (size_t)n;
            return 0;
        }
        if (n == 0)
            return -1; /* EOF */
        if (errno == EINTR)
            continue;
        return -1;
    }
}

static int reader_getc(Reader *r)
{
    if (r->off == r->len) {
        if (reader_fill(r) != 0)
            return -1;
    }
    return (int)r->buf[r->off++];
}

static int reader_read(Reader *r, void *dst, size_t n)
{
    char *p = (char *)dst;

    while (n > 0) {
        size_t avail;
        size_t take;

        if (r->off == r->len) {
            if (reader_fill(r) != 0)
                return -1;
        }
        avail = r->len - r->off;
        take = avail < n ? avail : n;
        memcpy(p, r->buf + r->off, take);
        r->off += take;
        p += take;
        n -= take;
    }
    return 0;
}

/* -1 = EOF/超时/错误；-2 = 超过缓冲上限。成功返回不含 CRLF 的长度。 */
static int read_line(Reader *r, char *out, size_t cap)
{
    size_t n = 0;

    for (;;) {
        int c = reader_getc(r);

        if (c < 0) {
            out[0] = '\0';
            return -1;
        }
        if (c == '\n') {
            if (n > 0 && out[n - 1] == '\r')
                n--;
            out[n] = '\0';
            return (int)n;
        }
        if (n + 1 >= cap) {
            out[0] = '\0';
            return -2;
        }
        out[n++] = (char)c;
    }
}

static void trim_ws(char *s)
{
    char *p = s;
    size_t n;

    while (*p == ' ' || *p == '\t')
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t'))
        s[--n] = '\0';
}

static const char *header_get(const Header *hs, int nh, const char *name)
{
    int i;

    for (i = 0; i < nh; i++) {
        if (strcasecmp(hs[i].name, name) == 0)
            return hs[i].value;
    }
    return NULL;
}

static int header_has_token(const Header *hs, int nh, const char *name,
                            const char *token)
{
    int i;

    for (i = 0; i < nh; i++) {
        const char *p;
        size_t toklen;

        if (strcasecmp(hs[i].name, name) != 0)
            continue;
        p = hs[i].value;
        toklen = strlen(token);
        while (*p != '\0') {
            const char *comma;
            size_t len;

            while (*p == ',' || *p == ' ' || *p == '\t')
                p++;
            comma = strchr(p, ',');
            len = comma ? (size_t)(comma - p) : strlen(p);
            while (len > 0 && (p[len - 1] == ' ' || p[len - 1] == '\t'))
                len--;
            if (len == toklen && strncasecmp(p, token, len) == 0)
                return 1;
            if (comma == NULL)
                break;
            p = comma + 1;
        }
    }
    return 0;
}

/* 取 `key=value` 的 value 段；返回指针与长度（不含 &）。 */
static const char *query_value(const char *query, const char *key, size_t *vlen)
{
    size_t klen;
    const char *p;

    if (query == NULL || *query == '\0')
        return NULL;
    klen = strlen(key);
    p = query;
    while (*p != '\0') {
        const char *amp = strchr(p, '&');
        size_t seglen = amp ? (size_t)(amp - p) : strlen(p);

        if (seglen >= klen && strncasecmp(p, key, klen) == 0 &&
            (seglen == klen || p[klen] == '=')) {
            if (seglen == klen) {
                *vlen = 0;
                return p + klen;
            }
            *vlen = seglen - klen - 1;
            return p + klen + 1;
        }
        if (amp == NULL)
            break;
        p = amp + 1;
    }
    return NULL;
}

static int query_flag(const char *query, const char *key)
{
    size_t vlen = 0;
    const char *v = query_value(query, key, &vlen);

    if (v == NULL)
        return 0;
    if (vlen == 0)
        return 1;
    if (vlen >= 1 && v[0] == '1')
        return 1;
    if (vlen >= 4 && strncasecmp(v, "true", 4) == 0)
        return 1;
    return 0;
}

static int query_int(const char *query, const char *key, int dflt)
{
    size_t vlen = 0;
    const char *v = query_value(query, key, &vlen);
    char tmp[32];
    char *end = NULL;
    long n;

    if (v == NULL || vlen == 0 || vlen >= sizeof(tmp))
        return dflt;
    memcpy(tmp, v, vlen);
    tmp[vlen] = '\0';
    errno = 0;
    n = strtol(tmp, &end, 10);
    if (errno != 0 || end == tmp)
        return dflt;
    return (int)n;
}

/* ------------------------------------------------------------- responses --- */

static const char *status_reason(int status)
{
    switch (status) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Payload Too Large";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    default:  return "Error";
    }
}

/*
 * 统一响应出口：标准 HTTP/1.1 + CGI 兼容的观测头。
 * `extra` 是额外的头块（已含 CRLF），可为 NULL。
 */
static int send_response(int fd, int status, const char *ctype,
                         const char *extra, const char *body, size_t body_len,
                         int keep_alive, unsigned long conn_id, int req_no,
                         int head_only)
{
    Buf h = {0};
    int rc = -1;

    if (ctype == NULL)
        ctype = "text/plain; charset=utf-8";
    if (buf_printf(&h, "HTTP/1.1 %d %s\r\n", status, status_reason(status)) != 0)
        goto out;
    if (buf_printf(&h, "Content-Type: %s\r\n", ctype) != 0)
        goto out;
    if (buf_printf(&h, "Content-Length: %zu\r\n", body_len) != 0)
        goto out;
    if (buf_puts(&h, "X-Crucible-Engine: c-sidecar\r\n") != 0)
        goto out;
    if (buf_puts(&h, "X-Crucible-Mode: pthread-per-connection\r\n") != 0)
        goto out;
    if (buf_printf(&h, "X-Crucible-Conn: %lu\r\n", conn_id) != 0)
        goto out;
    if (buf_printf(&h, "X-Crucible-Thread: %lx\r\n",
                   thread_id()) != 0)
        goto out;
    if (buf_printf(&h, "X-Crucible-Requests: %d\r\n", req_no) != 0)
        goto out;
    if (buf_puts(&h, "Cache-Control: no-store\r\n") != 0)
        goto out;
    if (keep_alive) {
        if (buf_printf(&h, "Connection: keep-alive\r\n"
                           "Keep-Alive: timeout=%d, max=%d\r\n",
                       DEFAULT_IDLE_TIMEOUT_SECS, DEFAULT_MAX_REQUESTS) != 0)
            goto out;
    } else {
        if (buf_puts(&h, "Connection: close\r\n") != 0)
            goto out;
    }
    if (extra != NULL && *extra != '\0' && buf_puts(&h, extra) != 0)
        goto out;
    if (buf_puts(&h, "\r\n") != 0)
        goto out;
    if (write_all(fd, h.p, h.len) != 0)
        goto out;
    if (!head_only && body_len > 0 && write_all(fd, body, body_len) != 0)
        goto out;
    rc = 0;
out:
    free(h.p);
    return rc;
}

static int send_simple(int fd, int status, const char *msg, int keep_alive,
                       unsigned long conn_id, int req_no, int head_only)
{
    Buf b = {0};
    int rc;

    buf_printf(&b, "%d %s\n", status, status_reason(status));
    if (msg != NULL)
        buf_puts(&b, msg);
    rc = send_response(fd, status, "text/plain; charset=utf-8", NULL,
                       b.p ? b.p : "", b.len, keep_alive, conn_id, req_no,
                       head_only);
    free(b.p);
    return rc;
}

/* ---------------------------------------------------------------- CGI env --- */

/* 请求头名 → `HTTP_*`（大写、`-` 换 `_`）。 */
static void cgi_http_name(const char *name, char *out, size_t cap)
{
    size_t i = 0;
    size_t j = 5;

    if (cap < 6)
        return;
    memcpy(out, "HTTP_", 5);
    while (name[i] != '\0' && j + 1 < cap) {
        unsigned char c = (unsigned char)name[i++];
        out[j++] = (char)(c == '-' ? '_' : toupper(c));
    }
    out[j] = '\0';
}

/*
 * 构造 CGI 环境摘要。`.env` / `HTTP_*` 都从进程 environ 取（CGI 语义）；
 * 本程序作为 sidecar 运行时宿主不会为每个请求 setenv，所以 HTTP_* 回退到
 * 请求头。`APP_HELLO` 是宿主按应用 .env 注入的键，直接展示。
 */
static int build_dump_body(Buf *b, const char *method, const char *path,
                           const char *query, const char *version,
                           const Header *hs, int nh, unsigned long conn_id,
                           int req_no)
{
    int i;
    const char *envv;

    buf_printf(b, "engine=c-sidecar\n");
    buf_printf(b, "pid=%ld\n", (long)getpid());
    buf_printf(b, "conn=%lu\n", conn_id);
    buf_printf(b, "thread=%lx\n", thread_id());
    buf_printf(b, "request=%d\n", req_no);
    buf_printf(b, "method=%s\npath=%s\nquery=%s\nversion=%s\n", method, path,
               query ? query : "", version);
    buf_printf(b, "REQUEST_METHOD=%s\n", method);
    buf_printf(b, "PATH_INFO=%s\n", path);
    buf_printf(b, "QUERY_STRING=%s\n", query ? query : "");
    envv = getenv("DOCUMENT_ROOT");
    buf_printf(b, "DOCUMENT_ROOT=%s\n", envv ? envv : "");
    envv = getenv("GATEWAY_INTERFACE");
    buf_printf(b, "GATEWAY_INTERFACE=%s\n", envv ? envv : "CGI/1.1");
    buf_printf(b, "SERVER_SOFTWARE=crucible/c-sidecar\n");
    envv = getenv("WEBSERVER_LISTEN_UNIX");
    buf_printf(b, "WEBSERVER_LISTEN_UNIX=%s\n", envv ? envv : "");
    envv = getenv("APP_HELLO");
    buf_printf(b, "APP_HELLO=%s\n", envv ? envv : "<unset>");
    for (i = 0; i < nh; i++) {
        char name[MAX_HEADER_NAME + 5];
        const char *value;

        cgi_http_name(hs[i].name, name, sizeof(name));
        value = getenv(name);
        buf_printf(b, "%s=%s\n", name, value ? value : hs[i].value);
        if (strcasecmp(hs[i].name, "content-type") == 0)
            buf_printf(b, "CONTENT_TYPE=%s\n", hs[i].value);
        if (strcasecmp(hs[i].name, "content-length") == 0)
            buf_printf(b, "CONTENT_LENGTH=%s\n", hs[i].value);
    }
    return 0;
}

/* ---------------------------------------------------------------- worker --- */

static void *conn_thread(void *arg)
{
    ConnArg *ca = (ConnArg *)arg;
    int fd = ca->fd;
    unsigned long conn_id = ca->conn_id;
    Header *hs;
    Reader rd;
    int max_requests = DEFAULT_MAX_REQUESTS;
    const char *envn;
    int req_no;

    free(ca);
    pthread_detach(pthread_self());

    envn = getenv("WEBSERVER_MAX_REQUESTS");
    if (envn != NULL && *envn != '\0') {
        long v = strtol(envn, NULL, 10);
        if (v > 0 && v < 1000000)
            max_requests = (int)v;
    }

    hs = calloc(MAX_HEADERS, sizeof(*hs));
    if (hs == NULL) {
        send_simple(fd, 500, "out of memory\n", 0, conn_id, 0, 0);
        close(fd);
        return NULL;
    }
    memset(&rd, 0, sizeof(rd));
    rd.fd = fd;

    fprintf(stderr, "c-sidecar: conn=%lu thread=%lx accepted\n", conn_id,
            thread_id());

    for (req_no = 1; req_no <= max_requests; req_no++) {
        char line[MAX_LINE_BYTES];
        char method[MAX_LINE_BYTES];
        char target[MAX_LINE_BYTES];
        char version[32];
        char *sp1;
        char *sp2;
        char *path;
        char *query = NULL;
        int n;
        int nh = 0;
        int header_too_many = 0;
        size_t header_bytes = 0;
        long long clen = 0;
        char *body = NULL;
        int keep_alive = 0;
        int http11;
        int head_only;
        int echo;
        int delay_ms;
        int fatal = 0;
        const char *te;
        const char *cls;
        const char *ct;
        Buf bodybuf = {0};

        /* 连接空闲阶段：用短 deadline 等下一请求；超时静默关闭。 */
        rd.deadline_ms = now_ms() + (long long)DEFAULT_IDLE_TIMEOUT_SECS * 1000LL;
        do {
            n = read_line(&rd, line, sizeof(line));
        } while (n == 0); /* 容忍请求前的空行 */
        if (n == -2) {
            send_simple(fd, 431, "request line too long\n", 0, conn_id,
                        req_no, 0);
            break;
        }
        if (n < 0)
            break;
        /* 正在处理请求：整个请求（头 + body）共用一个 60s 上限。 */
        rd.deadline_ms = now_ms() + REQUEST_TIMEOUT_MS;

        memcpy(method, line, sizeof(method));
        method[sizeof(method) - 1] = '\0';
        sp1 = strchr(method, ' ');
        if (sp1 == NULL) {
            send_simple(fd, 400, "malformed request line\n", 0, conn_id,
                        req_no, 0);
            break;
        }
        *sp1++ = '\0';
        while (*sp1 == ' ')
            sp1++;
        snprintf(target, sizeof(target), "%s", sp1);
        sp2 = strchr(target, ' ');
        if (sp2 == NULL) {
            send_simple(fd, 400, "malformed request line\n", 0, conn_id,
                        req_no, 0);
            break;
        }
        *sp2++ = '\0';
        while (*sp2 == ' ')
            sp2++;
        snprintf(version, sizeof(version), "%s", sp2);
        if (method[0] == '\0' || target[0] == '\0' ||
            (strcmp(version, "HTTP/1.1") != 0 &&
             strcmp(version, "HTTP/1.0") != 0)) {
            send_simple(fd, 400, "unsupported request line\n", 0, conn_id,
                        req_no, 0);
            break;
        }

        /* 头：逐行读，总量有上限；obs-fold 与无冒号行一律 400。 */
        for (;;) {
            n = read_line(&rd, line, sizeof(line));
            if (n == -2) {
                send_simple(fd, 431, "header line too long\n", 0, conn_id,
                            req_no, 0);
                fatal = 1;
                break;
            }
            if (n < 0) {
                send_simple(fd, 408, "timeout while reading headers\n", 0,
                            conn_id, req_no, 0);
                fatal = 1;
                break;
            }
            if (n == 0)
                break;
            header_bytes += (size_t)n;
            if (header_bytes > MAX_HEADER_BYTES) {
                send_simple(fd, 431, "headers too large\n", 0, conn_id,
                            req_no, 0);
                fatal = 1;
                break;
            }
            if (line[0] == ' ' || line[0] == '\t') {
                send_simple(fd, 400, "obsolete line folding\n", 0, conn_id,
                            req_no, 0);
                fatal = 1;
                break;
            }
            {
                char *colon = strchr(line, ':');
                char *val;

                if (colon == NULL) {
                    send_simple(fd, 400, "malformed header\n", 0, conn_id,
                                req_no, 0);
                    fatal = 1;
                    break;
                }
                *colon = '\0';
                val = colon + 1;
                trim_ws(line);
                trim_ws(val);
                if (line[0] == '\0') {
                    send_simple(fd, 400, "empty header name\n", 0, conn_id,
                                req_no, 0);
                    fatal = 1;
                    break;
                }
                if (nh >= MAX_HEADERS) {
                    header_too_many = 1;
                    continue;
                }
                {
                    size_t nl = strlen(line);
                    size_t vl = strlen(val);

                    if (nl >= sizeof(hs[nh].name) ||
                        vl >= sizeof(hs[nh].value)) {
                        send_simple(fd, 431, "header field too large\n", 0,
                                    conn_id, req_no, 0);
                        fatal = 1;
                        break;
                    }
                    memcpy(hs[nh].name, line, nl + 1);
                    memcpy(hs[nh].value, val, vl + 1);
                }
                nh++;
            }
        }
        if (fatal)
            goto req_done;
        if (header_too_many) {
            send_simple(fd, 431, "too many headers\n", 0, conn_id, req_no, 0);
            goto req_done;
        }

        te = header_get(hs, nh, "transfer-encoding");
        if (te != NULL && *te != '\0') {
            /* 宿主用 Full<Bytes> + Content-Length；chunked 不在本样例范围。 */
            send_simple(fd, 400, "Transfer-Encoding is not supported\n", 0,
                        conn_id, req_no, 0);
            goto req_done;
        }
        cls = header_get(hs, nh, "content-length");
        if (cls != NULL && *cls != '\0') {
            char *end = NULL;

            errno = 0;
            clen = strtol(cls, &end, 10);
            if (errno != 0 || end == cls || *end != '\0' || clen < 0) {
                send_simple(fd, 400, "bad Content-Length\n", 0, conn_id,
                            req_no, 0);
                goto req_done;
            }
            if (clen > MAX_BODY_BYTES) {
                send_simple(fd, 413, "request body too large\n", 0, conn_id,
                            req_no, 0);
                goto req_done;
            }
        }

        head_only = (strcmp(method, "HEAD") == 0);
        if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0 &&
            strcmp(method, "POST") != 0 && strcmp(method, "PUT") != 0) {
            static const char allow[] = "Allow: GET, HEAD, POST, PUT\r\n";
            Buf b = {0};
            buf_printf(&b, "method %s is not supported\n", method);
            send_response(fd, 405, "text/plain; charset=utf-8", allow,
                          b.p ? b.p : "", b.len, 0, conn_id, req_no,
                          head_only);
            free(b.p);
            goto req_done;
        }

        /* Expect: 100-continue（宿主不会发；给通用客户端留正确语义）。 */
        {
            const char *expect = header_get(hs, nh, "expect");
            if (expect != NULL && strcasecmp(expect, "100-continue") == 0 &&
                clen > 0) {
                static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
                if (write_all(fd, cont, sizeof(cont) - 1) != 0)
                    goto req_done;
            }
        }

        if (clen > 0) {
            body = malloc((size_t)clen + 1);
            if (body == NULL) {
                send_simple(fd, 500, "out of memory\n", 0, conn_id, req_no,
                            head_only);
                goto req_done;
            }
            if (reader_read(&rd, body, (size_t)clen) != 0) {
                send_simple(fd, 408, "timeout while reading body\n", 0,
                            conn_id, req_no, head_only);
                goto req_done;
            }
            body[clen] = '\0';
        }

        /* origin-form / absolute-form 都接受；query 只用于样例开关。 */
        path = target;
        if (strncmp(path, "http://", 7) == 0 ||
            strncmp(path, "https://", 8) == 0) {
            /* 跳过 scheme://authority，从 authority 之后找 path；不能直接
             * strchr(path,'/') —— 那会命中 "http://" 里的第一个 '/'，得到
             * "//authority/path" 这种错误路径。 */
            char *authority = path + (path[4] == 's' ? 8 : 7);
            char *slash = strchr(authority, '/');
            static char root_path[] = "/";

            path = (slash != NULL) ? slash : root_path;
        }
        query = strchr(path, '?');
        if (query != NULL) {
            *query++ = '\0';
        }

        http11 = (strcmp(version, "HTTP/1.1") == 0);
        keep_alive = http11
                         ? !header_has_token(hs, nh, "connection", "close")
                         : header_has_token(hs, nh, "connection", "keep-alive");
        if (req_no >= max_requests)
            keep_alive = 0;

        echo = query_flag(query, "echo");
        delay_ms = query_int(query, "delay_ms", 0);
        if (delay_ms < 0)
            delay_ms = 0;
        if (delay_ms > 5000)
            delay_ms = 5000;
        if (delay_ms > 0) {
            struct timespec ts;
            ts.tv_sec = delay_ms / 1000;
            ts.tv_nsec = (long)(delay_ms % 1000) * 1000000L;
            while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
                ;
        }

        if (query_flag(query, "dump")) {
            if (build_dump_body(&bodybuf, method, path, query, version, hs,
                                nh, conn_id, req_no) != 0) {
                send_simple(fd, 500, "out of memory\n", 0, conn_id, req_no,
                            head_only);
                goto req_done;
            }
            n = send_response(fd, 200, "text/plain; charset=utf-8", NULL,
                              bodybuf.p, bodybuf.len, keep_alive, conn_id,
                              req_no, head_only);
        } else if (echo) {
            ct = header_get(hs, nh, "content-type");
            n = send_response(fd, 200,
                              (ct != NULL && *ct != '\0')
                                  ? ct
                                  : "application/octet-stream",
                              NULL, body ? body : "", (size_t)clen,
                              keep_alive, conn_id, req_no, head_only);
        } else {
            const char *hello = getenv("APP_HELLO");
            if (hello == NULL || *hello == '\0')
                hello = "hello from c";
            buf_printf(&bodybuf, "%s path=%s method=%s engine=sidecar "
                                 "conn=%lu thread=%lx body_len=%lld\n",
                       hello, path, method, conn_id,
                       thread_id(), clen);
            n = send_response(fd, 200, "text/plain; charset=utf-8", NULL,
                              bodybuf.p ? bodybuf.p : "", bodybuf.len,
                              keep_alive, conn_id, req_no, head_only);
        }
        if (n != 0) {
            /* 客户端提前关闭/写超时：连接已不可复用。 */
            keep_alive = 0;
        }

req_done:
        free(bodybuf.p);
        free(body);
        if (!keep_alive)
            break;
    }

    free(hs);
    /* 错误响应后客户端可能还在发请求体/超长头：先排空再 close，避免 RST 吞掉响应。 */
    drain_input(fd);
    close(fd);
    fprintf(stderr, "c-sidecar: conn=%lu closed after %d request(s)\n",
            conn_id, req_no);
    return NULL;
}

/* ----------------------------------------------------------------- main --- */

int main(int argc, char **argv)
{
    const char *sock = getenv("WEBSERVER_LISTEN_UNIX");
    struct sockaddr_un addr;
    int lfd;
    unsigned long next_conn = 0;
    const char *workers;

    if (sock == NULL || *sock == '\0') {
        if (argc > 1)
            sock = argv[1];
        else
            sock = "/tmp/crucible-c-sidecar.sock";
    }
    if (strlen(sock) >= sizeof(addr.sun_path)) {
        fprintf(stderr, "c-sidecar: socket path too long: %s\n", sock);
        return 1;
    }

    /* 宿主可能在超时/崩溃后留下 socket 文件；先删再 bind。 */
    unlink(sock);

    signal(SIGPIPE, SIG_IGN);

    lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("c-sidecar: socket");
        return 1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    /* 4.4BSD 系（OpenBSD/FreeBSD）的 sockaddr_un 有 sun_len，bind() 会校验；
     * Linux 没有该字段。 */
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__APPLE__)
    addr.sun_len = (unsigned char)sizeof(addr);
#endif
    memcpy(addr.sun_path, sock, strlen(sock) + 1);
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("c-sidecar: bind");
        close(lfd);
        return 1;
    }
    if (listen(lfd, LISTEN_BACKLOG) != 0) {
        perror("c-sidecar: listen");
        close(lfd);
        unlink(sock);
        return 1;
    }

    workers = getenv("WEBSERVER_WORKERS");
    fprintf(stderr,
            "c-sidecar: listening on %s (pthread-per-connection, "
            "WEBSERVER_WORKERS=%s ignored: one thread per accepted socket)\n",
            sock, workers ? workers : "<unset>");

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        ConnArg *ca;
        pthread_t th;
        int rc;

        if (cfd < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "c-sidecar: accept: %s\n", strerror(errno));
            {
                struct timespec ts = {0, 10 * 1000000L};
                nanosleep(&ts, NULL);
            }
            continue;
        }
        ca = malloc(sizeof(*ca));
        if (ca == NULL) {
            close(cfd);
            continue;
        }
        /* 内核级兜底超时：任何 read/write 都不会无限期占住本线程。 */
        set_conn_timeouts(cfd);
        ca->fd = cfd;
        ca->conn_id = ++next_conn;
        rc = pthread_create(&th, NULL, conn_thread, ca);
        if (rc != 0) {
            fprintf(stderr, "c-sidecar: pthread_create: %s\n", strerror(rc));
            close(cfd);
            free(ca);
            continue;
        }
        /* 线程自己 pthread_detach，连接结束即回收。 */
    }
    close(lfd);
    unlink(sock);
    return 0;
}
