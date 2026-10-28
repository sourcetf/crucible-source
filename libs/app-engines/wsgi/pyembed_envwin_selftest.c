/*
 * pyembed_envwin_selftest.c —— 「同内容组并发请求都能看见自己的 .env」回归自测。
 *
 * 复现/守住的缺陷（apps6-wave11 §7.1，pre-existing P2，本文件同目录的
 * ../../common/crucible_pyembed.h 于 wave-12 修复）：
 *   同一应用的并发请求在 Rust 侧 env_lock 里被判为「同内容组」而**允许并发**，
 *   但 os.environ 是解释器全局的缓存映射。旧实现每个请求各记一份「请求前状态」、
 *   各自恢复一次 ⇒ 最早完成的那个把 .env 键删掉，其余仍在飞的同组请求（sleep 之后
 *   才读 os.environ 的）读到 `<unset>`。真机实测 8 并发 `/wsgi-a/?sleep=2`
 *   → 1 有值 / 7 `<unset>`，且压力下（同组高并发 + 换组）失败率可达 ~46%。
 *
 * 本自测直接调用与 libapp_wsgi.so 完全相同的 crucible_py_wsgi_request（include 同一份
 * crucible_pyembed.h），不需要起 webserver，也不需要 Rust 侧——因此可以在 CI/开发机
 * 上当作「pyembed 并发语义」的回归哨兵：
 *
 *   # 修复版（工作树）：应当 PASS（N 个并发请求全部看到自己的 .env）
 *   cc -O2 -fPIC -pthread -Wall -Werror=implicit-function-declaration \
 *      -I<repo>/libs/app-engines/include -I<repo>/libs/app-engines/common \
 *      -o /tmp/envwin_test pyembed_envwin_selftest.c \
 *      <repo>/libs/app-engines/common/appengine_common.c \
 *      <repo>/libs/app-engines/common/appengine_util.c
 *   /tmp/envwin_test 8 && echo OK
 *
 *   # 旧版（把 HEAD 的 crucible_pyembed.h 放到 -I 优先目录）：应当 FAIL（1 有值 / N-1 <unset>）
 *   git show HEAD:libs/app-engines/common/crucible_pyembed.h > /tmp/head-pyembed/crucible_pyembed.h
 *   cc ... -I/tmp/head-pyembed -I<repo>/libs/app-engines/common ...
 *
 * 覆盖的三条不变量：
 *   A) 同组并发：N 个带同一份 .env 的并发请求**全部**看到自己的值（本修复）；
 *   B) 无残留：并发组结束后，紧随其后的请求在 os.environ 里看不到上一组的键
 *      （窗口「最后一个离开者恢复」语义没坏，也是 apps3b §6.1 那条 P1 的守卫）；
 *   C) 可重复：多轮（默认 2 轮）反复开窗/关窗不出错。
 *
 * 关键细节（为什么先要一次「预热」请求）：真实服务器里 Py_Initialize 发生在启动期
 * （运维环境），.env 键是请求期才临时进 C environ 的；若解释器初始化时该键已存在，
 * os.environ 的初始快照里就有它（先验 == 现值 ⇒ 不记账），竞态反而复现不出来。
 * 因此本自测先跑一个不带 .env 的请求完成解释器初始化，再 setenv 模拟 env_lock 安装。
 *
 * 用法：envwin_selftest [N] [--rounds R] [--sleep S]
 *   N 默认 8（真机回归里试过 8/16/32 全绿）；sleep 默认 1 秒（sleep 之后才读 os.environ，
 *   正是竞态窗口所在的形态）。退出码 0 = 全部通过。
 */
#include "appengine.h"
#include "appengine_common.h"
#include "crucible_embed.h"
#include "crucible_pyembed.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ENVWIN_NMAX 128

/* 被测应用：睡 sleep 秒**之后**才读 os.environ（竞态窗口就在这里）。 */
static const char *g_app_src =
    "import os\n"
    "import re\n"
    "import time\n"
    "\n"
    "\n"
    "def application(environ, start_response):\n"
    "    q = environ.get('QUERY_STRING', '') or ''\n"
    "    m = re.search(r'sleep=([0-9.]+)', q)\n"
    "    if m:\n"
    "        time.sleep(float(m.group(1)))\n"
    "    v = os.environ.get('WINDOWMARK')\n"
    "    body = ('WINDOWMARK=%s\\n' % (v if v is not None else '<unset>')).encode()\n"
    "    start_response('200 OK', [('Content-Type', 'text/plain')])\n"
    "    return [body]\n"
    "\n"
    "\n"
    "app = application\n";

typedef struct {
    const char *script;
    const char *query;
    int env_dirty;
    int status;
    char body[256];
} envwin_job;

static void *envwin_run_one(void *arg)
{
    envwin_job *j = (envwin_job *)arg;
    AppEngineResult out;
    int rc;

    memset(&out, 0, sizeof(out));
    j->status = 0;
    j->body[0] = '\0';
    /* 与 app_ffi::call_exec 同一条路径（env_dirty = 本请求带 .env）。 */
    /* R-03：请求 `.env` 现以 ABI `extra` JSON 下发（不再依赖进程 env）。 */
    rc = crucible_py_wsgi_request(
        "wsgi", j->script, NULL, "GET", "/", j->query, NULL, NULL, 0, "127.0.0.1",
        "localhost", 80,
        j->env_dirty
            ? "{\"engine\":\"wsgi\",\"env\":{\"WINDOWMARK\":\"from-selftest\"}}"
            : "wsgi",
        NULL, &out);
    j->status = out.status;
    if (rc == 0 && out.body != NULL && out.body_len > 0 &&
        out.body_len < sizeof(j->body)) {
        memcpy(j->body, out.body, out.body_len);
        j->body[out.body_len] = '\0';
    }
    appengine_result_free(&out);
    return NULL;
}

/* 并发跑 n 个请求（都应看到 WINDOWMARK=from-selftest），返回「看到正确值」的个数。 */
static int envwin_fire(const char *script, int n, const char *query, int env_dirty,
                       char *summary, size_t summary_sz)
{
    pthread_t th[ENVWIN_NMAX];
    envwin_job jobs[ENVWIN_NMAX];
    const char *want = "WINDOWMARK=from-selftest";
    int i, good = 0;

    if (n > ENVWIN_NMAX)
        n = ENVWIN_NMAX;
    summary[0] = '\0';
    for (i = 0; i < n; i++) {
        jobs[i].script = script;
        jobs[i].query = query;
        jobs[i].env_dirty = env_dirty;
        if (pthread_create(&th[i], NULL, envwin_run_one, &jobs[i]) != 0)
            return -1;
    }
    for (i = 0; i < n; i++)
        pthread_join(th[i], NULL);
    for (i = 0; i < n; i++) {
        int hit = strstr(jobs[i].body, want) != NULL;
        if (hit)
            good++;
        else
            snprintf(summary, summary_sz, "第一个异常响应: status=%d body=%s",
                     jobs[i].status, jobs[i].body[0] ? jobs[i].body : "(empty)");
    }
    return good;
}

static void envwin_fire_one(const char *script, const char *query, int env_dirty,
                            char *body_out, size_t body_sz)
{
    envwin_job j;

    j.script = script;
    j.query = query;
    j.env_dirty = env_dirty;
    envwin_run_one(&j);
    snprintf(body_out, body_sz, "%s", j.body);
}

int main(int argc, char **argv)
{
    char script[256];
    char query[32];
    char summary[512];
    char body[512];
    const char *tmpdir;
    int n = 8, rounds = 2, i, fails = 0;
    double sleep_s = 1.0;
    FILE *f;

    if (argc > 1)
        n = atoi(argv[1]);
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--rounds") == 0 && i + 1 < argc)
            rounds = atoi(argv[++i]);
        else if (strcmp(argv[i], "--sleep") == 0 && i + 1 < argc)
            sleep_s = atof(argv[++i]);
    }

    tmpdir = getenv("TMPDIR");
    snprintf(script, sizeof(script), "%s/crucible_envwin_selftest_%d.py",
             tmpdir != NULL && tmpdir[0] != '\0' ? tmpdir : "/tmp", (int)getpid());
    f = fopen(script, "w");
    if (f == NULL) {
        fprintf(stderr, "无法写测试脚本 %s\n", script);
        return 2;
    }
    fputs(g_app_src, f);
    fclose(f);
    snprintf(query, sizeof(query), "sleep=%g", sleep_s);

    /* 预热：先初始化解释器（见文件头说明），再做带 .env 的并发。 */
    unsetenv("WINDOWMARK");
    envwin_fire_one(script, "", 0, body, sizeof(body));
    printf("warmup: %s", body[0] ? body : "(empty)\n");

    for (i = 0; i < rounds; i++) {
        int good;

        setenv("WINDOWMARK", "from-selftest", 1); /* 模拟 Rust env_lock::install */
        summary[0] = '\0';
        good = envwin_fire(script, n, query, 1, summary, sizeof(summary));
        printf("round %d: %d/%d 并发请求看见自己的 .env\n", i + 1, good, n);
        if (good != n) {
            printf("  FAIL: 期望 %d/%d —— %s\n", n, n, summary);
            fails++;
        }
        /* 无残留：全部结束后，os.environ 里不得还有上一组的键。 */
        unsetenv("WINDOWMARK"); /* 模拟 env_lock 恢复 C environ */
        envwin_fire_one(script, "", 1, body, sizeof(body));
        if (strstr(body, "WINDOWMARK=<unset>") == NULL) {
            printf("  FAIL: 上一组的 .env 键在 os.environ 里残留：%s", body);
            fails++;
        }
    }
    unlink(script);
    printf("%s: %d round(s), %d failure(s)\n", fails ? "FAIL" : "PASS", rounds, fails);
    return fails ? 1 : 0;
}
