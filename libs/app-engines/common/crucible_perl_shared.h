/* 进程级**唯一**的嵌入式 Perl 解释器 —— 供 libapp_perl.so 与 libapp_psgi.so 共用。
 *
 * 为什么必须唯一（真机证据）：OpenBSD base perl 是 **非线程、非多解释器**构建
 * （`perl -V:useithreads` = undef、`-V:usemultiplicity` = undef）。这种构建里
 * `PL_curinterp` 等全是**进程全局**变量：`perl_alloc()` 出第二个解释器、各线程再
 * `PERL_SET_CONTEXT` 指过去，就会把**另一条线程上正在跑**的调用切到错误解释器上。
 * 症状是 libperl 内部随机崩：OpenBSD 生产机 2026-11-03 的 core 反复落在
 * `Perl_rpp_free_2_ ← Perl_runops_standard ← Perl_call_sv ← appengine_execute(libapp_psgi.so)`；
 * 单独打 /perl/ 或单独打 /psgi/ 都稳（各自只有一个解释器），**两个引擎一起打**才崩
 * —— 这正是「双解释器互相踩全局状态」的指纹。
 *
 * 怎么做到唯一：两个 .so 都提供**同名、默认可见性**的 `crucible_perl_shared_get()`，
 * 且都**只通过 `dlsym(RTLD_DEFAULT, ...)`** 去解析它 —— 该查询返回的是**全局作用域里
 * 先加载的那一份**定义，也就是说：谁先被装载谁就是「所有者」，之后所有 .so 查到的都是
 * 它，于是大家共用它的那份静态实例。
 *
 * 为什么不靠「直接调用 + 符号介入」：实测（scripts/accept-verify-perl-shared.sh 的
 * 同款探针）`dlsym(handle)` 拿到的是**该 handle 自己**的定义，两个 .so 各调各自的
 * `crucible_perl_shared_get()` 会各自返回**自己的**实例 —— 那就是两个解释器。所以
 * 所有者解析必须显式走 `RTLD_DEFAULT`，不能指望调用点被介入。
 *
 * 前提：宿主必须用 RTLD_GLOBAL 装载引擎 .so（`app_ffi` 已显式 `RTLD_NOW|RTLD_GLOBAL`，
 * 规格 §7.1 铁律 3）。若查不到（= 本 .so 未进全局作用域，无从知道有没有同伴），
 * 本头文件**明确失败**而不是再建一个解释器：宁可让该引擎干净地回 502，也不能把整个
 * webserver 打成堆损坏。
 *
 * 验收：`libs/app-engines/common/crucible_perl_shared.h` 导出的
 * `crucible_perl_probe_interp()` 供 scripts 侧断言「两个 .so 拿到同一个解释器」。
 *
 * 注意：本头文件被多个 .so 的各一个 TU 包含 ⇒ `crucible_perl_shared_get` 是**非
 * static 定义**，每次只在一个 TU 里定义一次，不构成重复定义。
 */
#ifndef CRUCIBLE_PERL_SHARED_H
#define CRUCIBLE_PERL_SHARED_H

#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#include <EXTERN.h>
#include <perl.h>

#define CRUCIBLE_PERL_SHARED_MAGIC 0x4350554cUL /* "CPUL" */

typedef struct crucible_perl_shared {
    unsigned long magic;
    char owner[64]; /* 谁建的（诊断用：libapp_psgi.so / libapp_perl.so） */
    PerlInterpreter *interp;
} crucible_perl_shared_t;

/* 本 .so 的实例；跨 .so 由动态链接器的符号介入统一到同一个对象上。 */
crucible_perl_shared_t *crucible_perl_shared_get(void)
{
    static crucible_perl_shared_t inst;
    return &inst;
}

/* 实际生效的那一份（**所有者解析**）：只认 `dlsym(RTLD_DEFAULT)` —— 它返回全局作用域
 * 里先加载的那份定义。返回 NULL = 本 .so 未进全局作用域（宿主没按 RTLD_GLOBAL 装载），
 * 这时无从知道进程里有没有同伴，**绝不能**自己再建一个解释器（见文件头说明）。 */
static crucible_perl_shared_t *crucible_perl_shared_instance(void)
{
    void *sym = dlsym(RTLD_DEFAULT, "crucible_perl_shared_get");

    if (sym == NULL)
        return NULL;
    return ((crucible_perl_shared_t *(*)(void))sym)();
}

/* 取（必要时创建）进程唯一的解释器；NULL = 不可用，原因写进 err。
 *
 * 调用方必须保证**串行**（宿主的 perl 家族单线程串行池；见 app_ffi::pool_family）：
 * 非多解释器 perl 同时只允许一个调用在跑，且这样创建/解析也只发生一次。
 * `-e 0` 只初始化解释器、不跑任何用户代码 —— 脚本在请求期由各引擎自行 eval。 */
static PerlInterpreter *crucible_perl_shared_interp(const char *owner, char *err, size_t errsz)
{
    crucible_perl_shared_t *sh = crucible_perl_shared_instance();

    if (sh == NULL) {
        snprintf(err, errsz,
                 "引擎 .so 未以 RTLD_GLOBAL 装载：无法确定本进程是否已有 Perl 解释器。"
                 "拒绝再建一个（目标机 perl 多实例不安全），请让宿主用 "
                 "RTLD_NOW|RTLD_GLOBAL dlopen 引擎 .so");
        return NULL;
    }
    if (sh->magic == CRUCIBLE_PERL_SHARED_MAGIC)
        return sh->interp;
    {
        /* static：perl_parse 会保留 argv 指针（PL_origargv），指向栈上数组会在之后
         * 被 GC/错误路径解引用 —— 真机实测段错误。 */
        static char *embedding[] = {(char *)"crucible-perl", (char *)"-e", (char *)"0"};
        int argc = 3;
        char **argv = embedding;
        char **env = NULL;
        PerlInterpreter *p;

        PERL_SYS_INIT3(&argc, &argv, &env); /* 按文档：每进程一次 */
        p = perl_alloc();
        if (p == NULL) {
            snprintf(err, errsz, "perl_alloc 失败");
            return NULL;
        }
        perl_construct(p);
        if (perl_parse(p, NULL, 3, embedding, NULL) != 0) {
            /* argv[1] 是 `-e`，argv[2] 是 `0`：既不当脚本文件打开、也不跑用户代码。
             * （传普通名字会被 perl 当成脚本路径，直接 "Can't open perl script"。） */
            snprintf(err, errsz, "perl_parse(-e 0) 失败");
            return NULL;
        }
        (void)perl_run(p); /* 只跑 BEGIN 块 */
        sh->interp = p;
        snprintf(sh->owner, sizeof(sh->owner), "%s", owner != NULL ? owner : "?");
        sh->magic = CRUCIBLE_PERL_SHARED_MAGIC;
    }
    return sh->interp;
}

/* **验收探针**（默认可见性导出，供 scripts 断言，不参与请求路径）：
 * 确保共享解释器就绪并返回它。同一个进程里对**任意**两个引擎 .so 各调一次，
 * 两次必须返回**同一个**非空指针 —— 这就是「单解释器」不变量的可执行证据
 * （见 scripts/accept-verify-perl-shared.sh）。 */
PerlInterpreter *crucible_perl_probe_interp(void)
{
    char err[256];

    return crucible_perl_shared_interp("probe", err, sizeof(err));
}

#endif /* CRUCIBLE_PERL_SHARED_H */
