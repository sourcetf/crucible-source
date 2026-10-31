/*
 * Lua app-engine — PUC-Lua with ngx.say / ngx.header / ngx.var stubs.
 *
 * Thread safety: each request creates its own lua_State and stores ngx_ctx_t*
 * in the Lua registry (lightuserdata key). A process-wide mutex serializes
 * init and protects the rare shared fallback path. Never share one lua_State
 * across threads.
 */
#include "appengine.h"
#include "appengine_common.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <pthread.h>
static pthread_mutex_t g_lua_mutex = PTHREAD_MUTEX_INITIALIZER;
#define LUA_LOCK()   pthread_mutex_lock(&g_lua_mutex)
#define LUA_UNLOCK() pthread_mutex_unlock(&g_lua_mutex)
#else
#define LUA_LOCK()   ((void)0)
#define LUA_UNLOCK() ((void)0)
#endif

#ifdef CRUCIBLE_HAVE_LUA
#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>


#ifndef LUA_OK
#define LUA_OK 0
#endif

/* ═══════════════ 每请求资源上限 ═══════════════════════════════════════════
 *
 * 旧实现没有**任何**上限：`while true do end` 只能等宿主 60s 看门狗判超时，
 * 而看门狗只能「放弃线程 + 隔离该 .so」—— 被放弃的 C 调用永久烧满一个核，
 * 且该引擎直到重启 webserver 都不可用（apps5b §1.3 真机记录）。本引擎现在在
 * Lua VM 内用 count hook 检查墙钟 deadline，纯 Lua 死循环（含协程）在 5s 内
 * 干净地以 Lua error 返回，C 调用正常结束、worker 不被放弃、.so 不被隔离。
 *
 * 另外两道上限防止内存 DoS：
 *   * lua_State 用自定义分配器记账（默认 32MiB/请求）：`string.rep("x", 1e9)`
 *     得到 "not enough memory" 的普通 Lua error，而不是把进程 RSS 撑爆；
 *   * `ngx.say` 的响应体缓冲在 C 堆上（绕过 Lua 分配器），单独限 64MiB，
 *     与宿主 UPSTREAM_BODY_CAP 一致。
 *
 * 默认值可用**启动期基底环境**（appengine_base_env_block，不含请求 .env）覆盖：
 *   CRUCIBLE_LUA_TIMEOUT_MS   纯 Lua 执行墙钟上限（默认 5000，0 = 关闭）
 *   CRUCIBLE_LUA_MAX_MEM_MB   lua_State 堆上限（默认 32，0 = 不限）
 */
#define CRUCIBLE_LUA_DEFAULT_TIMEOUT_MS 5000L
#define CRUCIBLE_LUA_DEFAULT_MAX_MEM_MB 32UL
#define CRUCIBLE_LUA_MAX_BODY_BYTES (64UL * 1024UL * 1024UL)
#define CRUCIBLE_LUA_HOOK_INSN_COUNT 10000

typedef struct {
    size_t used;
    size_t limit; /* 0 = 不限制 */
} lua_mem_limiter;

/* lua_Alloc：先记账、超限返回 NULL（Lua 会抛 "not enough memory"）。 */
static void *lua_limited_alloc(void *ud, void *ptr, size_t osize, size_t nsize) {
    lua_mem_limiter *m = (lua_mem_limiter *)ud;
    void *np;

    if (nsize == 0) {
        if (ptr != NULL) {
            free(ptr);
            if (osize <= m->used)
                m->used -= osize;
            else
                m->used = 0;
        }
        return NULL;
    }
    if (nsize > osize && m->limit > 0) {
        size_t grow = nsize - osize;
        if (m->used > m->limit || grow > m->limit - m->used)
            return NULL;
    }
    np = realloc(ptr, nsize);
    if (np == NULL)
        return NULL;
    if (nsize >= osize) {
        m->used += nsize - osize;
    } else {
        size_t shrink = osize - nsize;
        m->used = shrink <= m->used ? m->used - shrink : 0;
    }
    return np;
}

static long lua_now_ms(void) {
#ifdef _WIN32
    return (long)(clock() * 1000L / CLOCKS_PER_SEC);
#else
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (long)(ts.tv_sec * 1000L + ts.tv_nsec / 1000000L);
#endif
}

static long g_lua_timeout_ms = CRUCIBLE_LUA_DEFAULT_TIMEOUT_MS;
static size_t g_lua_mem_limit = (size_t)CRUCIBLE_LUA_DEFAULT_MAX_MEM_MB * 1024UL * 1024UL;
/* Registry key：deadline 存在 registry（同一 lua_State 的协程共享），
 * hook 从 registry 读取，因此主线程和每个被 resume 的协程用同一个 deadline。 */
static char g_lua_deadline_key;

#ifndef _WIN32
static pthread_once_t g_lua_cfg_once = PTHREAD_ONCE_INIT;
#define LUA_CFG_ONCE(fn) pthread_once(&g_lua_cfg_once, fn)
#else
static int g_lua_cfg_done;
#define LUA_CFG_ONCE(fn)          \
    do {                          \
        if (!g_lua_cfg_done) {    \
            g_lua_cfg_done = 1;   \
            (fn)();               \
        }                         \
    } while (0)
#endif

/* 从启动期基底块（K=V\0…）里读一个十进制数值；找不到/不合法返回 0。 */
static int lua_base_env_u64(const char *block, const char *key, unsigned long long *out) {
    size_t klen = strlen(key);
    const char *p = block;

    if (block == NULL)
        return 0;
    while (*p != '\0') {
        const char *eq = strchr(p, '=');
        char *end = NULL;
        unsigned long long v;

        if (eq == NULL)
            break;
        if ((size_t)(eq - p) == klen && memcmp(p, key, klen) == 0) {
            v = strtoull(eq + 1, &end, 10);
            if (end == eq + 1)
                return 0;
            while (*end == ' ' || *end == '\t')
                end++;
            if (*end != '\0')
                return 0;
            *out = v;
            return 1;
        }
        p = eq + strlen(eq) + 1;
    }
    return 0;
}

static void lua_load_cfg(void) {
    const char *base = appengine_base_env_block();
    unsigned long long v;

    if (lua_base_env_u64(base, "CRUCIBLE_LUA_TIMEOUT_MS", &v)) {
        if (v > 300000ULL) /* 5min 封顶；更长的请求应走宿主看门狗/外部队列 */
            v = 300000ULL;
        g_lua_timeout_ms = (long)v;
    }
    if (lua_base_env_u64(base, "CRUCIBLE_LUA_MAX_MEM_MB", &v)) {
        if (v > 4096ULL)
            v = 4096ULL;
        g_lua_mem_limit = (size_t)v * 1024UL * 1024UL;
    }
}

static void lua_ensure_cfg(void) { LUA_CFG_ONCE(lua_load_cfg); }

/* count hook：每 N 条指令检查一次墙钟。命中 → 普通 Lua error（lua_pcall 捕获），
 * 调用栈正常返回宿主，worker 线程不会被放弃。 */
static void lua_timeout_hook(lua_State *L, lua_Debug *ar) {
    long deadline;

    (void)ar;
    lua_pushlightuserdata(L, (void *)&g_lua_deadline_key);
    lua_rawget(L, LUA_REGISTRYINDEX);
    deadline = (long)lua_tointeger(L, -1);
    lua_pop(L, 1);
    if (deadline > 0 && lua_now_ms() >= deadline)
        /* luaL_error 的格式串只认 %s/%d/%f/%p/%c/%U/%I/%%（%ld 会变成
         * "invalid option '%l'"），所以这里显式转 int。 */
        (void)luaL_error(L, "lua: execution timeout after %d ms", (int)g_lua_timeout_ms);
}

/* 给一个（可能是协程的）lua_State 装上同一 deadline 的 count hook。
 * 协程是独立的 lua_State，主线程的 hook 在 coroutine.resume() 内部不计数 ——
 * 不显式安装的话 `coroutine.wrap(function() while true do end end)()` 会绕过
 * 全部超时保护（真机基线实测 6s 后被宿主看门狗放弃线程）。 */
static void lua_apply_hook(lua_State *co) {
    if (g_lua_timeout_ms <= 0 || co == NULL)
        return;
    lua_pushlightuserdata(co, (void *)&g_lua_deadline_key);
    lua_rawget(co, LUA_REGISTRYINDEX);
    if (lua_isnumber(co, -1)) {
        lua_pop(co, 1);
        lua_sethook(co, lua_timeout_hook, LUA_MASKCOUNT, CRUCIBLE_LUA_HOOK_INSN_COUNT);
    } else {
        lua_pop(co, 1);
    }
}

static void lua_install_timeout(lua_State *L) {
    if (g_lua_timeout_ms <= 0)
        return;
    lua_pushlightuserdata(L, (void *)&g_lua_deadline_key);
    lua_pushinteger(L, (lua_Integer)(lua_now_ms() + g_lua_timeout_ms));
    lua_rawset(L, LUA_REGISTRYINDEX);
    lua_sethook(L, lua_timeout_hook, LUA_MASKCOUNT, CRUCIBLE_LUA_HOOK_INSN_COUNT);
}

/* ── coroutine.create/resume/wrap 包装：创建/恢复前把 hook 装到子线程 ── */
static int l_crucible_co_create(lua_State *L) {
    int n = lua_gettop(L);

    lua_pushvalue(L, lua_upvalueindex(1)); /* 原 coroutine.create */
    lua_insert(L, 1);
    lua_call(L, n, 1);
    if (lua_isthread(L, -1))
        lua_apply_hook(lua_tothread(L, -1));
    return 1;
}

static int l_crucible_co_resume(lua_State *L) {
    int n = lua_gettop(L);

    if (n >= 1 && lua_isthread(L, 1))
        lua_apply_hook(lua_tothread(L, 1));
    lua_pushvalue(L, lua_upvalueindex(1)); /* 原 coroutine.resume */
    lua_insert(L, 1);
    lua_call(L, n, LUA_MULTRET);
    return lua_gettop(L);
}

static int l_crucible_co_wrap_run(lua_State *L) {
    int n = lua_gettop(L);
    int top;

    lua_State *co = lua_tothread(L, lua_upvalueindex(1));
    lua_apply_hook(co);
    lua_pushvalue(L, lua_upvalueindex(1)); /* co */
    lua_pushvalue(L, lua_upvalueindex(2)); /* 原 resume */
    lua_insert(L, 1);                      /* resume → 1 */
    lua_insert(L, 2);                      /* co → 2 */
    lua_call(L, n + 1, LUA_MULTRET);
    top = lua_gettop(L);
    if (top >= 1 && !lua_toboolean(L, 1)) {
        if (top >= 2) {
            lua_pushvalue(L, 2);
            return lua_error(L);
        }
        return luaL_error(L, "coroutine failed");
    }
    lua_remove(L, 1); /* 去掉 resume 的 true */
    return lua_gettop(L);
}

static int l_crucible_co_wrap(lua_State *L) {
    /* upvalue 1 = 原 create；2 = 原 resume */
    if (lua_gettop(L) < 1)
        return luaL_error(L, "bad argument #1 to 'wrap' (function expected)");
    lua_pushvalue(L, lua_upvalueindex(1));
    lua_pushvalue(L, 1);
    lua_call(L, 1, 1);
    if (!lua_isthread(L, -1))
        return luaL_error(L, "coroutine.create failed");
    lua_apply_hook(lua_tothread(L, -1));
    lua_pushvalue(L, -1);                  /* co（upvalue 1） */
    lua_pushvalue(L, lua_upvalueindex(2)); /* 原 resume（upvalue 2） */
    lua_pushcclosure(L, l_crucible_co_wrap_run, 2);
    lua_remove(L, -2); /* 去掉 co，留下闭包 */
    return 1;
}

static void lua_install_libs_guard(lua_State *L) {
    lua_getglobal(L, "coroutine");
    if (lua_istable(L, -1)) {
        lua_getfield(L, -1, "create");
        if (lua_isfunction(L, -1)) {
            lua_pushcclosure(L, l_crucible_co_create, 1);
            lua_setfield(L, -2, "create");
        } else {
            lua_pop(L, 1);
        }
        lua_getfield(L, -1, "resume");
        if (lua_isfunction(L, -1)) {
            lua_pushcclosure(L, l_crucible_co_resume, 1);
            lua_setfield(L, -2, "resume");
        } else {
            lua_pop(L, 1);
        }
        lua_getfield(L, -1, "create");
        lua_getfield(L, -2, "resume");
        if (lua_isfunction(L, -2) && lua_isfunction(L, -1)) {
            lua_pushcclosure(L, l_crucible_co_wrap, 2);
            lua_setfield(L, -2, "wrap");
        } else {
            lua_pop(L, 2);
        }
    }
    lua_pop(L, 1);
}

/* os.exit() 直接 exit(3) —— 会把整个 webserver 打死（真机基线：一次请求后
 * 进程消失、客户端 empty reply）。改成 Lua error：应用可以捕获，未捕获则 500。 */
static int l_crucible_os_exit(lua_State *L) {
    (void)L;
    return luaL_error(L, "lua: os.exit is disabled in the embedded engine");
}

/* os.setlocale 改的是**进程级** C locale（不是 lua_State 自己的）：一个请求改
 * LC_NUMERIC/LC_CTYPE 会影响同进程其它请求/引擎的数字格式与大小写映射。查询
 * （第二参数为 nil）放行，设置一律拒绝。 */
static int l_crucible_os_setlocale(lua_State *L) {
    int n = lua_gettop(L);

    /* os.setlocale(locale [, category])：arg1 非 nil 就是设置；查询是
     * os.setlocale(nil) / os.setlocale(nil, cat) / os.setlocale()。 */
    if (n >= 1 && !lua_isnoneornil(L, 1))
        return luaL_error(L, "lua: os.setlocale is disabled (process-global state)");
    lua_pushvalue(L, lua_upvalueindex(1)); /* 原 os.setlocale */
    lua_insert(L, 1);
    lua_call(L, n, LUA_MULTRET);
    return lua_gettop(L);
}

static void lua_install_os_guard(lua_State *L) {
    lua_getglobal(L, "os");
    if (lua_istable(L, -1)) {
        lua_pushcfunction(L, l_crucible_os_exit);
        lua_setfield(L, -2, "exit");
        lua_getfield(L, -1, "setlocale");
        if (lua_isfunction(L, -1)) {
            lua_pushcclosure(L, l_crucible_os_setlocale, 1);
            lua_setfield(L, -2, "setlocale");
        } else {
            lua_pop(L, 1);
        }
    }
    lua_pop(L, 1);
}

/* 应用私有模块：把 docroot 放在 package.path 最前（`require "lib.util"` 可加载
 * 应用自己的 Lua 模块）。默认的 ./?.lua 等系统项保留，避免破坏既有应用。 */
static void lua_prepend_package_path(lua_State *L, const char *dir) {
    const char *old;

    if (dir == NULL || dir[0] == '\0')
        return;
    lua_getglobal(L, "package");
    if (!lua_istable(L, -1)) {
        lua_pop(L, 1);
        return;
    }
    lua_getfield(L, -1, "path");
    if (!lua_isstring(L, -1)) {
        lua_pop(L, 2);
        return;
    }
    old = lua_tostring(L, -1);
    lua_pushfstring(L, "%s/?.lua;%s/?/init.lua;%s", dir, dir, old ? old : "");
    lua_setfield(L, -3, "path");
    lua_pop(L, 2);
}

/*
 * luaL_tolstring arrived in Lua 5.2. OpenBSD ships lua-5.1; implement a
 * compatible helper that always leaves a string on the stack (same contract).
 */
static const char *crucible_lua_tolstring(lua_State *L, int idx, size_t *len) {
    if (idx < 0 && idx > LUA_REGISTRYINDEX)
        idx = lua_gettop(L) + idx + 1;
    if (luaL_callmeta(L, idx, "__tostring")) {
        if (!lua_isstring(L, -1))
            luaL_error(L, "'__tostring' must return a string");
    } else {
        int t = lua_type(L, idx);
        if (t == LUA_TNUMBER || t == LUA_TSTRING) {
            lua_pushvalue(L, idx);
            /* Ensure a string representation (converts numbers in-place). */
            if (!lua_isstring(L, -1))
                (void)lua_tostring(L, -1);
        } else if (t == LUA_TBOOLEAN) {
            lua_pushstring(L, lua_toboolean(L, idx) ? "true" : "false");
        } else if (t == LUA_TNIL) {
            lua_pushliteral(L, "nil");
        } else {
            lua_pushfstring(L, "%s: %p", luaL_typename(L, idx),
                            lua_topointer(L, idx));
        }
    }
    return lua_tolstring(L, -1, len);
}

typedef struct {
    char *body;
    size_t body_len;
    size_t body_cap;
    char headers[2048];
    size_t headers_len;
    int status;
    int exited;      /* ngx.exit() 触发：有意终止，不是应用错误 */
    int body_failed; /* 响应体超过上限/分配失败 */
} ngx_ctx_t;

/* Registry key for per-state ngx_ctx_t* (address of this static is unique). */
static char ngx_ctx_regkey;

static ngx_ctx_t *ngx_ctx_from(lua_State *L) {
    lua_pushlightuserdata(L, (void *)&ngx_ctx_regkey);
    lua_gettable(L, LUA_REGISTRYINDEX);
    ngx_ctx_t *c = (ngx_ctx_t *)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return c;
}

static void ngx_ctx_bind(lua_State *L, ngx_ctx_t *c) {
    lua_pushlightuserdata(L, (void *)&ngx_ctx_regkey);
    lua_pushlightuserdata(L, (void *)c);
    lua_settable(L, LUA_REGISTRYINDEX);
}

static int ngx_ctx_ensure(ngx_ctx_t *c) {
    if (c->body)
        return 0;
    c->body_cap = 4096;
    c->body = (char *)malloc(c->body_cap);
    if (!c->body)
        return -1;
    c->body_len = 0;
    c->body[0] = '\0';
    c->headers[0] = '\0';
    c->headers_len = 0;
    c->status = 200;
    return 0;
}

static int ngx_append(ngx_ctx_t *c, const char *s, size_t n) {
    if (ngx_ctx_ensure(c) != 0) {
        c->body_failed = 1;
        return -1;
    }
    /* 响应体缓冲在 C 堆上，不受 Lua 分配器上限约束 ⇒ 单独封顶。 */
    if (n > CRUCIBLE_LUA_MAX_BODY_BYTES - c->body_len) {
        c->body_failed = 1;
        return -1;
    }
    while (c->body_len + n + 1 > c->body_cap) {
        size_t nc = c->body_cap * 2;
        char *nb;
        if (nc < c->body_cap) { /* 溢出兜底 */
            c->body_failed = 1;
            return -1;
        }
        nb = (char *)realloc(c->body, nc);
        if (!nb) {
            c->body_failed = 1;
            return -1;
        }
        c->body = nb;
        c->body_cap = nc;
    }
    memcpy(c->body + c->body_len, s, n);
    c->body_len += n;
    c->body[c->body_len] = '\0';
    return 0;
}

static int lua_body_overflow(lua_State *L) {
    return luaL_error(L, "lua: response body exceeds %d bytes (or out of memory)",
                      (int)CRUCIBLE_LUA_MAX_BODY_BYTES);
}

static int l_ngx_say(lua_State *L) {
    ngx_ctx_t *c = ngx_ctx_from(L);
    int n = lua_gettop(L);
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char *s = crucible_lua_tolstring(L, i, &len);
        if (s && c && ngx_append(c, s, len) != 0)
            return lua_body_overflow(L);
        lua_pop(L, 1);
        if (i < n && c && ngx_append(c, "\t", 1) != 0)
            return lua_body_overflow(L);
    }
    if (c && ngx_append(c, "\n", 1) != 0)
        return lua_body_overflow(L);
    return 0;
}

static int l_ngx_print(lua_State *L) {
    ngx_ctx_t *c = ngx_ctx_from(L);
    int n = lua_gettop(L);
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char *s = crucible_lua_tolstring(L, i, &len);
        if (s && c && ngx_append(c, s, len) != 0)
            return lua_body_overflow(L);
        lua_pop(L, 1);
    }
    return 0;
}

static int l_ngx_header_index(lua_State *L) {
    (void)L;
    return 0;
}

static int l_ngx_header_newindex(lua_State *L) {
    ngx_ctx_t *c = ngx_ctx_from(L);
    const char *k = luaL_checkstring(L, 2);
    const char *v = luaL_checkstring(L, 3);
    if (c && k && v) {
        char line[512];
        int n = snprintf(line, sizeof(line), "%s: %s\r\n", k, v);
        /* 头值超过 ~505 字节时 snprintf 返回「本来要写多长」> sizeof(line)，
         * 后面的 memcpy 会读出 line 之外的栈数据。先夹到缓冲区真实容量。 */
        if (n > 0 && (size_t)n > sizeof(line) - 1)
            n = (int)sizeof(line) - 1;
        if (n > 0 && c->headers_len + (size_t)n + 1 < sizeof(c->headers)) {
            memcpy(c->headers + c->headers_len, line, (size_t)n);
            c->headers_len += (size_t)n;
            c->headers[c->headers_len] = '\0';
        }
    }
    return 0;
}

static int l_ngx_var_index(lua_State *L) {
    const char *k = luaL_checkstring(L, 2);
    if (!k) {
        lua_pushnil(L);
        return 1;
    }
    lua_getfield(L, lua_upvalueindex(1), k);
    return 1;
}

static int l_ngx_exit(lua_State *L) {
    ngx_ctx_t *c = ngx_ctx_from(L);
    lua_Integer st = luaL_optinteger(L, 1, 200);

    if (c) {
        c->status = (int)st;
        c->exited = 1; /* 与真正的应用错误区分：状态码/已写 body 都要保留 */
    }
    lua_settop(L, 1);
    if (lua_isnoneornil(L, 1))
        lua_pushinteger(L, (lua_Integer)st);
    return lua_error(L);
}

/* ngx.req.get_headers()：请求头表（键小写，与 nginx 同约定）。
 * 同名头本实现取最后一条（nginx 返回数组），样例/路由场景够用。 */
static int l_ngx_req_get_headers(lua_State *L) {
    lua_pushvalue(L, lua_upvalueindex(1));
    return 1;
}

/* ngx.req.read_body()：宿主在调用引擎前已经收齐 body（ABI 形参），无阻塞读，
 * 保持 nginx API 形状（应用里的 read_body 调用无需修改）。 */
static int l_ngx_req_read_body(lua_State *L) {
    (void)L;
    return 0;
}

/* ngx.req.get_body_data()：返回原始请求体（可含 NUL）；无 body 时返回 nil。
 * upvalue 1 = lightuserdata body（ABI 指针，仅本次调用有效），2 = 长度。 */
static int l_ngx_req_get_body_data(lua_State *L) {
    const char *b = (const char *)lua_touserdata(L, lua_upvalueindex(1));
    size_t n = (size_t)lua_tointeger(L, lua_upvalueindex(2));

    if (b == NULL || n == 0) {
        lua_pushnil(L);
        return 1;
    }
    lua_pushlstring(L, b, n);
    return 1;
}

struct lua_hdr_ctx {
    lua_State *L;
    int table_idx; /* 栈上 headers 表的绝对索引 */
};

static int lua_hdr_cb(void *ctx, const char *name, size_t name_len, const char *value,
                      size_t value_len) {
    struct lua_hdr_ctx *c = (struct lua_hdr_ctx *)ctx;
    char key[262];
    size_t i;

    if (c == NULL || c->L == NULL)
        return 1;
    if (name_len >= sizeof(key))
        return 0;
    for (i = 0; i < name_len; i++) {
        char ch = name[i];
        if (ch >= 'A' && ch <= 'Z')
            ch = (char)(ch - 'A' + 'a');
        key[i] = ch;
    }
    key[name_len] = '\0';
    lua_pushlstring(c->L, key, name_len);
    lua_pushlstring(c->L, value, value_len);
    lua_settable(c->L, c->table_idx);
    return 0;
}

static void inject_ngx(lua_State *L, const char *method, const char *path,
                       const char *query, const char *remote, const char *headers,
                       const char *req_body, size_t req_body_len) {
    lua_newtable(L); /* ngx */

    lua_pushcfunction(L, l_ngx_say);
    lua_setfield(L, -2, "say");
    lua_pushcfunction(L, l_ngx_print);
    lua_setfield(L, -2, "print");
    lua_pushcfunction(L, l_ngx_exit);
    lua_setfield(L, -2, "exit");
    lua_pushinteger(L, 200);
    lua_setfield(L, -2, "HTTP_OK");
    lua_pushinteger(L, 404);
    lua_setfield(L, -2, "HTTP_NOT_FOUND");

    lua_newtable(L);
    lua_newtable(L);
    lua_pushcfunction(L, l_ngx_header_index);
    lua_setfield(L, -2, "__index");
    lua_pushcfunction(L, l_ngx_header_newindex);
    lua_setfield(L, -2, "__newindex");
    lua_setmetatable(L, -2);
    lua_setfield(L, -2, "header");

    /* ngx.req.get_headers() */
    lua_newtable(L); /* req */
    lua_newtable(L); /* headers 表 */
    {
        struct lua_hdr_ctx hc;

        hc.L = L;
        hc.table_idx = lua_gettop(L);
        (void)appengine_headers_foreach(headers, lua_hdr_cb, &hc);
    }
    lua_pushvalue(L, -1); /* 复制一份作 closure upvalue */
    lua_pushcclosure(L, l_ngx_req_get_headers, 1);
    lua_setfield(L, -3, "get_headers"); /* req.get_headers */
    lua_pop(L, 1);                      /* 弹出 headers 表 */
    lua_pushcfunction(L, l_ngx_req_read_body);
    lua_setfield(L, -2, "read_body");
    lua_pushlightuserdata(L, (void *)(uintptr_t)req_body);
    lua_pushinteger(L, (lua_Integer)req_body_len);
    lua_pushcclosure(L, l_ngx_req_get_body_data, 2);
    lua_setfield(L, -2, "get_body_data");
    lua_setfield(L, -2, "req");         /* ngx.req */

    lua_newtable(L); /* vars data */
    if (method)
        lua_pushstring(L, method), lua_setfield(L, -2, "request_method");
    if (path)
        lua_pushstring(L, path), lua_setfield(L, -2, "uri");
    if (query)
        lua_pushstring(L, query), lua_setfield(L, -2, "query_string");
    if (remote)
        lua_pushstring(L, remote), lua_setfield(L, -2, "remote_addr");

    lua_newtable(L); /* var proxy */
    lua_pushvalue(L, -2);
    lua_pushcclosure(L, l_ngx_var_index, 1);
    lua_newtable(L);
    lua_pushvalue(L, -2);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, -3);
    lua_pop(L, 1);
    lua_setfield(L, -3, "var");
    lua_pop(L, 1);

    lua_setglobal(L, "ngx");
}
#endif /* CRUCIBLE_HAVE_LUA */

/* ═══════════════ R-03：每请求 `.env` 视图（os.getenv 覆盖） ═══════════════
 *
 * 本引擎自报 `appengine_env_isolation()=1` 后，宿主不再把请求 `.env` 装进进程
 * 环境（也不再持有全局 env 锁），只经 ABI `extra` JSON 下发。Lua 应用读环境
 * 的标准入口是 `os.getenv`；这里在**每请求新建的 lua_State** 里把它换成一个
 * C 闭包：
 *   1) 先查本请求覆盖表（`extra.env`；空值 = 键不存在，不插入）；
 *   2) 再查启动期基底（`appengine_base_env_block()`，宿主经
 *      appengine_set_base_env 交付）；
 *   3) 基底不可用（极旧宿主）时才回退到真实 `os.getenv`。
 *
 * 请求期**绝不**回退到真实 getenv —— 进程 env 里可能有别的（仍走 env 锁的）
 * 引擎的临时 `.env`，本引擎已与它们并发。
 *
 * 诚实边界：Lua 里 `os.getenv` 的替代只覆盖标准库入口；第三方 C 模块直接
 * 调 `getenv(2)` 不受保护（与 cgi 的 env_isolation 同一信任边界），应用自己
 * 用 `os.execute` 起的子进程也不继承请求 `.env`。
 */
typedef struct {
    lua_State *L;
    int table_idx; /* 正数栈下标（绝对） */
} lua_env_fill_ctx;

static int lua_env_fill_cb(void *ctx, const char *k, const char *v)
{
    lua_env_fill_ctx *c = (lua_env_fill_ctx *)ctx;

    if (c == NULL || c->L == NULL || k == NULL || k[0] == '\0')
        return 0;
    lua_pushstring(c->L, k);
    if (v == NULL || v[0] == '\0') {
        /* `.env` 空值 = 键不存在（与 cgi/cgi_script 子进程 envp 一致：连启动期
         * 基底里的同名键也必须不可见）。用 `false` 当删除哨兵：只跳过本项会让
         * 基底表里的同名值重新露出来，与进程 env 的 remove_var 语义分叉。 */
        lua_pushboolean(c->L, 0);
    } else {
        lua_pushstring(c->L, v);
    }
    lua_settable(c->L, c->table_idx);
    return 0;
}

static int l_crucible_getenv(lua_State *L)
{
    const char *key;
    int i;

    if (lua_gettop(L) < 1 || !lua_isstring(L, 1)) {
        lua_pushnil(L);
        return 1;
    }
    key = lua_tostring(L, 1);
    /* upvalue 1 = 本请求覆盖表；2 = 启动期基底表；3 = 真实 os.getenv 或 nil */
    for (i = 1; i <= 2; i++) {
        lua_pushstring(L, key);
        lua_rawget(L, lua_upvalueindex(i));
        if (!lua_isnil(L, -1)) {
            /* 请求覆盖表里的 `false` = `.env` 显式空值（删除），必须返回 nil 且
             * **不再**回落到启动期基底（否则空值语义与 cgi 子进程 envp 分叉）。 */
            if (lua_isboolean(L, -1) && !lua_toboolean(L, -1)) {
                lua_pop(L, 1);
                lua_pushnil(L);
            }
            return 1;
        }
        lua_pop(L, 1);
    }
    if (!lua_isnil(L, lua_upvalueindex(3))) {
        lua_pushvalue(L, lua_upvalueindex(3));
        lua_pushstring(L, key);
        lua_call(L, 1, 1);
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

/* 安装每请求环境视图（须在 luaL_openlibs 之后、luaL_dofile 之前调用）。 */
static void lua_inject_env(lua_State *L, const char *extra)
{
    const char *base = appengine_base_env_block();
    lua_env_fill_ctx ctx;

    lua_newtable(L); /* 1: 请求覆盖 */
    ctx.L = L;
    ctx.table_idx = lua_gettop(L);
    if (extra != NULL)
        (void)appengine_extra_env_foreach(extra, lua_env_fill_cb, &ctx);

    lua_newtable(L); /* 2: 启动期基底 */
    ctx.table_idx = lua_gettop(L);
    if (base != NULL) {
        const char *p = base;
        while (*p != '\0') {
            const char *eq = strchr(p, '=');
            if (eq == NULL)
                break;
            lua_pushlstring(L, p, (size_t)(eq - p));
            lua_pushstring(L, eq + 1);
            lua_settable(L, ctx.table_idx);
            p = eq + strlen(eq) + 1;
        }
        lua_pushnil(L); /* 基底可用 ⇒ 不回退真实 getenv */
    } else {
        lua_getglobal(L, "os");
        if (lua_istable(L, -1)) {
            lua_getfield(L, -1, "getenv");
            lua_remove(L, -2);
        } else {
            lua_pop(L, 1);
            lua_pushnil(L);
        }
    }

    /* os.getenv = _crucible_getenv(req, base, real) */
    lua_getglobal(L, "os");
    if (lua_istable(L, -1)) {
        lua_pushvalue(L, 1);
        lua_pushvalue(L, 2);
        lua_pushvalue(L, 3);
        lua_pushcclosure(L, l_crucible_getenv, 3);
        lua_setfield(L, -2, "getenv");
    }
    lua_pop(L, 4); /* os, real, base, req */
}

/* 初始化一个请求的 lua_State：openlibs → 环境视图 → 安全/超时接线 → ngx。
 * 整个初始化放在 lua_pcall 里跑：即使 Lua 堆上限设得很小，openlibs/环境表/
 * 头表分配失败也走干净的 Lua error，而不是无保护 longjmp 到 panic（abort）。 */
typedef struct {
    const char *extra;
    const char *method;
    const char *path;
    const char *query;
    const char *remote;
    const char *headers;
    const char *req_body;
    size_t req_body_len;
    const char *docroot;
} lua_setup_ctx;

static int lua_setup_state(lua_State *L) {
    lua_setup_ctx *s = (lua_setup_ctx *)lua_touserdata(L, lua_upvalueindex(1));

    if (s == NULL)
        return luaL_error(L, "lua: internal setup error");
    luaL_openlibs(L);
    /* 应用私有模块：docroot 优先。 */
    lua_prepend_package_path(L, s->docroot);
    /* R-03：每请求 `.env` 视图（os.getenv 覆盖；不碰进程 env）。 */
    lua_inject_env(L, s->extra);
    /* P0：os.exit() 会杀掉整个 webserver → 改成 Lua error。 */
    lua_install_os_guard(L);
    /* 协程需要自己的 count hook（见 lua_apply_hook 说明）。 */
    lua_install_libs_guard(L);
    inject_ngx(L, s->method, s->path, s->query, s->remote, s->headers,
               s->req_body, s->req_body_len);
    return 0;
}

static int g_inited;

int appengine_init(const char *engine, const char *lib_hint) {
    (void)lib_hint;
    (void)engine;
    LUA_LOCK();
    g_inited = 1;
#ifndef CRUCIBLE_HAVE_LUA
    /* Clear error path when system Lua was missing at build time. */
    fprintf(stderr,
            "libapp_lua.so: built WITHOUT CRUCIBLE_HAVE_LUA — install lua "
            "headers (lua.h) and rebuild via build_app_engines.sh; serving "
            "hello stub only\n");
#endif
    LUA_UNLOCK();
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
    (void)docroot;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)server_name;
    (void)server_port;
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

#ifdef CRUCIBLE_HAVE_LUA
    if (script && script[0]) {
        ngx_ctx_t ctx;
        lua_State *L;

        /* 脚本不存在 → 404（而不是把 luaL_dofile 的 "cannot open ..." 一律当 500）。
         * 此前请求一个不存在的 `.lua` 得到 **500**：与 php/tsx/ruby 的 404 口径不一致，
         * 也让「文件没部署」看起来像「引擎坏了」。绝对路径只进 out->error（Rust 侧节流
         * 写日志），客户端拿固定文本。用 fopen 探测（access/F_OK 在 -std=c99 下不可见）。 */
        {
            FILE *probe = fopen(script, "rb");
            if (!probe) {
                out->status = 404;
                appengine_result_set_headers(
                    out, "Content-Type: text/plain; charset=utf-8\r\n");
                appengine_result_set_body(out, "lua: script not found\n", 22);
                appengine_result_set_error(out, script);
                return 0;
            }
            fclose(probe);
        }

        memset(&ctx, 0, sizeof(ctx));

        /* 每请求一个 lua_State：请求间不共享 _G/package.loaded/registry；lua_close
         * 在函数返回前释放全部 Lua 内存。分配器带 32MiB 上限（可配）。 */
        lua_ensure_cfg();
        {
            lua_mem_limiter mem;
            lua_setup_ctx setup;

            mem.used = 0;
            mem.limit = g_lua_mem_limit;
            L = lua_newstate(lua_limited_alloc, &mem);
            if (!L)
                return -1;
            ngx_ctx_bind(L, &ctx);
            setup.extra = extra;
            setup.method = method;
            setup.path = path;
            setup.query = query;
            setup.remote = remote;
            setup.headers = headers;
            setup.req_body = body;
            setup.req_body_len = body_len;
            setup.docroot = docroot;
            lua_pushlightuserdata(L, &setup);
            lua_pushcclosure(L, lua_setup_state, 1);
            if (lua_pcall(L, 0, 0, 0) != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                static const char k_setup_err[] = "lua: application error\n";

                out->status = 500;
                appengine_result_set_headers(
                    out, "Content-Type: text/plain; charset=utf-8\r\n");
                appengine_result_set_body(out, k_setup_err, sizeof(k_setup_err) - 1);
                appengine_result_set_error(out, err ? err : "lua setup error");
                lua_close(L);
                free(ctx.body);
                return 0;
            }
            /* 纯 Lua 执行的墙钟 deadline（协程在 resume 前单独装同一个 hook）。 */
            lua_install_timeout(L);
        }

        {
            int rc = luaL_dofile(L, script);
            if (rc != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                if (!ctx.exited) {
                    /* **响应体只给固定文本**：`err` 是 Lua 解释器原文，典型形如
                     * `cannot open /crucible/www-apps/lua/x.lua: No such file or directory`
                     * 或 `/abs/path/x.lua:1: syntax error near ...` —— 含**服务器绝对路径**
                     * 与脚本行号，任意能命中该路由的客户端都能看到。本项目统一口径是
                     * 「细节只进本地日志，客户端拿固定文本」（Rust 侧 engine_error；
                     * cgi/cgi_script 早已如此）。原文改放 `out->error`，由 Rust 侧
                     * **经节流**写进本地日志（`app_ffi` 现在 rc==0 时也会记录 error）。
                     *
                     * 注意：旧实现只在 `ctx.body_len == 0` 时回 500 —— 应用先
                     * `ngx.say` 再 `error()` 会得到 **200 + 半截 body**（真机基线复现）。
                     * 输出尚未提交（全在缓冲里），未捕获错误一律固定 500。
                     * `ngx.exit()` 是**有意**终止（Lua error 只是控制流），走下面的
                     * 正常路径保留它设置的状态码与已写 body。 */
                    static const char k_lua_err_body[] = "lua: application error\n";
                    out->status = 500;
                    appengine_result_set_headers(
                        out, "Content-Type: text/plain; charset=utf-8\r\n");
                    appengine_result_set_body(out, k_lua_err_body,
                                              sizeof(k_lua_err_body) - 1);
                    appengine_result_set_error(out, err ? err : "lua error");
                    lua_close(L);
                    free(ctx.body);
                    return 0;
                }
            }
        }

        if (!ctx.exited && ctx.body_len == 0 && lua_isstring(L, -1)) {
            size_t n = 0;
            const char *s = lua_tolstring(L, -1, &n);
            ngx_append(&ctx, s ? s : "", n);
        }

        out->status = ctx.status ? ctx.status : 200;
        if (ctx.headers_len > 0) {
            appengine_result_set_headers(out, ctx.headers);
        } else {
            appengine_result_set_headers(
                out, "Content-Type: text/plain; charset=utf-8\r\n");
        }
        appengine_result_set_body(out, ctx.body ? ctx.body : "", ctx.body_len);
        lua_close(L);
        free(ctx.body);
        return 0;
    }
#else
    {
        char buf[640];
        (void)headers;
        snprintf(buf, sizeof(buf),
                 "hello from lua engine (NO CRUCIBLE_HAVE_LUA — install lua "
                 "dev headers and rebuild) path=%s method=%s query=%s "
                 "script=%s\n",
                 path ? path : "/", method ? method : "GET",
                 query ? query : "", script ? script : "(inline)");
        out->status = 200;
        appengine_result_set_headers(
            out, "Content-Type: text/plain; charset=utf-8\r\n"
                 "X-Crucible-Lua: stub-no-headers\r\n");
        appengine_result_set_body(out, buf, strlen(buf));
        return 0;
    }
#endif

    {
        char buf[512];
        snprintf(buf, sizeof(buf),
                 "hello from lua engine path=%s method=%s query=%s script=%s\n",
                 path ? path : "/", method ? method : "GET",
                 query ? query : "", script ? script : "(inline)");
        out->status = 200;
        appengine_result_set_headers(
            out, "Content-Type: text/plain; charset=utf-8\r\n");
        appengine_result_set_body(out, buf, strlen(buf));
        return 0;
    }
}

/* R-03：`.env` 隔离自报（可选符号，见 appengine.h）。
 *
 * 返回非 0 = 本引擎不依赖进程 env：请求 `.env` 只走 ABI `extra` JSON，落进每请求
 * lua_State 的 os.getenv 覆盖表；从不 setenv/putenv，也不继承 environ。宿主因此
 * 可以跳过全局 env 锁 —— 慢的空请求不再挡住随后带 `.env` 的 lua 请求。
 * 没有内置 Lua（stub 构建）时无法保证脚本读环境的行为，诚实回答 0。 */
int appengine_env_isolation(void)
{
#ifdef CRUCIBLE_HAVE_LUA
    return 1;
#else
    return 0;
#endif
}

void appengine_shutdown(void) {
    LUA_LOCK();
    g_inited = 0;
    LUA_UNLOCK();
}

