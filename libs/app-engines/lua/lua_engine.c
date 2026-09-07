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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    if (ngx_ctx_ensure(c) != 0)
        return -1;
    while (c->body_len + n + 1 > c->body_cap) {
        size_t nc = c->body_cap * 2;
        char *nb = (char *)realloc(c->body, nc);
        if (!nb)
            return -1;
        c->body = nb;
        c->body_cap = nc;
    }
    memcpy(c->body + c->body_len, s, n);
    c->body_len += n;
    c->body[c->body_len] = '\0';
    return 0;
}

static int l_ngx_say(lua_State *L) {
    ngx_ctx_t *c = ngx_ctx_from(L);
    int n = lua_gettop(L);
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char *s = crucible_lua_tolstring(L, i, &len);
        if (s && c)
            ngx_append(c, s, len);
        lua_pop(L, 1);
        if (i < n && c)
            ngx_append(c, "\t", 1);
    }
    if (c)
        ngx_append(c, "\n", 1);
    return 0;
}

static int l_ngx_print(lua_State *L) {
    ngx_ctx_t *c = ngx_ctx_from(L);
    int n = lua_gettop(L);
    for (int i = 1; i <= n; i++) {
        size_t len = 0;
        const char *s = crucible_lua_tolstring(L, i, &len);
        if (s && c)
            ngx_append(c, s, len);
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
    if (c)
        c->status = (int)luaL_optinteger(L, 1, 200);
    return lua_error(L);
}

static void inject_ngx(lua_State *L, const char *method, const char *path,
                       const char *query, const char *remote) {
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
    AppEngineResult *out)
{
    (void)docroot;
    (void)content_type;
    (void)body;
    (void)body_len;
    (void)server_name;
    (void)server_port;
    (void)extra;
    if (!out) {
        return -1;
    }
    memset(out, 0, sizeof(*out));

#ifdef CRUCIBLE_HAVE_LUA
    if (script && script[0]) {
        ngx_ctx_t ctx;
        lua_State *L;

        memset(&ctx, 0, sizeof(ctx));

        /* Per-request lua_State — no shared global state across threads. */
        L = luaL_newstate();
        if (!L) {
            return -1;
        }
        luaL_openlibs(L);
        ngx_ctx_bind(L, &ctx);
        inject_ngx(L, method, path, query, remote);

        {
            int rc = luaL_dofile(L, script);
            if (rc != LUA_OK) {
                const char *err = lua_tostring(L, -1);
                if (ctx.body_len == 0) {
                    out->status = 500;
                    appengine_result_set_headers(
                        out, "Content-Type: text/plain; charset=utf-8\r\n");
                    appengine_result_set_body(out, err ? err : "lua error",
                                              err ? strlen(err) : 9);
                    lua_close(L);
                    free(ctx.body);
                    return 0;
                }
            }
        }

        if (ctx.body_len == 0 && lua_isstring(L, -1)) {
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

void appengine_shutdown(void) {
    LUA_LOCK();
    g_inited = 0;
    LUA_UNLOCK();
}

