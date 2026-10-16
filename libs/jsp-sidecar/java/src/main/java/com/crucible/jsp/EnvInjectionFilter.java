package com.crucible.jsp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

/**
 * 把 web-server 宿主转发的应用 <code>.env</code> 注入为 <b>request attribute</b>（每请求独立）。
 *
 * <h2>通道约定（宿主侧实现：<code>src/server/apps/sidecar_engine.rs::env_forward_headers</code>）</h2>
 * <ul>
 *   <li>头名 <code>x-crucible-env-&lt;key 的小写&gt;</code>，值是 RFC 3986 percent-encoded
 *       （UTF-8；<b>不是</b>表单编码 —— 字面 <code>+</code> 由宿主编码成 <code>%2B</code>，
 *       因此解码时绝不能把 <code>+</code> 当空格）；</li>
 *   <li>空值（<code>.env</code> 的 <code>KEY=</code>）不转发 = 该键不存在；</li>
 *   <li>宿主侧上限 64 键 / 16KiB，超限截断；</li>
 *   <li>宿主在转发前会<b>剥掉客户端自带的</b> <code>x-crucible-env-*</code>，所以该通道
 *       不可能被外部注入；本 filter 仍按「只认头名/只认合法键/再压一次上限」做纵深防御。</li>
 * </ul>
 *
 * <h2>何时会收到这些头</h2>
 * 只有<b>显式 <code>apps[].socket</code></b>（运维自己起的 Jetty，宿主够不着它的进程 env）
 * 才走这条请求头通道。受管 sidecar（<code>deps/bin/index</code>）的 <code>.env</code> 走
 * <b>spawn env</b>：应用直接 <code>System.getenv("KEY")</code> 即可 —— 本 filter 不改动、
 * 也不模拟那条通道（两条通道语义不同，不能互相冒充）。
 *
 * <h2>为什么是 request attribute（而不是 System.setProperty）</h2>
 * 属性属于<b>单个请求</b>，随请求结束回收；系统属性是 <b>JVM 全局</b>的 —— 同一个 Jetty
 * 承载多个应用（或多个 <code>.env</code>）时，后一个请求会覆盖前一个写入的值，而且请求
 * 结束后仍然残留，之后任何读到「当前值」的代码都会拿到<b>别的请求/别的应用</b>的环境
 * （跨请求、跨应用串味，且没有任何清理点）。属性没有这个窗口。
 *
 * <h2>应用侧读取</h2>
 * <pre>
 *   String v = (String) request.getAttribute("crucible.env.db_password");
 *   &#64;SuppressWarnings("unchecked")
 *   Map&lt;String,String&gt; all = (Map&lt;String,String&gt;) request.getAttribute("crucible.env");
 * </pre>
 * 键名 = 头名去掉前缀后的<b>小写</b>形态（HTTP 头名大小写不敏感，宿主按小写发送）。
 * 样例见 <code>www-apps/jsp/index.jsp</code>。
 */
public final class EnvInjectionFilter implements Filter {

    /** 宿主转发头的前缀（比较前会先做小写化）。 */
    public static final String HEADER_PREFIX = "x-crucible-env-";
    /** 单键属性名：<code>crucible.env.&lt;key&gt;</code>。 */
    public static final String ATTR_PREFIX = "crucible.env.";
    /** 全部键值对（不可变 <code>Map&lt;String,String&gt;</code>）的属性名。 */
    public static final String ATTR_MAP = "crucible.env";

    /** 上限（与宿主侧同量级；伪造头最多只能撑到这么多 —— 纵深防御）。 */
    static final int MAX_KEYS = 64;
    static final int MAX_KEY_LEN = 128;
    static final int MAX_VALUE_LEN = 8192;
    static final int MAX_TOTAL_BYTES = 16 * 1024;

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (request instanceof HttpServletRequest http) {
            inject(http);
        }
        chain.doFilter(request, response);
    }

    /** 读取转发头 → 注入属性（见类注释）。 */
    static void inject(HttpServletRequest req) {
        Map<String, String> found = new LinkedHashMap<>();
        int total = 0;
        Enumeration<String> names = req.getHeaderNames();
        if (names == null) {
            return;
        }
        while (names.hasMoreElements() && found.size() < MAX_KEYS) {
            String raw = names.nextElement();
            if (raw == null) {
                continue;
            }
            String lower = raw.toLowerCase(Locale.ROOT);
            if (!lower.startsWith(HEADER_PREFIX)) {
                continue;
            }
            String key = lower.substring(HEADER_PREFIX.length());
            if (!validKey(key) || found.containsKey(key)) {
                // 非法键：忽略（宿主只会发合法键；这是纵深防御）。
                // 同名头（大小写不同）只取**第一条** —— 与宿主对「仅大小写不同的 .env 键」
                // 的去重语义一致（保留先出现者）。
                continue;
            }
            Enumeration<String> values = req.getHeaders(raw);
            if (values == null || !values.hasMoreElements()) {
                continue;
            }
            String decoded = percentDecode(values.nextElement());
            if (decoded == null || decoded.isEmpty() || decoded.length() > MAX_VALUE_LEN) {
                continue; // 空值 = 键不存在（与宿主/进程 env 的语义一致）
            }
            if (total + key.length() + decoded.length() > MAX_TOTAL_BYTES) {
                break;
            }
            total += key.length() + decoded.length();
            found.put(key, decoded);
        }
        if (found.isEmpty()) {
            return;
        }
        req.setAttribute(ATTR_MAP, Collections.unmodifiableMap(found));
        for (Map.Entry<String, String> e : found.entrySet()) {
            req.setAttribute(ATTR_PREFIX + e.getKey(), e.getValue());
        }
    }

    /** `[a-z0-9_]`、长度 1..=128（宿主侧 `.env` 键的子集）。 */
    static boolean validKey(String key) {
        if (key.isEmpty() || key.length() > MAX_KEY_LEN) {
            return false;
        }
        for (int i = 0; i < key.length(); i++) {
            char c = key.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
            if (!ok) {
                return false;
            }
        }
        return true;
    }

    /**
     * RFC 3986 percent-decode（UTF-8，非法 UTF-8 字节序列按 U+FFFD 替换）。
     *
     * 与 Python 侧 <code>urllib.parse.unquote(value, encoding="utf-8", errors="replace")</code>
     * <b>逐字节等价</b>（libs/jsp-sidecar/jsp_sidecar.py 的 <code>extract_env_attributes</code>
     * 实现同一套规则 —— 两条实现必须一致，否则同一个 .env 在 Java 与 Python sidecar 上读到
     * 不同的值）。注意：
     * <ul>
     *   <li><b>不能</b>用 <code>java.net.URLDecoder</code>：它是 <code>application/x-www-form-urlencoded</code>
     *       解码器，会把 <code>+</code> 解成空格（RFC 3986 里 <code>+</code> 是普通字符），
     *       且遇到非法转义会抛 <code>IllegalArgumentException</code>（把请求打成 500）；</li>
     *   <li>非法转义（<code>%</code> 后不足两个十六进制位）按字面保留，与 Python <code>unquote</code>
     *       一致。</li>
     * </ul>
     */
    static String percentDecode(String value) {
        if (value == null) {
            return null;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%' && i + 2 < value.length()) {
                int hi = Character.digit(value.charAt(i + 1), 16);
                int lo = Character.digit(value.charAt(i + 2), 16);
                if (hi >= 0 && lo >= 0) {
                    out.write((hi << 4) | lo);
                    i += 2;
                    continue;
                }
            }
            // 字面字符（含非法 `%`）：按 UTF-8 逐码元写出。
            byte[] raw = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
            out.write(raw, 0, raw.length);
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private EnvInjectionFilter() {
        // no state
    }

    /** 供 {@code new FilterHolder(EnvInjectionFilter.create())} 使用
     *（构造器私有：本类无状态、只有常量语义，避免外部误以为可以带参构造）。 */
    public static EnvInjectionFilter create() {
        return new EnvInjectionFilter();
    }
}
