<%@ page contentType="text/html; charset=UTF-8" %>
<html>
<body>
<% out.println("hello from jsp"); %>
<p>path=<%= request.getRequestURI() %></p>
<p>q=<%= request.getParameter("q") %></p>
<%-- .env 注入的两条通道（实现见 libs/jsp-sidecar 与 src/server/apps/sidecar_engine.rs）。

     ① 受管 sidecar（deps/bin/index）:宿主在 spawn 时把【本应用自己的 .env】放进进程环境,
     应用直接读环境变量即可（下一行的 getenv 通道）。
     ② 显式 apps[].socket（运维自己起的 Jetty 等）:宿主够不着它的进程 env,改为按请求转发
     x-crucible-env-<key 小写> 头（值 percent-encoded）;EnvInjectionFilter 把它注入成
     request attribute,键名为 crucible.env.<key 小写>（下一行的 attribute 通道）。
     两条通道语义不同、互不冒充:同一次请求通常只有其中一条有值,另一条显示 null/空。

     试:在 www-apps/jsp/.env 写入 APP_MARK=demo-1 后请求本页。 --%>
<p>env-attribute[explicit-socket]=<%= request.getAttribute("crucible.env.app_mark") %></p>
<p>env-getenv[managed-sidecar]=<%= System.getenv("APP_MARK") %></p>
</body>
</html>
