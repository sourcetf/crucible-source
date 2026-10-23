<%@ Page Language="C#" %>
<script runat="server">
  // Crucible aspnet sample.
  // 装了 .NET + dotnet SDK 后，libapp_aspnet.so 通过 hostfxr 进程内加载
  // www-apps/aspnet/bin/CrucibleAspNetSample.dll，由托管 Handler.Render 渲染本页
  // （响应头 X-Crucible-AspNet-Mode: hostfxr）。没有托管程序集时退回 mini 渲染器。
</script>
<html>
<body>
  <p>hello from aspnet index.aspx</p>
  <p>managed=<%= Host.Framework %></p>
  <p>managed-version=<%= Host.Version %></p>
  <p>path=<%= Request.Path %></p>
  <p>q=<%= Request.QueryString("q") %></p>
</body>
</html>
