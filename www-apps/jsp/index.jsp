<%@ page contentType="text/html; charset=UTF-8" %>
<html>
<body>
<% out.println("hello from jsp"); %>
<p>path=<%= request.getRequestURI() %></p>
<p>q=<%= request.getParameter("q") %></p>
</body>
</html>
