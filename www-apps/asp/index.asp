<%
Response.Write("hello from asp")
%>
<p>path=<%= Request.ServerVariables("PATH_INFO") %></p>
<p>q=<%= Request.QueryString("q") %></p>
<%
Response.Write Request.QueryString("msg")
%>
