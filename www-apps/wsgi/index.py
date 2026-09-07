def application(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain; charset=utf-8")])
    path = environ.get("PATH_INFO", "/")
    return [f"hello from wsgi index path={path}\n".encode("utf-8")]


# Alias for engines that look for `app`
app = application
