def application(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain; charset=utf-8")])
    path = environ.get("PATH_INFO", "/")
    return [f"hello from wsgi path={path}\n".encode("utf-8")]
