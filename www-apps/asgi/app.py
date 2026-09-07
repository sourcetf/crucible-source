async def app(scope, receive, send):
    assert scope["type"] == "http"
    path = scope.get("path", "/")
    body = f"hello from asgi path={path}\n".encode("utf-8")
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", b"text/plain; charset=utf-8")]})
    await send({"type": "http.response.body", "body": body})
