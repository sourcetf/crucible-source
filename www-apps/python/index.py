print("hello from python path=%s\n" % (__import__("os").environ.get("PATH_INFO", "/")))
