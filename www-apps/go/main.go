package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

func main() {
	sock := os.Getenv("WEBSERVER_LISTEN_UNIX")
	if sock == "" {
		sock = "/tmp/go-app.sock"
	}
	_ = os.Remove(sock)

	ln, err := net.Listen("unix", sock)
	if err != nil {
		panic(err)
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(true)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "hello from go www-app path=%s\n", r.URL.Path)
	})

	fmt.Fprintf(os.Stderr, "go www-app listening on %s\n", sock)
	if err := http.Serve(ln, mux); err != nil {
		panic(err)
	}
}
