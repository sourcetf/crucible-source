package main

/*
#include <stdlib.h>
#include <string.h>

typedef struct AppEngineResult {
    int status;
    char *headers;
    size_t headers_len;
    char *body;
    size_t body_len;
    char *error;
} AppEngineResult;
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"os"
	"unsafe"
)

//export appengine_init
func appengine_init(engine, libHint *C.char) C.int {
	return 0
}

//export appengine_shutdown
func appengine_shutdown() {}

//export appengine_result_free
func appengine_result_free(out *C.AppEngineResult) {
	if out == nil {
		return
	}
	if out.headers != nil {
		C.free(unsafe.Pointer(out.headers))
		out.headers = nil
	}
	if out.body != nil {
		C.free(unsafe.Pointer(out.body))
		out.body = nil
	}
	if out.error != nil {
		C.free(unsafe.Pointer(out.error))
		out.error = nil
	}
}

//export appengine_execute
func appengine_execute(
	script, docroot, method, path, query, contentType *C.char,
	body *C.char, bodyLen C.size_t,
	remote, serverName *C.char, serverPort C.int,
	extra *C.char,
	out *C.AppEngineResult,
) C.int {
	if out == nil {
		return -1
	}
	// P1-1：extra 语义升级——有 .env 变量时 Rust 侧传 JSON {"engine":...,"env":{...}}；
	// legacy 输入（纯引擎名）解析失败即忽略。解析出的键值注入进程环境供插件读取。
	if extra != nil {
		var payload struct {
			Engine string            `json:"engine"`
			Env    map[string]string `json:"env"`
		}
		if err := json.Unmarshal([]byte(C.GoString(extra)), &payload); err == nil {
			for k, v := range payload.Env {
				os.Setenv(k, v)
			}
		}
	}
	msg := "hello from go app-engine ffi"
	if v := os.Getenv("APP_HELLO"); v != "" {
		msg = v
	}
	p := ""
	if path != nil {
		p = C.GoString(path)
	}
	bodyStr := fmt.Sprintf("%s path=%s\n", msg, p)
	hdr := "Content-Type: text/plain; charset=utf-8\r\nX-App-Engine: go\r\n"
	out.status = 200
	out.headers = C.CString(hdr)
	out.headers_len = C.size_t(len(hdr))
	out.body = C.CString(bodyStr)
	out.body_len = C.size_t(len(bodyStr))
	out.error = nil
	_ = script
	_ = docroot
	_ = method
	_ = query
	_ = contentType
	_ = body
	_ = bodyLen
	_ = remote
	_ = serverName
	_ = serverPort
	return 0
}

func main() {}
