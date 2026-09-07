package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"unsafe"
)

var (
	reWrite   = regexp.MustCompile(`(?is)Response\.Write\s*\(\s*"([^"]*)"\s*\)`)
	reExpr    = regexp.MustCompile(`(?s)<%=\s*(.*?)\s*%>`)
	reBlock   = regexp.MustCompile(`(?s)<%.*?%>`)
	reQS      = regexp.MustCompile(`(?i)Request\.QueryString\s*\(\s*"([^"]+)"\s*\)`)
)

//export axonasp_handle
func axonasp_handle(method, path, query, script, docroot *C.char) *C.char {
	m := C.GoString(method)
	p := C.GoString(path)
	q := C.GoString(query)
	scriptPath := C.GoString(script)
	root := C.GoString(docroot)

	out := renderAsp(scriptPath, root, m, p, q)
	return C.CString(out)
}

func renderAsp(script, root, method, path, query string) string {
	candidates := []string{}
	if script != "" {
		candidates = append(candidates, script)
		if root != "" && !strings.Contains(script, "/") && !strings.Contains(script, `\`) {
			candidates = append(candidates, root+"/"+script)
		}
	}
	if root != "" {
		candidates = append(candidates, root+"/index.asp", root+"/default.asp")
	}
	for _, c := range candidates {
		data, err := os.ReadFile(c)
		if err != nil {
			continue
		}
		return expandAsp(string(data), query)
	}
	return fmt.Sprintf("hello from axonasp engine method=%s path=%s query=%s\n", method, path, query)
}

func expandAsp(src, query string) string {
	qs := parseQuery(query)
	src = reWrite.ReplaceAllStringFunc(src, func(m string) string {
		sub := reWrite.FindStringSubmatch(m)
		if len(sub) > 1 {
			return sub[1]
		}
		return ""
	})
	src = reExpr.ReplaceAllStringFunc(src, func(m string) string {
		sub := reExpr.FindStringSubmatch(m)
		if len(sub) < 2 {
			return ""
		}
		expr := strings.TrimSpace(sub[1])
		if qm := reQS.FindStringSubmatch(expr); len(qm) > 1 {
			return qs[strings.ToLower(qm[1])]
		}
		if strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\"") && len(expr) >= 2 {
			return expr[1 : len(expr)-1]
		}
		return ""
	})
	src = reBlock.ReplaceAllString(src, "")
	return src
}

func parseQuery(q string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(q, "&") {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		k := strings.ToLower(kv[0])
		v := ""
		if len(kv) > 1 {
			v = kv[1]
		}
		out[k] = v
	}
	return out
}

//export axonasp_free
func axonasp_free(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func main() {}
