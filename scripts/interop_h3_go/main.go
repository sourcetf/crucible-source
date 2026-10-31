// interop_h3_go — independent HTTP/3 client for U-11 interoperability tests.
//
// This client uses quic-go's HTTP/3 stack (a completely independent Go
// implementation: quic-go QUIC + its own QPACK/H3) to talk to the Crucible
// listener.  It is deliberately *not* the same stack as the server (quinn +
// Rust h3) nor the aioquic baseline, so agreement between all three is real
// interoperability evidence.
//
// Usage:
//
//	interop-h3-go -url https://127.0.0.1:27143/blob-8m.bin -n 4 -c 2 \
//	    -expect-sha256 <hex> -json out.json
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"time"

	"github.com/quic-go/quic-go/http3"
)

type result struct {
	I         int               `json:"i"`
	Status    int               `json:"status"`
	Proto     string            `json:"proto"`
	Bytes     int64             `json:"bytes"`
	SHA256    string            `json:"sha256"`
	ElapsedMS float64           `json:"elapsed_ms"`
	OK        bool              `json:"ok"`
	Error     string            `json:"error,omitempty"`
	Headers   map[string][]string `json:"headers,omitempty"`
}

func depVersion(path string) string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == path {
				return d.Version
			}
		}
	}
	return "unknown"
}

func pct(v []float64, p float64) float64 {
	if len(v) == 0 {
		return 0
	}
	sort.Float64s(v)
	i := int(float64(len(v)-1) * p / 100.0)
	return v[i]
}

func main() {
	urlStr := flag.String("url", "https://127.0.0.1:27143/", "request URL")
	n := flag.Int("n", 1, "total number of requests")
	c := flag.Int("c", 1, "concurrency")
	nconn := flag.Int("connections", 1, "number of QUIC connections (transports)")
	insecure := flag.Bool("insecure", true, "skip TLS certificate verification")
	serverName := flag.String("server-name", "", "TLS ServerName override")
	timeout := flag.Duration("timeout", 120*time.Second, "per-request timeout")
	expectSHA := flag.String("expect-sha256", "", "expected body SHA-256 (hex)")
	jsonOut := flag.String("json", "", "write JSON summary to this file")
	flag.Parse()

	u, err := url.Parse(*urlStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bad -url: %v\n", err)
		os.Exit(2)
	}
	if *n < 1 || *c < 1 || *nconn < 1 {
		fmt.Fprintln(os.Stderr, "-n, -c and -connections must be >= 1")
		os.Exit(2)
	}
	if *c > *n {
		*c = *n
	}

	transports := make([]*http3.Transport, 0, *nconn)
	for i := 0; i < *nconn; i++ {
		tlsConf := &tls.Config{
			InsecureSkipVerify: *insecure, //nolint:gosec // test client, self-signed cert
			ServerName:         *serverName,
			NextProtos:         []string{"h3"},
			MinVersion:         tls.VersionTLS13,
		}
		tr := &http3.Transport{
			TLSClientConfig:    tlsConf,
			DisableCompression: true,
		}
		transports = append(transports, tr)
	}
	defer func() {
		for _, tr := range transports {
			tr.Close()
		}
	}()

	results := make([]result, *n)
	jobs := make(chan int)
	var wg sync.WaitGroup
	t0 := time.Now()

	worker := func(w int) {
		defer wg.Done()
		tr := transports[w%len(transports)]
		client := &http.Client{Transport: tr, Timeout: *timeout}
		for i := range jobs {
			req, err := http.NewRequest(http.MethodGet, u.String(), nil)
			if err != nil {
				results[i] = result{I: i, Error: err.Error()}
				continue
			}
			req.Header.Set("User-Agent", "interop-h3-go/1")
			start := time.Now()
			resp, err := client.Do(req)
			if err != nil {
				results[i] = result{I: i, Error: err.Error(), ElapsedMS: ms(start)}
				continue
			}
			h := sha256.New()
			nb, err := io.Copy(h, resp.Body)
			resp.Body.Close()
			r := result{
				I:         i,
				Status:    resp.StatusCode,
				Proto:     resp.Proto,
				Bytes:     nb,
				SHA256:    hex.EncodeToString(h.Sum(nil)),
				ElapsedMS: ms(start),
			}
			if err != nil {
				r.Error = err.Error()
			} else if resp.StatusCode != http.StatusOK {
				r.Error = fmt.Sprintf("status %d", resp.StatusCode)
			} else if *expectSHA != "" && r.SHA256 != *expectSHA {
				r.Error = "sha256 mismatch"
			}
			r.OK = r.Error == ""
			if i == 0 {
				r.Headers = map[string][]string(resp.Header)
			}
			results[i] = r
		}
	}
	for w := 0; w < *c; w++ {
		wg.Add(1)
		go worker(w)
	}
	for i := 0; i < *n; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	wall := time.Since(t0)

	var okCount int
	var bytesOK int64
	var lat []float64
	var failures []result
	var proto string
	var headers map[string][]string
	for _, r := range results {
		if r.OK {
			okCount++
			bytesOK += r.Bytes
			lat = append(lat, r.ElapsedMS)
			if proto == "" {
				proto = r.Proto
			}
			if r.Headers != nil && headers == nil {
				headers = r.Headers
			}
		} else {
			failures = append(failures, r)
		}
	}
	summary := map[string]interface{}{
		"client":          "quic-go",
		"quic_go_version": depVersion("github.com/quic-go/quic-go"),
		"go_version":      runtime.Version(),
		"url":             u.String(),
		"requests":        *n,
		"concurrency":     *c,
		"connections":     *nconn,
		"ok":              okCount,
		"failures":        failures,
		"wall_s":          round(wall.Seconds(), 3),
		"bytes_ok":        bytesOK,
		"throughput_mib_s": func() float64 {
			if wall.Seconds() == 0 {
				return 0
			}
			return round(float64(bytesOK)/wall.Seconds()/1048576, 2)
		}(),
		"latency_ms": map[string]float64{
			"min": round(pct(lat, 0), 3),
			"p50": round(pct(lat, 50), 3),
			"p95": round(pct(lat, 95), 3),
			"max": round(pct(lat, 100), 3),
		},
		"proto":   proto,
		"headers": headers,
	}
	b, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(b))
	if *jsonOut != "" {
		if err := os.WriteFile(*jsonOut, b, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", *jsonOut, err)
		}
	}
	if len(failures) > 0 {
		os.Exit(1)
	}
}

func ms(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000.0 }

func round(v float64, dec int) float64 {
	pow := 1.0
	for i := 0; i < dec; i++ {
		pow *= 10
	}
	return float64(int64(v*pow+0.5)) / pow
}
