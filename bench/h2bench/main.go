// h2bench —— 极简 HTTP/1.1 + HTTP/2(+h2c) 压测器（工号 1009 为公平基准补充）。
//
// 为什么需要：OpenBSD 7.9 的 nghttp2 包**不包含 h2load**，而规格 §22 的公平矩阵要求
// HTTP/2 的吞吐/延迟对比。wrk 只支持 HTTP/1.1。这里用 Go 标准库自带的 http2 客户端
// （TLS 下自动协商 h2；明文用 x/net/http2 的 h2c）做一个最小但真实的并发压测，
// 输出 RPS 与延迟分位数，供双门禁使用。
//
// 用法:
//   go run ./bench/h2bench -url https://127.0.0.1:19446/ -c 8 -d 10s -insecure
//   go run ./bench/h2bench -url http://127.0.0.1:19081/  -c 8 -d 10s -h2c
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	url := flag.String("url", "", "target URL")
	conc := flag.Int("c", 8, "concurrency")
	dur := flag.Duration("d", 10*time.Second, "duration")
	insecure := flag.Bool("insecure", false, "skip TLS verification")
	h2c := flag.Bool("h2c", false, "use cleartext HTTP/2 (prior knowledge)")
	body := flag.Bool("count-body", false, "count response bytes")
	flag.Parse()
	if *url == "" {
		fmt.Fprintln(os.Stderr, "usage: h2bench -url <url> [-c 8] [-d 10s] [-insecure] [-h2c]")
		os.Exit(2)
	}

	tr := &http.Transport{
		MaxIdleConns:        *conc * 2,
		MaxIdleConnsPerHost: *conc * 2,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  true,
		ForceAttemptHTTP2:   true,
	}
	if *insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	if *h2c {
		// Go 1.24+ 内置 h2c（prior knowledge）支持：Protocols 直接指定明文 HTTP/2。
		tr.Protocols = new(http.Protocols)
		tr.Protocols.SetUnencryptedHTTP2(true)
		tr.Protocols.SetHTTP1(false)
		tr.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}

	var (
		requests atomic.Int64
		errors   atomic.Int64
		bytes    atomic.Int64
	)
	lats := make([][]int64, *conc) // 每 goroutine 各自记录，避免锁竞争
	deadline := time.Now().Add(*dur)

	var (
		wg          sync.WaitGroup
		protosMu    sync.Mutex
		globalProto string
	)
	for i := 0; i < *conc; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			local := make([]int64, 0, 4096)
			req, err := http.NewRequest("GET", *url, nil)
			if err != nil {
				errors.Add(1)
				lats[id] = local
				return
			}
			protoSeen := ""
			for time.Now().Before(deadline) {
				t0 := time.Now()
				resp, err := client.Do(req)
				if err != nil {
					errors.Add(1)
					continue
				}
				n, _ := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode/100 != 2 {
					errors.Add(1)
					continue
				}
				if *body {
					bytes.Add(n)
				}
				local = append(local, time.Since(t0).Microseconds())
				if protoSeen == "" {
					protoSeen = resp.Proto
					protosMu.Lock()
					if globalProto == "" {
						globalProto = resp.Proto
					}
					protosMu.Unlock()
				}
				requests.Add(1)
			}
			lats[id] = local
		}(i)
	}
	wg.Wait()

	var all []int64
	for _, l := range lats {
		all = append(all, l...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	pct := func(p float64) int64 {
		if len(all) == 0 {
			return 0
		}
		idx := int(float64(len(all)-1) * p)
		return all[idx]
	}
	elapsed := (*dur).Seconds()
	rps := float64(requests.Load()) / elapsed
	fmt.Printf("proto=%s requests=%d errors=%d rps=%.2f\n", globalProto, requests.Load(), errors.Load(), rps)
	fmt.Printf("latency_mean=%.1fus p50=%.1fus p90=%.1fus p99=%.1fus max=%.1fus\n",
		mean(all), float64(pct(0.50)), float64(pct(0.90)), float64(pct(0.99)), float64(pct(1.0)))
	if *body {
		fmt.Printf("bytes_total=%d\n", bytes.Load())
	}
}

func mean(xs []int64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var s int64
	for _, v := range xs {
		s += v
	}
	return float64(s) / float64(len(xs))
}
