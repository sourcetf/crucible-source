// gobench — minimal native HTTP/1.1 load generator (agent-bench wave8, 1009).
//
// Why: the spec fair-gate script wants wrk/h2load, which are not installed on this
// box (no sudo). The python bench.py client is GIL-bound above ~10k rps and cannot
// reproduce wrk-shaped load (wrk -t2 -c64). This is the same connection model as
// wrk: one in-flight request per connection, N connections total, fixed request
// bytes, per-connection read buffer, no HTTP client library layers.
//
// Usage:
//   gobench -addr 127.0.0.1:24081 -path / -c 64 -d 10 -server-pid 12345 -label h2o
// Modes: ka (keep-alive), churn (new conn per request).
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	addr      = flag.String("addr", "127.0.0.1:24081", "host:port")
	path      = flag.String("path", "/", "request path")
	conns     = flag.Int("c", 64, "connections")
	durSec    = flag.Float64("d", 10, "duration seconds")
	mode      = flag.String("mode", "ka", "ka|churn")
	serverPID = flag.Int("pid", 0, "server pid for /proc cpu sampling")
	label     = flag.String("label", "", "label")
	warmup    = flag.Float64("warmup", 1.0, "warmup seconds (discarded)")
)

func cpuTicks(pid int) (int64, bool) {
	if pid <= 0 {
		return 0, false
	}
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, false
	}
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0, false
	}
	f := strings.Fields(s[i+1:])
	// after comm: state(0) ... utime=11, stime=12 (0-based)
	if len(f) < 13 {
		return 0, false
	}
	u, _ := strconv.ParseInt(f[11], 10, 64)
	st, _ := strconv.ParseInt(f[12], 10, 64)
	return u + st, true
}

type result struct {
	n     int64
	errs  int64
	lats  []int64
	nLat  int64
	sumUs int64
}

func workerKa(a string, p string, deadline time.Time, res *result, req []byte) {
	c, err := net.Dial("tcp", a)
	if err != nil {
		res.errs++
		return
	}
	defer c.Close()
	_ = c.(*net.TCPConn).SetNoDelay(true)
	buf := make([]byte, 65536)
	lats := make([]int64, 0, 4096)
	var n, errs, sum int64
	for time.Now().Before(deadline) {
		t0 := time.Now()
		if _, err := c.Write(req); err != nil {
			errs++
			break
		}
		consumed := 0
		for {
			// find header end in buf[:consumed]; then read body
			idx := indexHeaderEnd(buf[:consumed])
			if idx < 0 {
				m, err := c.Read(buf[consumed:])
				if err != nil {
					errs++
					goto done
				}
				consumed += m
				continue
			}
			cl := contentLength(buf[:idx+4])
			need := idx + 4 + cl
			for consumed < need {
				m, err := c.Read(buf[consumed:])
				if err != nil {
					errs++
					goto done
				}
				consumed += m
			}
			// shift leftover
			rest := copy(buf, buf[need:consumed])
			consumed = rest
			break
		}
		dt := time.Since(t0).Microseconds()
		n++
		sum += dt
		if len(lats) < 200000 {
			lats = append(lats, dt)
		}
	}
done:
	res.n += n
	res.errs += errs
	res.sumUs += sum
	res.lats = append(res.lats, lats...)
}

func workerChurn(a string, p string, deadline time.Time, res *result, req []byte) {
	buf := make([]byte, 65536)
	lats := make([]int64, 0, 4096)
	var n, errs, sum int64
	for time.Now().Before(deadline) {
		t0 := time.Now()
		requireLoop := true
		for requireLoop {
			requireLoop = false
			c, err := net.Dial("tcp", a)
			if err != nil {
				errs++
				break
			}
			_ = c.(*net.TCPConn).SetNoDelay(true)
			if _, err := c.Write(req); err != nil {
				errs++
				c.Close()
				break
			}
			consumed := 0
			ok := false
			for {
				idx := indexHeaderEnd(buf[:consumed])
				if idx < 0 {
					m, err := c.Read(buf[consumed:])
					if err != nil {
						break
					}
					consumed += m
					continue
				}
				cl := contentLength(buf[:idx+4])
				need := idx + 4 + cl
				for consumed < need {
					m, err := c.Read(buf[consumed:])
					if err != nil {
						break
					}
					consumed += m
				}
				ok = consumed >= need
				break
			}
			c.Close()
			if !ok {
				errs++
				break
			}
			n++
			sum += time.Since(t0).Microseconds()
			if len(lats) < 200000 {
				lats = append(lats, time.Since(t0).Microseconds())
			}
		}
	}
	res.n += n
	res.errs += errs
	res.sumUs += sum
	res.lats = append(res.lats, lats...)
}

func indexHeaderEnd(b []byte) int {
	for i := 0; i+4 <= len(b); i++ {
		if b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n' {
			return i
		}
	}
	return -1
}

func contentLength(head []byte) int {
	ls := strings.Split(string(head), "\r\n")
	cl := 0
	for _, l := range ls {
		ll := strings.ToLower(l)
		if strings.HasPrefix(ll, "content-length:") {
			v := strings.TrimSpace(l[len("content-length:"):])
			cl, _ = strconv.Atoi(v)
		}
	}
	return cl
}

func main() {
	flag.Parse()
	req := []byte("GET " + *path + " HTTP/1.1\r\nHost: " + *addr + "\r\nConnection: keep-alive\r\n\r\n")
	if *mode == "churn" {
		req = []byte("GET " + *path + " HTTP/1.1\r\nHost: " + *addr + "\r\nConnection: close\r\n\r\n")
	}
	// warmup
	if *warmup > 0 {
		w := time.Now().Add(time.Duration(*warmup * float64(time.Second)))
		var wg sync.WaitGroup
		for i := 0; i < *conns; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); r := &result{}; workerKa(*addr, *path, w, r, req) }()
		}
		wg.Wait()
	}
	c0, haveCPU := cpuTicks(*serverPID)
	t0 := time.Now()
	deadline := t0.Add(time.Duration(*durSec * float64(time.Second)))
	var wg sync.WaitGroup
	results := make([]*result, *conns)
	for i := 0; i < *conns; i++ {
		results[i] = &result{}
		wg.Add(1)
		if *mode == "churn" {
			go func(r *result) { defer wg.Done(); workerChurn(*addr, *path, deadline, r, req) }(results[i])
		} else {
			go func(r *result) { defer wg.Done(); workerKa(*addr, *path, deadline, r, req) }(results[i])
		}
	}
	wg.Wait()
	elapsed := time.Since(t0).Seconds()
	c1, _ := cpuTicks(*serverPID)

	var n, errs, sum int64
	var all []int64
	for _, r := range results {
		n += r.n
		errs += r.errs
		sum += r.sumUs
		all = append(all, r.lats...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	pct := func(p float64) float64 {
		if len(all) == 0 {
			return 0
		}
		return float64(all[int(float64(len(all)-1)*p)]) / 1000.0
	}
	mean := 0.0
	if n > 0 {
		mean = float64(sum) / float64(n) / 1000.0
	}
	cores := 0.0
	if haveCPU {
		cores = float64(c1-c0) / 100.0 / elapsed
	}
	cpus := 0.0
	if haveCPU && n > 0 {
		cpus = float64(c1-c0) / 100.0 / float64(n) * 1e6
	}
	fmt.Printf("[%s] mode=%s conns=%d dur=%.2fs reqs=%d errs=%d rps=%.0f mean=%.2fms p50=%.2fms p90=%.2fms p99=%.2fms cores=%.2f cpu_us=%.2f\n",
		*label, *mode, *conns, elapsed, n, errs, float64(n)/elapsed, mean, pct(0.5), pct(0.9), pct(0.99), cores, cpus)
}
