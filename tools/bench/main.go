// Bench is a small load generator for SonuShield (stdlib only).
// It measures requests/sec, latency percentiles, and error rate
// against a locally running proxy + dummy backend.
//
// Modes:
//   cookie    - warm a challenge cookie once per worker, then hammer GET /
//   challenge - fresh cookie jar per iteration: full Stage-1 redirect flow
//   pow       - no cookie, stage locked at 2: PoW page serving, no solving
//
// Usage: bench -mode cookie -duration 30s -workers 32
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"sort"
	"sync"
	"time"
)

var (
	mode     = flag.String("mode", "cookie", "cookie|challenge|pow")
	duration = flag.Duration("duration", 30*time.Second, "run duration")
	workers  = flag.Int("workers", 32, "concurrent workers")
	target   = flag.String("url", "https://127.0.0.1:443/", "target URL")
	host     = flag.String("host", "example.com", "Host header / SNI name")
)

func newTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // test-only: self-signed bench cert
			ServerName:         *host,
		},
		MaxIdleConns:        256,
		MaxIdleConnsPerHost: 256,
		DisableCompression:  false,
	}
}

func doReq(client *http.Client, jar http.CookieJar) (time.Duration, int, error) {
	req, err := http.NewRequest("GET", *target, nil)
	if err != nil {
		return 0, 0, err
	}
	req.Host = *host
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return time.Since(start), 0, err
	}
	_, copyErr := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if copyErr != nil {
		return time.Since(start), resp.StatusCode, copyErr
	}
	return time.Since(start), resp.StatusCode, nil
}

func main() {
	flag.Parse()
	transport := newTransport()

	deadline := time.Now().Add(*duration)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var latencies []time.Duration
	var ok, errors int
	errKinds := map[string]int{}

	// Warm-up: one request to make sure the proxy answers.
	warmJar, _ := cookiejar.New(nil)
	warmClient := &http.Client{Transport: transport, Jar: warmJar, Timeout: 10 * time.Second}
	if _, status, err := doReq(warmClient, warmJar); err != nil || (status != 200 && status != 302) {
		fmt.Fprintf(os.Stderr, "warm-up failed: status=%d err=%v\n", status, err)
		os.Exit(2)
	}

	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			jar, _ := cookiejar.New(nil)
			client := &http.Client{Transport: transport, Jar: jar, Timeout: 15 * time.Second}
			// In cookie mode the jar is warmed once and reused,
			// so every timed request carries a valid cookie.
			if *mode == "cookie" {
				_, _, _ = doReq(client, jar)
			}
			for time.Now().Before(deadline) {
				if *mode == "challenge" {
					// Fresh jar per iteration = a new visitor
					// doing the full Stage-1 redirect flow.
					jar, _ = cookiejar.New(nil)
					client.Jar = jar
				}
				lat, status, err := doReq(client, jar)
				mu.Lock()
				latencies = append(latencies, lat)
				if err != nil {
					errors++
					errKinds["transport"]++
				} else if status != 200 {
					errors++
					errKinds[fmt.Sprintf("http_%d", status)]++
				} else {
					ok++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	total := ok + errors
	elapsed := *duration
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	pct := func(p float64) time.Duration {
		if len(latencies) == 0 {
			return 0
		}
		idx := int(p * float64(len(latencies)-1))
		return latencies[idx]
	}
	var sum time.Duration
	for _, l := range latencies {
		sum += l
	}
	mean := time.Duration(0)
	if len(latencies) > 0 {
		mean = sum / time.Duration(len(latencies))
	}
	u, _ := url.Parse(*target)
	fmt.Printf("mode=%s workers=%d duration=%s target=%s host=%s\n", *mode, *workers, elapsed, u.Host, *host)
	fmt.Printf("requests=%d ok=%d errors=%d rps=%.1f\n", total, ok, errors, float64(total)/elapsed.Seconds())
	fmt.Printf("latency mean=%s p50=%s p95=%s p99=%s max=%s\n", mean, pct(0.50), pct(0.95), pct(0.99), latencies[len(latencies)-1])
	fmt.Printf("error_kinds=%v\n", errKinds)
}
