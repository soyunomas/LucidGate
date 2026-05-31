//go:build ignore
// +build ignore

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type result struct {
	status int
	lat    time.Duration
	err    error
}

type metricsSample struct {
	activeConnections float64
	goroutines        float64
	openFDs           float64
	rssBytes          float64
}

func main() {
	proxyAddr := flag.String("proxy", "http://127.0.0.1:8080", "HTTP proxy URL")
	metricsURL := flag.String("metrics", "http://127.0.0.1:6060/metrics", "Prometheus metrics URL")
	listenAddr := flag.String("listen", "127.0.0.1:18080", "local upstream listen address")
	mode := flag.String("mode", "all", "test mode: load, leak, all")
	concurrency := flag.Int("concurrency", 100, "number of concurrent workers")
	duration := flag.Duration("duration", 5*time.Second, "duration of load test per round")
	delay := flag.Duration("delay", 10*time.Millisecond, "upstream response delay")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	keepAlive := flag.Bool("keepalive", true, "reuse per-device connections")
	flag.Parse()

	// Start standard local upstream
	upstreamURL, stop := startUpstream(*listenAddr, *delay)
	defer stop()

	fmt.Printf("LucidGate Benchmark Suite\n")
	fmt.Printf("=========================\n")
	fmt.Printf("Proxy:      %s\n", *proxyAddr)
	fmt.Printf("Upstream:   %s\n", upstreamURL)
	fmt.Printf("Mode:       %s\n", *mode)
	fmt.Printf("Workers:    %d\n", *concurrency)
	fmt.Printf("Duration:   %s\n", *duration)
	fmt.Printf("KeepAlive:  %t\n\n", *keepAlive)

	hcClient := &http.Client{Timeout: 2 * time.Second}
	if _, err := hcClient.Get(*metricsURL); err != nil {
		log.Fatalf("Error: Metrics server not reachable at %s. Ensure LucidGate is running with metrics enabled.\n", *metricsURL)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(mustURL(*proxyAddr)),
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        *concurrency,
		MaxIdleConnsPerHost: *concurrency,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   !*keepAlive,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
	}

	if *mode == "load" || *mode == "all" {
		runLoadTest(client, *metricsURL, upstreamURL, *concurrency, *duration)
	}

	if *mode == "leak" || *mode == "all" {
		runLeakTest(client, *metricsURL, upstreamURL, *concurrency, *duration)
	}
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		log.Fatal(err)
	}
	return u
}

func startUpstream(addr string, delay time.Duration) (string, func()) {
	mux := http.NewServeMux()
	var active atomic.Int64
	mux.HandleFunc("/payload", func(w http.ResponseWriter, r *http.Request) {
		cur := active.Add(1)
		defer active.Add(-1)
		if delay > 0 {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream-Active", strconv.FormatInt(cur, 10))
		_, _ = io.WriteString(w, "ok\n")
	})

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("upstream failed: %v", err)
		}
	}()
	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	return "http://" + ln.Addr().String() + "/payload", stop
}

func runLoadTest(client *http.Client, metricsURL, target string, concurrency int, duration time.Duration) {
	fmt.Printf("--- Starting Load Test ---\n")
	results := make(chan result, 200000)
	var activeWorkers int32 = int32(concurrency)
	var totalRequests int64 = 0

	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	metricsDone := pollMetrics(metricsCtx, metricsURL, 50*time.Millisecond)

	start := time.Now()
	deadline := start.Add(duration)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				reqStart := time.Now()
				resp, err := client.Get(target)
				atomic.AddInt64(&totalRequests, 1)
				if err != nil {
					results <- result{lat: time.Since(reqStart), err: err}
					continue
				}
				_, readErr := io.Copy(io.Discard, resp.Body)
				closeErr := resp.Body.Close()
				if readErr != nil {
					results <- result{status: resp.StatusCode, lat: time.Since(reqStart), err: readErr}
					continue
				}
				if closeErr != nil {
					results <- result{status: resp.StatusCode, lat: time.Since(reqStart), err: closeErr}
					continue
				}
				results <- result{status: resp.StatusCode, lat: time.Since(reqStart)}
			}
			atomic.AddInt32(&activeWorkers, -1)
		}()
	}

	wg.Wait()
	stopMetrics()
	peak := <-metricsDone
	close(results)
	elapsed := time.Since(start)

	statuses := map[int]int{}
	errs := 0
	lats := make([]time.Duration, 0, totalRequests)
	for res := range results {
		if res.err != nil {
			errs++
			continue
		}
		statuses[res.status]++
		lats = append(lats, res.lat)
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })

	fmt.Printf("Execution Details:\n")
	fmt.Printf("  Elapsed time:      %s\n", elapsed.Round(time.Millisecond))
	fmt.Printf("  Total Requests:    %d\n", len(lats)+errs)
	fmt.Printf("  Successful (200):  %d\n", statuses[http.StatusOK])
	fmt.Printf("  Errors:            %d\n", errs)
	if elapsed.Seconds() > 0 {
		fmt.Printf("  Throughput (RPS):  %.1f req/s\n", float64(len(lats)+errs)/elapsed.Seconds())
	}
	fmt.Printf("  Latencies:\n")
	fmt.Printf("    P50 (Median):    %s\n", percentile(lats, 50))
	fmt.Printf("    P95:             %s\n", percentile(lats, 95))
	fmt.Printf("    P99:             %s\n", percentile(lats, 99))
	fmt.Printf("    Max:             %s\n", percentile(lats, 100))
	fmt.Printf("  Peak Metrics (LucidGate):\n")
	fmt.Printf("    Active Conns:    %.0f\n", peak.activeConnections)
	fmt.Printf("    Goroutines:      %.0f\n", peak.goroutines)
	fmt.Printf("    Open FDs:        %.0f\n", peak.openFDs)
	fmt.Printf("    RSS Memory:      %.1f MB\n\n", peak.rssBytes/(1024*1024))
}

func runLeakTest(client *http.Client, metricsURL, target string, concurrency int, duration time.Duration) {
	fmt.Printf("--- Starting Leakage Detection Test ---\n")
	httpClient := &http.Client{Timeout: time.Second}

	// 1. Establish baseline
	baseline, err := scrapeMetrics(httpClient, metricsURL)
	if err != nil {
		log.Fatalf("Failed to retrieve baseline metrics: %v\n", err)
	}
	fmt.Printf("Baseline metrics: Goroutines=%.0f, OpenFDs=%.0f\n", baseline.goroutines, baseline.openFDs)

	// 2. Perform aggressive stress round
	fmt.Printf("Stressing with %d workers for %s...\n", concurrency, duration)
	runLoadRoundSilent(client, target, concurrency, duration)

	// 3. Close idle connections to trigger draining
	client.Transport.(*http.Transport).CloseIdleConnections()

	// 4. Wait for graceful draining (allowing background work to settle)
	gracePeriod := 5 * time.Second
	fmt.Printf("Waiting %s for connections and goroutines to settle...\n", gracePeriod)
	time.Sleep(gracePeriod)

	// 5. Sample post-load metrics
	postLoad, err := scrapeMetrics(httpClient, metricsURL)
	if err != nil {
		log.Fatalf("Failed to retrieve post-load metrics: %v\n", err)
	}
	fmt.Printf("Post-load metrics: Goroutines=%.0f, OpenFDs=%.0f\n", postLoad.goroutines, postLoad.openFDs)

	// 6. Assert leakage criteria
	leakDetected := false
	fdThreshold := baseline.openFDs + 5
	if postLoad.openFDs > fdThreshold {
		fmt.Printf("❌ ERROR: File descriptor leak detected! Post-load FDs (%.0f) > baseline (%.0f) + threshold.\n", postLoad.openFDs, baseline.openFDs)
		leakDetected = true
	}

	goroutineThreshold := baseline.goroutines + 10
	if postLoad.goroutines > goroutineThreshold {
		fmt.Printf("❌ ERROR: Goroutine leak detected! Post-load Goroutines (%.0f) > baseline (%.0f) + threshold.\n", postLoad.goroutines, baseline.goroutines)
		leakDetected = true
	}

	if !leakDetected {
		fmt.Printf("✅ SUCCESS: No FDs or Goroutines leaks detected (post-load returned to baseline levels).\n\n")
	} else {
		os.Exit(1)
	}
}

func runLoadRoundSilent(client *http.Client, target string, concurrency int, duration time.Duration) {
	deadline := time.Now().Add(duration)
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				resp, err := client.Get(target)
				if err == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}
		}()
	}
	wg.Wait()
}

func pollMetrics(ctx context.Context, metricsURL string, interval time.Duration) <-chan metricsSample {
	done := make(chan metricsSample, 1)
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		client := &http.Client{Timeout: 500 * time.Millisecond}
		var peak metricsSample
		for {
			sample, err := scrapeMetrics(client, metricsURL)
			if err == nil {
				if sample.activeConnections > peak.activeConnections {
					peak.activeConnections = sample.activeConnections
				}
				if sample.goroutines > peak.goroutines {
					peak.goroutines = sample.goroutines
				}
				if sample.openFDs > peak.openFDs {
					peak.openFDs = sample.openFDs
				}
				if sample.rssBytes > peak.rssBytes {
					peak.rssBytes = sample.rssBytes
				}
			}
			select {
			case <-ctx.Done():
				done <- peak
				return
			case <-ticker.C:
			}
		}
	}()
	return done
}

func scrapeMetrics(client *http.Client, metricsURL string) (metricsSample, error) {
	resp, err := client.Get(metricsURL)
	if err != nil {
		return metricsSample{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return metricsSample{}, err
	}
	var out metricsSample
	for _, line := range strings.Split(string(data), "\n") {
		name, value, ok := parseMetricLine(line)
		if !ok {
			continue
		}
		switch name {
		case "lucidgate_active_connections":
			out.activeConnections = value
		case "go_goroutines":
			out.goroutines = value
		case "process_open_fds":
			out.openFDs = value
		case "process_resident_memory_bytes":
			out.rssBytes = value
		}
	}
	return out, nil
}

func parseMetricLine(line string) (string, float64, bool) {
	if line == "" || strings.HasPrefix(line, "#") {
		return "", 0, false
	}
	fields := strings.Fields(line)
	if len(fields) != 2 {
		return "", 0, false
	}
	value, err := strconv.ParseFloat(fields[1], 64)
	if err != nil {
		return "", 0, false
	}
	name := fields[0]
	if idx := strings.IndexByte(name, '{'); idx >= 0 {
		name = name[:idx]
	}
	return name, value, true
}

func formatStatuses(statuses map[int]int) string {
	keys := make([]int, 0, len(statuses))
	for code := range statuses {
		keys = append(keys, code)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, code := range keys {
		parts = append(parts, fmt.Sprintf("%d:%d", code, statuses[code]))
	}
	return strings.Join(parts, ",")
}

func percentile(values []time.Duration, pct float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	if pct >= 100 {
		return values[len(values)-1].Round(time.Microsecond)
	}
	idx := int(math.Ceil((pct/100)*float64(len(values)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx].Round(time.Microsecond)
}
