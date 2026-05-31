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

func main() {
	proxyAddr := flag.String("proxy", "http://127.0.0.1:8080", "HTTP proxy URL")
	metricsURL := flag.String("metrics", "http://127.0.0.1:6060/metrics", "Prometheus metrics URL")
	listenAddr := flag.String("listen", "127.0.0.1:18080", "local upstream listen address")
	roundsFlag := flag.String("rounds", "100,500,1000", "comma-separated concurrency/request counts")
	delay := flag.Duration("delay", 200*time.Millisecond, "upstream response delay")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	flag.Parse()

	rounds, err := parseRounds(*roundsFlag)
	if err != nil {
		log.Fatal(err)
	}
	upstreamURL, stop := startUpstream(*listenAddr, *delay)
	defer stop()

	transport := &http.Transport{
		Proxy: http.ProxyURL(mustURL(*proxyAddr)),
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 4096,
		MaxConnsPerHost:     0,
		IdleConnTimeout:     30 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
	}

	fmt.Printf("proxy=%s upstream=%s delay=%s timeout=%s\n", *proxyAddr, upstreamURL, delay.String(), timeout.String())
	for _, n := range rounds {
		runRound(client, *metricsURL, upstreamURL, n)
		time.Sleep(500 * time.Millisecond)
	}
}

func parseRounds(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid round %q", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no rounds configured")
	}
	return out, nil
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
		time.Sleep(delay)
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

func runRound(client *http.Client, metricsURL, target string, n int) {
	start := time.Now()
	results := make(chan result, n)
	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	metricsDone := pollMetrics(metricsCtx, metricsURL, 25*time.Millisecond)
	var wg sync.WaitGroup
	ready := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			reqStart := time.Now()
			resp, err := client.Get(target)
			if err != nil {
				results <- result{lat: time.Since(reqStart), err: err}
				return
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			closeErr := resp.Body.Close()
			if readErr != nil {
				results <- result{status: resp.StatusCode, lat: time.Since(reqStart), err: readErr}
				return
			}
			if closeErr != nil {
				results <- result{status: resp.StatusCode, lat: time.Since(reqStart), err: closeErr}
				return
			}
			results <- result{status: resp.StatusCode, lat: time.Since(reqStart)}
		}()
	}
	close(ready)
	wg.Wait()
	stopMetrics()
	peak := <-metricsDone
	close(results)

	statuses := map[int]int{}
	errs := 0
	lats := make([]time.Duration, 0, n)
	for res := range results {
		if res.err != nil {
			errs++
			continue
		}
		statuses[res.status]++
		lats = append(lats, res.lat)
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	elapsed := time.Since(start)
	fmt.Printf("round concurrency=%d elapsed=%s ok=%d statuses=%s errors=%d rps=%.1f p50=%s p95=%s p99=%s max=%s peak_active=%.0f peak_goroutines=%.0f peak_fds=%.0f\n",
		n,
		elapsed.Round(time.Millisecond),
		statuses[http.StatusOK],
		formatStatuses(statuses),
		errs,
		float64(n)/elapsed.Seconds(),
		percentile(lats, 50),
		percentile(lats, 95),
		percentile(lats, 99),
		percentile(lats, 100),
		peak.activeConnections,
		peak.goroutines,
		peak.openFDs,
	)
}

type metricsPeak struct {
	activeConnections float64
	goroutines        float64
	openFDs           float64
}

func pollMetrics(ctx context.Context, metricsURL string, interval time.Duration) <-chan metricsPeak {
	done := make(chan metricsPeak, 1)
	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		client := &http.Client{Timeout: 500 * time.Millisecond}
		var peak metricsPeak
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

func scrapeMetrics(client *http.Client, metricsURL string) (metricsPeak, error) {
	resp, err := client.Get(metricsURL)
	if err != nil {
		return metricsPeak{}, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return metricsPeak{}, err
	}
	var out metricsPeak
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
		return values[len(values)-1].Round(time.Millisecond)
	}
	idx := int(math.Ceil((pct/100)*float64(len(values)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx].Round(time.Millisecond)
}
