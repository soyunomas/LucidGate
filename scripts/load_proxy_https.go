// load_proxy_https.go: load test through LucidGate against real HTTPS targets.
// Uses InsecureSkipVerify so the client accepts LucidGate's MITM cert without
// importing the CA. Targets must be hosts designed for high-volume probes
// (captive-portal checks, CDN trace endpoints).

//go:build ignore
// +build ignore

package main

import (
	"context"
	"crypto/tls"
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
	"time"
)

type result struct {
	status int
	host   string
	lat    time.Duration
	err    error
}

func main() {
	proxyAddr := flag.String("proxy", "http://127.0.0.1:8080", "HTTP proxy URL")
	metricsURL := flag.String("metrics", "http://127.0.0.1:6060/metrics", "Prometheus metrics URL")
	roundsFlag := flag.String("rounds", "50,200,500", "comma-separated concurrency counts")
	targetsFlag := flag.String("targets", strings.Join([]string{
		"https://www.google.com/generate_204",
		"https://www.gstatic.com/generate_204",
		"https://www.cloudflare.com/cdn-cgi/trace",
		"https://1.1.1.1/cdn-cgi/trace",
	}, ","), "comma-separated HTTPS targets")
	timeout := flag.Duration("timeout", 30*time.Second, "per-request timeout")
	requestsPerWorker := flag.Int("requests-per-worker", 1, "sequential requests each concurrent worker sends")
	clientKeepAlive := flag.Bool("client-keepalive", false, "reuse client connections to the proxy instead of forcing one CONNECT per request")
	flag.Parse()

	rounds, err := parseInts(*roundsFlag)
	if err != nil {
		log.Fatal(err)
	}
	targets := splitNonEmpty(*targetsFlag, ",")
	if len(targets) == 0 {
		log.Fatal("no targets")
	}
	if *requestsPerWorker <= 0 {
		log.Fatal("requests-per-worker must be positive")
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(mustURL(*proxyAddr)),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        4096,
		MaxIdleConnsPerHost: 4096,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   false,
		DisableKeepAlives:   !*clientKeepAlive,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   *timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fmt.Printf("proxy=%s timeout=%s client_keepalive=%t requests_per_worker=%d targets=%d (%s)\n", *proxyAddr, timeout.String(), *clientKeepAlive, *requestsPerWorker, len(targets), strings.Join(targets, ", "))
	for _, n := range rounds {
		runRound(client, *metricsURL, targets, n, *requestsPerWorker)
		time.Sleep(1 * time.Second)
	}
}

func parseInts(raw string) ([]int, error) {
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
		return nil, fmt.Errorf("no rounds")
	}
	return out, nil
}

func splitNonEmpty(raw, sep string) []string {
	out := []string{}
	for _, s := range strings.Split(raw, sep) {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		log.Fatal(err)
	}
	return u
}

func runRound(client *http.Client, metricsURL string, targets []string, n int, requestsPerWorker int) {
	start := time.Now()
	total := n * requestsPerWorker
	results := make(chan result, total)
	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	metricsDone := pollMetrics(metricsCtx, metricsURL, 25*time.Millisecond)
	var wg sync.WaitGroup
	ready := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-ready
			for j := 0; j < requestsPerWorker; j++ {
				url := targets[(idx+j)%len(targets)]
				reqStart := time.Now()
				host := hostOf(url)
				resp, err := client.Get(url)
				if err != nil {
					results <- result{host: host, lat: time.Since(reqStart), err: err}
					continue
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
				_ = resp.Body.Close()
				results <- result{host: host, status: resp.StatusCode, lat: time.Since(reqStart)}
			}
		}(i)
	}
	close(ready)
	wg.Wait()
	stopMetrics()
	peak := <-metricsDone
	close(results)

	statuses := map[int]int{}
	perHostOK := map[string]int{}
	perHostErr := map[string]int{}
	errSamples := map[string]int{}
	errs := 0
	lats := make([]time.Duration, 0, total)
	for res := range results {
		if res.err != nil {
			errs++
			perHostErr[res.host]++
			key := classifyErr(res.err)
			errSamples[key]++
			continue
		}
		statuses[res.status]++
		perHostOK[res.host]++
		lats = append(lats, res.lat)
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	elapsed := time.Since(start)
	fmt.Printf("\nround concurrency=%d total_requests=%d elapsed=%s ok=%d statuses=%s errors=%d rps=%.1f p50=%s p95=%s p99=%s max=%s peak_active=%.0f peak_goroutines=%.0f peak_fds=%.0f\n",
		n,
		total,
		elapsed.Round(time.Millisecond),
		statuses[http.StatusOK]+statuses[http.StatusNoContent],
		formatStatuses(statuses),
		errs,
		float64(total)/elapsed.Seconds(),
		percentile(lats, 50),
		percentile(lats, 95),
		percentile(lats, 99),
		percentile(lats, 100),
		peak.activeConnections,
		peak.goroutines,
		peak.openFDs,
	)
	fmt.Printf("  by host ok: %s\n", formatHostMap(perHostOK))
	if len(perHostErr) > 0 {
		fmt.Printf("  by host err: %s\n", formatHostMap(perHostErr))
	}
	if len(errSamples) > 0 {
		fmt.Printf("  err kinds: %s\n", formatHostMap(errSamples))
	}
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
}

func classifyErr(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "Client.Timeout"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "EOF"):
		return "eof"
	case strings.Contains(msg, "reset"):
		return "reset"
	case strings.Contains(msg, "tls"):
		return "tls"
	case strings.Contains(msg, "503"):
		return "503"
	default:
		return "other"
	}
}

func formatHostMap(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", k, m[k]))
	}
	return strings.Join(parts, ", ")
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
