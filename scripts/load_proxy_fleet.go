//go:build ignore
// +build ignore

// load_proxy_fleet.go simulates many client machines against LucidGate.
// Each logical machine binds outbound proxy connections to a distinct
// loopback source IP (127.64.x.y) and opens N concurrent connections.
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
	device int
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

type upstreamStats struct {
	active atomic.Int64
	peak   atomic.Int64
}

func main() {
	proxyAddr := flag.String("proxy", "http://127.0.0.1:8080", "HTTP proxy URL")
	metricsURL := flag.String("metrics", "http://127.0.0.1:6060/metrics", "Prometheus metrics URL")
	listenAddr := flag.String("listen", "127.0.0.1:18080", "local upstream listen address")
	devicesFlag := flag.String("devices", "50,150,300,500", "comma-separated logical machine counts")
	connsPerDevice := flag.Int("conns-per-device", 4, "concurrent proxy connections per logical machine")
	requestsPerConn := flag.Int("requests-per-conn", 1, "sequential requests per logical connection")
	delay := flag.Duration("delay", 200*time.Millisecond, "upstream response delay")
	timeout := flag.Duration("timeout", 15*time.Second, "per-request timeout")
	keepAlive := flag.Bool("keepalive", true, "reuse per-device connections for sequential requests")
	flag.Parse()

	devices, err := parseInts(*devicesFlag)
	if err != nil {
		log.Fatal(err)
	}
	if *connsPerDevice <= 0 {
		log.Fatal("conns-per-device must be positive")
	}
	if *requestsPerConn <= 0 {
		log.Fatal("requests-per-conn must be positive")
	}

	stats := &upstreamStats{}
	upstreamURL, stop := startUpstream(*listenAddr, *delay, stats)
	defer stop()

	fmt.Printf("proxy=%s upstream=%s delay=%s timeout=%s conns_per_device=%d requests_per_conn=%d keepalive=%t\n",
		*proxyAddr, upstreamURL, delay.String(), timeout.String(), *connsPerDevice, *requestsPerConn, *keepAlive)
	for _, n := range devices {
		runRound(*proxyAddr, *metricsURL, upstreamURL, n, *connsPerDevice, *requestsPerConn, *timeout, *keepAlive, stats)
		time.Sleep(750 * time.Millisecond)
	}
}

func runRound(proxyAddr, metricsURL, target string, devices, connsPerDevice, requestsPerConn int, timeout time.Duration, keepAlive bool, upstream *upstreamStats) {
	totalConnections := devices * connsPerDevice
	totalRequests := totalConnections * requestsPerConn
	results := make(chan result, totalRequests)
	clients := make([]*http.Client, 0, devices)
	transports := make([]*http.Transport, 0, devices)
	proxyURL := mustURL(proxyAddr)
	for device := 0; device < devices; device++ {
		srcIP := loopbackDeviceIP(device)
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			DialContext: (&net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
				LocalAddr: &net.TCPAddr{IP: srcIP},
			}).DialContext,
			MaxIdleConns:        totalConnections,
			MaxIdleConnsPerHost: connsPerDevice,
			MaxConnsPerHost:     connsPerDevice,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   !keepAlive,
		}
		transports = append(transports, transport)
		clients = append(clients, &http.Client{Transport: transport, Timeout: timeout})
	}
	defer func() {
		for _, transport := range transports {
			transport.CloseIdleConnections()
		}
	}()

	upstream.peak.Store(0)
	start := time.Now()
	metricsCtx, stopMetrics := context.WithCancel(context.Background())
	metricsDone := pollMetrics(metricsCtx, metricsURL, 25*time.Millisecond)
	var wg sync.WaitGroup
	ready := make(chan struct{})
	for device := 0; device < devices; device++ {
		client := clients[device]
		for connID := 0; connID < connsPerDevice; connID++ {
			wg.Add(1)
			go func(device, connID int, client *http.Client) {
				defer wg.Done()
				<-ready
				for reqID := 0; reqID < requestsPerConn; reqID++ {
					reqStart := time.Now()
					url := fmt.Sprintf("%s?device=%d&conn=%d&req=%d", target, device, connID, reqID)
					resp, err := client.Get(url)
					if err != nil {
						results <- result{device: device, lat: time.Since(reqStart), err: err}
						continue
					}
					_, readErr := io.Copy(io.Discard, resp.Body)
					closeErr := resp.Body.Close()
					if readErr != nil {
						results <- result{device: device, status: resp.StatusCode, lat: time.Since(reqStart), err: readErr}
						continue
					}
					if closeErr != nil {
						results <- result{device: device, status: resp.StatusCode, lat: time.Since(reqStart), err: closeErr}
						continue
					}
					results <- result{device: device, status: resp.StatusCode, lat: time.Since(reqStart)}
				}
			}(device, connID, client)
		}
	}
	close(ready)
	wg.Wait()
	stopMetrics()
	peakMetrics := <-metricsDone
	close(results)

	statuses := map[int]int{}
	errKinds := map[string]int{}
	deviceOK := make([]bool, devices)
	errs := 0
	lats := make([]time.Duration, 0, totalRequests)
	for res := range results {
		if res.err != nil {
			errs++
			errKinds[classifyErr(res.err)]++
			continue
		}
		statuses[res.status]++
		if res.status >= 200 && res.status < 300 && res.device >= 0 && res.device < devices {
			deviceOK[res.device] = true
		}
		lats = append(lats, res.lat)
	}
	healthyDevices := 0
	for _, ok := range deviceOK {
		if ok {
			healthyDevices++
		}
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	elapsed := time.Since(start)
	fmt.Printf("\nround devices=%d conns_per_device=%d total_conns=%d total_requests=%d elapsed=%s healthy_devices=%d ok=%d statuses=%s errors=%d rps=%.1f p50=%s p95=%s p99=%s max=%s peak_active=%.0f peak_goroutines=%.0f peak_fds=%.0f peak_rss=%.1fMB peak_upstream_active=%d\n",
		devices,
		connsPerDevice,
		totalConnections,
		totalRequests,
		elapsed.Round(time.Millisecond),
		healthyDevices,
		successCount(statuses),
		formatStatuses(statuses),
		errs,
		float64(totalRequests)/elapsed.Seconds(),
		percentile(lats, 50),
		percentile(lats, 95),
		percentile(lats, 99),
		percentile(lats, 100),
		peakMetrics.activeConnections,
		peakMetrics.goroutines,
		peakMetrics.openFDs,
		peakMetrics.rssBytes/(1024*1024),
		upstream.peak.Load(),
	)
	if len(errKinds) > 0 {
		fmt.Printf("  err kinds: %s\n", formatStringMap(errKinds))
	}
}

func startUpstream(addr string, delay time.Duration, stats *upstreamStats) (string, func()) {
	mux := http.NewServeMux()
	mux.HandleFunc("/payload", func(w http.ResponseWriter, r *http.Request) {
		cur := stats.active.Add(1)
		updatePeak(&stats.peak, cur)
		defer stats.active.Add(-1)
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

func updatePeak(peak *atomic.Int64, value int64) {
	for {
		old := peak.Load()
		if value <= old {
			return
		}
		if peak.CompareAndSwap(old, value) {
			return
		}
	}
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
			return nil, fmt.Errorf("invalid count %q", part)
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no counts configured")
	}
	return out, nil
}

func loopbackDeviceIP(device int) net.IP {
	return net.IPv4(127, 64+byte(device/62500), byte((device/250)%250), byte(device%250+1))
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		log.Fatal(err)
	}
	return u
}

func classifyErr(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "deadline exceeded"), strings.Contains(msg, "Client.Timeout"):
		return "timeout"
	case strings.Contains(msg, "connection refused"):
		return "refused"
	case strings.Contains(msg, "cannot assign requested address"):
		return "bind"
	case strings.Contains(msg, "EOF"):
		return "eof"
	case strings.Contains(msg, "reset"):
		return "reset"
	case strings.Contains(msg, "503"):
		return "503"
	default:
		return "other"
	}
}

func successCount(statuses map[int]int) int {
	total := 0
	for code, count := range statuses {
		if code >= 200 && code < 300 {
			total += count
		}
	}
	return total
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

func formatStringMap(m map[string]int) string {
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
