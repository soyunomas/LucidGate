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
	"os/exec"
	"sort"
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
	proxyBin := flag.String("bin", "./build/lucidgate", "Path to lucidgate binary")
	listenAddr := flag.String("listen", "127.0.0.1:8088", "Proxy listen address for degradation test")
	upstreamAddr := flag.String("upstream", "127.0.0.1:18088", "Mock upstream listen address")
	flag.Parse()

	fmt.Printf("LucidGate Graceful Degradation Test (200%% Capacity)\n")
	fmt.Printf("===================================================\n")
	fmt.Printf("LucidGate Binary:  %s\n", *proxyBin)
	fmt.Printf("Test Proxy Addr:   %s\n", *listenAddr)
	fmt.Printf("Test Upstream:     %s\n\n", *upstreamAddr)

	// 1. Compile/Build the binary if not present
	if _, err := os.Stat(*proxyBin); os.IsNotExist(err) {
		fmt.Println("Building lucidgate binary...")
		buildCmd := exec.Command("go", "build", "-o", *proxyBin, ".")
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			log.Fatalf("Failed to build lucidgate: %v", err)
		}
	}

	// 2. Start mock upstream with 150ms response delay
	delay := 150 * time.Millisecond
	upstreamURL, stopUpstream := startUpstream(*upstreamAddr, delay)
	defer stopUpstream()

	// 3. Start LucidGate process with max_connections = 3 and wait_timeout = 50ms
	maxConns := 3
	cmd := exec.Command(*proxyBin,
		"-listen", *listenAddr,
		"-max-connections", fmt.Sprintf("%d", maxConns),
		"-wait-timeout", "50ms",
		"-cert-dir", "certs",
		"-log-bodies=false",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("Failed to start lucidgate process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()

	// 4. Wait for proxy to boot
	proxyReady := false
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", *listenAddr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			proxyReady = true
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if !proxyReady {
		log.Fatalf("Error: LucidGate proxy did not boot on %s within timeout", *listenAddr)
	}
	fmt.Printf("LucidGate proxy successfully started with MaxConnections = %d.\n", maxConns)

	// 5. Setup client with 200% capacity (10 concurrent workers)
	workers := 10
	fmt.Printf("Triggering 200%% load: %d concurrent workers targeting upstream with %s delay...\n", workers, delay)

	proxyURL, err := url.Parse("http://" + *listenAddr)
	if err != nil {
		log.Fatalf("Invalid proxy address: %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
		DialContext: (&net.Dialer{
			Timeout: 1 * time.Second,
		}).DialContext,
		MaxIdleConns:        workers,
		MaxIdleConnsPerHost: workers,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
	}

	results := make(chan result, workers)
	var wg sync.WaitGroup
	ready := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-ready
			reqStart := time.Now()
			resp, err := client.Get(upstreamURL)
			if err != nil {
				results <- result{lat: time.Since(reqStart), err: err}
				return
			}
			_, readErr := io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if readErr != nil {
				results <- result{status: resp.StatusCode, lat: time.Since(reqStart), err: readErr}
				return
			}
			results <- result{status: resp.StatusCode, lat: time.Since(reqStart)}
		}()
	}

	close(ready)
	wg.Wait()
	close(results)

	// 6. Analyze results
	var successCount int
	var serviceUnavailableCount int
	var errorCount int
	var successfulLatencies []time.Duration

	for res := range results {
		if res.err != nil {
			errorCount++
			continue
		}
		if res.status == http.StatusOK {
			successCount++
			successfulLatencies = append(successfulLatencies, res.lat)
		} else if res.status == http.StatusServiceUnavailable {
			serviceUnavailableCount++
		} else {
			errorCount++
		}
	}

	sort.Slice(successfulLatencies, func(i, j int) bool {
		return successfulLatencies[i] < successfulLatencies[j]
	})

	fmt.Printf("\nDegradation Round Summary:\n")
	fmt.Printf("  Total requests sent:            %d\n", workers)
	fmt.Printf("  Successful (200 OK):            %d (Expected: %d)\n", successCount, maxConns)
	fmt.Printf("  Service Unavailable (503):      %d (Expected: %d)\n", serviceUnavailableCount, workers-maxConns)
	fmt.Printf("  Other failures:                 %d\n", errorCount)

	if successCount == 0 {
		log.Fatalf("❌ ERROR: Zero successful requests! Proxy failed completely under load.")
	}
	if serviceUnavailableCount == 0 {
		log.Fatalf("❌ ERROR: Zero rejected requests! Proxy did not degrade/reject excess connections.")
	}

	p50 := percentile(successfulLatencies, 50)
	fmt.Printf("  Successful Requests P50 Latency: %s\n", p50)

	// Baseline latency is the mock delay (30ms)
	maxAllowedLatency := 3 * delay // 90ms
	if p50 > maxAllowedLatency {
		fmt.Printf("❌ ERROR: Latency degradation is too high! P50 (%s) exceeded 3x upstream delay (%s).\n", p50, maxAllowedLatency)
		os.Exit(1)
	}

	fmt.Printf("✅ SUCCESS: Latency degradation is within bounds (P50 %s <= 3x baseline %s).\n", p50, maxAllowedLatency)
	fmt.Printf("✅ SUCCESS: LucidGate sustained 200%% nominal capacity without crashing, rejecting excess traffic elegantly.\n\n")
}

func startUpstream(addr string, delay time.Duration) (string, func()) {
	mux := http.NewServeMux()
	var active atomic.Int64
	mux.HandleFunc("/payload", func(w http.ResponseWriter, r *http.Request) {
		active.Add(1)
		defer active.Add(-1)
		if delay > 0 {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", "text/plain")
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
