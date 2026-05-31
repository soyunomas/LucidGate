//go:build ignore
// +build ignore

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	metricsURL := flag.String("metrics", "http://127.0.0.1:6060", "LucidGate administration base URL")
	outDir := flag.String("out", "bench/profiles", "Output directory for profiles")
	seconds := flag.Int("seconds", 5, "CPU profiling duration in seconds")
	flag.Parse()

	fmt.Printf("LucidGate Profiler Collector\n")
	fmt.Printf("============================\n")
	fmt.Printf("Admin Base URL:  %s\n", *metricsURL)
	fmt.Printf("Output Dir:      %s\n", *outDir)
	fmt.Printf("CPU Profile Sec: %d\n\n", *seconds)

	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	httpClient := &http.Client{Timeout: time.Duration(*seconds+5) * time.Second}

	// 1. Fetch Heap Profile
	heapURL := fmt.Sprintf("%s/debug/pprof/heap", *metricsURL)
	heapFile := filepath.Join(*outDir, fmt.Sprintf("heap_%s.pprof", time.Now().Format("20060102_150405")))
	fmt.Printf("Fetching Heap Profile from %s...\n", heapURL)
	if err := downloadProfile(httpClient, heapURL, heapFile); err != nil {
		log.Fatalf("Failed to fetch heap profile: %v", err)
	}
	fmt.Printf("✅ Heap profile saved to %s\n\n", heapFile)

	// 2. Fetch CPU Profile
	cpuURL := fmt.Sprintf("%s/debug/pprof/profile?seconds=%d", *metricsURL, *seconds)
	cpuFile := filepath.Join(*outDir, fmt.Sprintf("cpu_%s.pprof", time.Now().Format("20060102_150405")))
	fmt.Printf("Fetching CPU Profile (%ds) from %s...\n", *seconds, cpuURL)
	if err := downloadProfile(httpClient, cpuURL, cpuFile); err != nil {
		log.Fatalf("Failed to fetch CPU profile: %v", err)
	}
	fmt.Printf("✅ CPU profile saved to %s\n\n", cpuFile)

	fmt.Printf("Profiles collected successfully. You can inspect them using:\n")
	fmt.Printf("  go tool pprof -http=:8089 %s\n", cpuFile)
	fmt.Printf("  go tool pprof -http=:8089 %s\n\n", heapFile)
}

func downloadProfile(client *http.Client, url, filename string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	out, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}
