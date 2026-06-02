package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

type logMap map[string]any

type asyncSafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *asyncSafeBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *asyncSafeBuffer) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	b := make([]byte, s.buf.Len())
	copy(b, s.buf.Bytes())
	return b
}

func (s *asyncSafeBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func TestAsyncHandlerProcessesLogs(t *testing.T) {
	var buf asyncSafeBuffer
	baseHandler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	ah := NewAsyncHandler(baseHandler, 10, "test-sink")
	defer ah.Close()

	logger := slog.New(ah)
	logger.Info("hello", slog.String("key", "val"))

	// Give the worker goroutine a brief moment to process the log
	time.Sleep(50 * time.Millisecond)

	var entry logMap
	if err := json.Unmarshal(buf.Bytes(), &entry); err != nil {
		t.Fatalf("failed to parse log output: %v", err)
	}

	if entry["msg"] != "hello" || entry["key"] != "val" {
		t.Errorf("unexpected log entry content: %v", entry)
	}
}

func TestAsyncHandlerDropsLogsWhenFull(t *testing.T) {
	// Reset metric to avoid interference from other tests
	DroppedLogsTotal.Reset()

	// Use a blocking/stubborn handler to simulate slow IO
	blockedCh := make(chan struct{})
	blocker := &stubbornHandler{blockedCh: blockedCh}

	// Bounded queue with capacity 1
	ah := NewAsyncHandler(blocker, 1, "test-drop-sink")
	defer ah.Close()

	// Fill the queue. First goes to worker immediately, second occupies the queue,
	// third and fourth should be dropped.
	logger := slog.New(ah)
	for i := 0; i < 5; i++ {
		logger.Info("log entry")
	}

	// Clean up worker block
	close(blockedCh)

	// Wait for queue to drain
	time.Sleep(50 * time.Millisecond)

	cnt := testutil.ToFloat64(DroppedLogsTotal.WithLabelValues("test-drop-sink"))
	if cnt == 0 {
		t.Error("expected dropped logs counter to be > 0, got 0")
	}
}

func TestLoggingRoutingAndAlerts(t *testing.T) {
	AlertsTotal.Reset()

	var accessBuf, alertBuf asyncSafeBuffer
	accessLogger := slog.New(NewAsyncHandler(slog.NewJSONHandler(&accessBuf, &slog.HandlerOptions{Level: slog.LevelInfo}), 100, "access"))
	alertLogger := slog.New(NewAsyncHandler(slog.NewJSONHandler(&alertBuf, &slog.HandlerOptions{Level: slog.LevelInfo}), 100, "alert"))

	alertCategories := map[string]bool{
		"bannedsitelist": true,
	}

	opts := RelayOptions{
		AccessLogger:    accessLogger,
		AlertLogger:     alertLogger,
		AlertCategories: alertCategories,
	}

	// 1. Blocked exchange log that fits the category (should double write & increment metric)
	req, _ := http.NewRequest("GET", "http://malicious.com/payload", nil)
	decision := PolicyDecision{
		Blocked:   true,
		MatchType: "bannedsitelist",
		Value:     "malicious.com",
	}

	logExchangeBlocked(nil, req, decision, opts)

	// 2. Blocked exchange log that does NOT fit the category (should write only to access log)
	req2, _ := http.NewRequest("GET", "http://example.com/ok", nil)
	decision2 := PolicyDecision{
		Blocked:   true,
		MatchType: "exceptionsitelist",
		Value:     "example.com",
	}
	logExchangeBlocked(nil, req2, decision2, opts)

	// Wait for async loggers to flush
	time.Sleep(100 * time.Millisecond)

	// Verify access log has 2 records
	accessLines := bytes.Split(bytes.TrimSpace(accessBuf.Bytes()), []byte("\n"))
	if len(accessLines) != 2 {
		t.Fatalf("expected 2 logs in access log, got %d. Content: %s", len(accessLines), accessBuf.String())
	}

	// Verify alert log has 1 record
	alertLines := bytes.Split(bytes.TrimSpace(alertBuf.Bytes()), []byte("\n"))
	if len(alertLines) != 1 || len(alertLines[0]) == 0 {
		t.Fatalf("expected exactly 1 log in alert log, got %d. Content: %s", len(alertLines), alertBuf.String())
	}

	var alertEntry logMap
	if err := json.Unmarshal(alertLines[0], &alertEntry); err != nil {
		t.Fatalf("failed to parse alert log: %v", err)
	}
	if alertEntry["policy_match_type"] != "bannedsitelist" {
		t.Errorf("unexpected alert log policy_match_type: %v", alertEntry["policy_match_type"])
	}

	// Verify prometheus alerts metric
	alertCnt := testutil.ToFloat64(AlertsTotal.WithLabelValues("bannedsitelist"))
	if alertCnt != 1 {
		t.Errorf("expected AlertsTotal to be 1, got %f", alertCnt)
	}
}

type stubbornHandler struct {
	blockedCh chan struct{}
}

func (s *stubbornHandler) Enabled(ctx context.Context, level slog.Level) bool { return true }
func (s *stubbornHandler) Handle(ctx context.Context, r slog.Record) error {
	<-s.blockedCh
	return nil
}
func (s *stubbornHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return s }
func (s *stubbornHandler) WithGroup(name string) slog.Handler       { return s }
