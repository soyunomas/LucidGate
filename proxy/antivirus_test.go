package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeAVScanner struct {
	result ScanResult
	err    error
	calls  atomic.Int64
	paths  chan string
}

func (s *fakeAVScanner) ScanFile(_ context.Context, path string) (ScanResult, error) {
	s.calls.Add(1)
	if _, err := os.Stat(path); err != nil {
		return ScanResult{}, err
	}
	if s.paths != nil {
		s.paths <- path
	}
	return s.result, s.err
}

func TestAntivirusTricklingReaderPassesCleanFileAndRemovesTemp(t *testing.T) {
	dir := t.TempDir()
	scanner := &fakeAVScanner{paths: make(chan string, 1)}
	av := NewAntivirus(scanner, dir, time.Millisecond)
	src := "abcdef"

	r := newAntivirusTricklingReader(context.Background(), io.NopCloser(strings.NewReader(src)), av)
	got, err := io.ReadAll(r)
	if closeErr := r.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatalf("ReadAll() error = %v", err)
	}
	if string(got) != src {
		t.Fatalf("body = %q, want %q", string(got), src)
	}
	if scanner.calls.Load() != 1 {
		t.Fatalf("scanner calls = %d, want 1", scanner.calls.Load())
	}
	select {
	case path := <-scanner.paths:
		if !strings.HasPrefix(path, dir+string(os.PathSeparator)) {
			t.Fatalf("scan path = %q, want inside %q", path, dir)
		}
	case <-time.After(time.Second):
		t.Fatal("scanner did not receive path")
	}
	matches, err := filepath.Glob(antivirusTempPattern(dir))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temp files left behind: %v", matches)
	}
}

func TestAntivirusTricklingReaderCutsConnectionOnVirus(t *testing.T) {
	scanner := &fakeAVScanner{result: ScanResult{Infected: true, Signature: "Eicar-Test-Signature"}}
	av := NewAntivirus(scanner, t.TempDir(), time.Millisecond)
	src := "0123456789abcdef"

	r := newAntivirusTricklingReader(context.Background(), io.NopCloser(strings.NewReader(src)), av)
	got, err := io.ReadAll(r)
	_ = r.Close()
	if !errors.Is(err, ErrAntivirusBlocked) {
		t.Fatalf("ReadAll() error = %v, want ErrAntivirusBlocked", err)
	}
	if len(got) == 0 || len(got) >= len(src) {
		t.Fatalf("trickled bytes = %q, want a small prefix only", string(got))
	}
	if scanner.calls.Load() != 1 {
		t.Fatalf("scanner calls = %d, want 1", scanner.calls.Load())
	}
}

func TestWriteResponseStreamingAntivirusScansBinaryAndForcesChunked(t *testing.T) {
	scanner := &fakeAVScanner{}
	av := NewAntivirus(scanner, t.TempDir(), time.Millisecond)
	filter := NewContentFilter(nil, nil, nil, nil, nil, av)
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("binary payload")),
		ContentLength: int64(len("binary payload")),
	}
	resp.Header.Set("Content-Type", "application/octet-stream")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	if _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	if strings.Contains(raw, "Content-Length:") {
		t.Fatalf("serialized response contains Content-Length: %q", raw)
	}
	if !strings.Contains(raw, "Transfer-Encoding: chunked\r\n") {
		t.Fatalf("serialized response missing chunked encoding: %q", raw)
	}
	parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(parsed.Body)
	_ = parsed.Body.Close()
	if err != nil {
		t.Fatalf("read parsed body error = %v", err)
	}
	if string(body) != "binary payload" {
		t.Fatalf("body = %q, want binary payload", string(body))
	}
	if scanner.calls.Load() != 1 {
		t.Fatalf("scanner calls = %d, want 1", scanner.calls.Load())
	}
}

func TestAntivirusBypassesMutableTextResponse(t *testing.T) {
	scanner := &fakeAVScanner{}
	av := NewAntivirus(scanner, t.TempDir(), time.Millisecond)
	filter := NewContentFilter(nil, nil, nil, nil, nil, av)
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("plain text")),
		ContentLength: int64(len("plain text")),
	}
	resp.Header.Set("Content-Type", "text/plain")

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	if _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if scanner.calls.Load() != 0 {
		t.Fatalf("scanner calls = %d, want text bypass", scanner.calls.Load())
	}
}

func TestParseClamAVResponse(t *testing.T) {
	for _, tc := range []struct {
		name string
		resp string
		want ScanResult
	}{
		{name: "clean", resp: "stream: OK\x00", want: ScanResult{}},
		{name: "infected", resp: "stream: Eicar-Test-Signature FOUND\x00", want: ScanResult{Infected: true, Signature: "Eicar-Test-Signature"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseClamAVResponse(tc.resp); got != tc.want {
				t.Fatalf("parseClamAVResponse() = %#v, want %#v", got, tc.want)
			}
		})
	}
}
