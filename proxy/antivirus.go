package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var ErrAntivirusBlocked = errors.New("antivirus blocked response")

type ScanResult struct {
	Infected  bool
	Signature string
}

type AntivirusScanner interface {
	ScanFile(ctx context.Context, path string) (ScanResult, error)
}

type Antivirus struct {
	Scanner         AntivirusScanner
	TempDir         string
	TrickleInterval time.Duration
}

func NewAntivirus(scanner AntivirusScanner, tempDir string, trickleInterval time.Duration) *Antivirus {
	if scanner == nil {
		return nil
	}
	if trickleInterval < 0 {
		trickleInterval = 0
	}
	return &Antivirus{
		Scanner:         scanner,
		TempDir:         tempDir,
		TrickleInterval: trickleInterval,
	}
}

type ClamAVScanner struct {
	Address string
	Timeout time.Duration
}

func NewClamAVScanner(address string, timeout time.Duration) *ClamAVScanner {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &ClamAVScanner{Address: address, Timeout: timeout}
}

func (s *ClamAVScanner) ScanFile(ctx context.Context, path string) (ScanResult, error) {
	dialer := net.Dialer{Timeout: s.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.Address)
	if err != nil {
		return ScanResult{}, fmt.Errorf("clamav dial: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(s.Timeout)); err != nil {
		return ScanResult{}, fmt.Errorf("clamav deadline: %w", err)
	}
	if _, err := io.WriteString(conn, "zINSTREAM\x00"); err != nil {
		return ScanResult{}, fmt.Errorf("clamav command: %w", err)
	}
	f, err := os.Open(path)
	if err != nil {
		return ScanResult{}, fmt.Errorf("open scan file: %w", err)
	}
	defer f.Close()
	bufp := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufp)
	var size [4]byte
	for {
		n, readErr := f.Read(*bufp)
		if n > 0 {
			binary.BigEndian.PutUint32(size[:], uint32(n))
			if _, err := conn.Write(size[:]); err != nil {
				return ScanResult{}, fmt.Errorf("clamav chunk size: %w", err)
			}
			if _, err := conn.Write((*bufp)[:n]); err != nil {
				return ScanResult{}, fmt.Errorf("clamav chunk body: %w", err)
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			return ScanResult{}, fmt.Errorf("read scan file: %w", readErr)
		}
	}
	binary.BigEndian.PutUint32(size[:], 0)
	if _, err := conn.Write(size[:]); err != nil {
		return ScanResult{}, fmt.Errorf("clamav eof: %w", err)
	}
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return ScanResult{}, fmt.Errorf("clamav response: %w", err)
	}
	return parseClamAVResponse(string(resp[:n])), nil
}

func parseClamAVResponse(resp string) ScanResult {
	resp = strings.TrimRight(resp, "\x00\r\n ")
	if strings.HasSuffix(resp, " OK") {
		return ScanResult{}
	}
	const found = " FOUND"
	if strings.HasSuffix(resp, found) {
		name := strings.TrimSuffix(resp, found)
		if i := strings.LastIndex(name, ": "); i >= 0 {
			name = name[i+2:]
		}
		return ScanResult{Infected: true, Signature: name}
	}
	return ScanResult{}
}

type antivirusTricklingReader struct {
	pr     *io.PipeReader
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
	err    error
}

func newAntivirusTricklingReader(ctx context.Context, src io.ReadCloser, av *Antivirus) io.ReadCloser {
	runCtx, cancel := context.WithCancel(ctx)
	pr, pw := io.Pipe()
	r := &antivirusTricklingReader{
		pr:     pr,
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go r.run(runCtx, src, pw, av)
	return r
}

func (r *antivirusTricklingReader) run(ctx context.Context, src io.ReadCloser, pw *io.PipeWriter, av *Antivirus) {
	defer close(r.done)
	defer src.Close()

	dir := av.TempDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	tmp, err := os.CreateTemp(dir, "lucidgate-av-*")
	if err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	path := tmp.Name()
	defer os.Remove(path)
	defer tmp.Close()

	var downloaded atomic.Int64
	downloadDone := make(chan error, 1)
	go downloadToTemp(ctx, src, tmp, &downloaded, downloadDone)

	offset, downloadErr, doneClosed, err := trickleUntilDownloaded(ctx, pw, tmp, &downloaded, downloadDone, av.TrickleInterval)
	if err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	if !doneClosed {
		downloadErr = <-downloadDone
	}
	if downloadErr != nil {
		_ = pw.CloseWithError(downloadErr)
		return
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	result, err := av.Scanner.ScanFile(ctx, path)
	if err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	if result.Infected {
		if result.Signature == "" {
			_ = pw.CloseWithError(ErrAntivirusBlocked)
			return
		}
		_ = pw.CloseWithError(fmt.Errorf("%w: %s", ErrAntivirusBlocked, result.Signature))
		return
	}
	if _, err := tmp.Seek(offset, io.SeekStart); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	if _, err := copyBufferPooled(pw, tmp); err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	_ = pw.Close()
}

func downloadToTemp(ctx context.Context, src io.Reader, dst *os.File, downloaded *atomic.Int64, done chan<- error) {
	bufp := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufp)
	for {
		select {
		case <-ctx.Done():
			done <- ctx.Err()
			return
		default:
		}
		n, err := src.Read(*bufp)
		if n > 0 {
			written, writeErr := dst.Write((*bufp)[:n])
			downloaded.Add(int64(written))
			if writeErr != nil {
				done <- writeErr
				return
			}
			if written != n {
				done <- io.ErrShortWrite
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				done <- nil
				return
			}
			done <- err
			return
		}
	}
}

func trickleUntilDownloaded(ctx context.Context, pw *io.PipeWriter, tmp *os.File, downloaded *atomic.Int64, done <-chan error, interval time.Duration) (int64, error, bool, error) {
	var offset int64
	var downloadErr error
	doneClosed := false
	var one [1]byte
	for {
		if downloaded.Load() <= offset {
			if doneClosed {
				return offset, downloadErr, doneClosed, nil
			}
			select {
			case <-ctx.Done():
				return offset, downloadErr, doneClosed, ctx.Err()
			case downloadErr = <-done:
				doneClosed = true
				if downloaded.Load() <= offset {
					return offset, downloadErr, doneClosed, nil
				}
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		n, err := tmp.ReadAt(one[:], offset)
		if n > 0 {
			if _, writeErr := pw.Write(one[:n]); writeErr != nil {
				return offset, downloadErr, doneClosed, writeErr
			}
			offset += int64(n)
			if doneClosed {
				return offset, downloadErr, doneClosed, nil
			}
			if interval > 0 {
				timer := time.NewTimer(interval)
				select {
				case <-ctx.Done():
					timer.Stop()
					return offset, downloadErr, doneClosed, ctx.Err()
				case downloadErr = <-done:
					doneClosed = true
					timer.Stop()
					return offset, downloadErr, doneClosed, nil
				case <-timer.C:
				}
			}
			continue
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return offset, downloadErr, doneClosed, err
		}
	}
}

func (r *antivirusTricklingReader) Read(p []byte) (int, error) {
	return r.pr.Read(p)
}

func (r *antivirusTricklingReader) Close() error {
	r.once.Do(func() {
		r.cancel()
		r.err = r.pr.Close()
		<-r.done
	})
	return r.err
}

func antivirusTempPattern(dir string) string {
	if dir == "" {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "lucidgate-av-*")
}
