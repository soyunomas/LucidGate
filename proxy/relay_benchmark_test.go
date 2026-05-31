package proxy

import (
	"io"
	"net/http"
	"testing"
)

const tenGiB int64 = 10 << 30

func BenchmarkWriteResponseStreaming10GiB(b *testing.B) {
	for i := 0; i < b.N; i++ {
		resp := &http.Response{
			Status:        "200 OK",
			StatusCode:    http.StatusOK,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          &zeroReadCloser{remaining: tenGiB},
			ContentLength: tenGiB,
		}
		resp.Header.Set("Content-Type", "application/octet-stream")
		cap := newBodyCapture(resp.Body != nil, RelayOptions{
			LogBodies:       true,
			MaxCaptureBytes: 1,
		})

		n, _, err := writeResponseStreaming(io.Discard, resp, cap, nil)
		if err != nil {
			b.Fatalf("writeResponseStreaming() error = %v", err)
		}
		if n != tenGiB {
			b.Fatalf("logged bytes = %d, want %d", n, tenGiB)
		}
	}
}

type zeroReadCloser struct {
	remaining int64
}

func (r *zeroReadCloser) Read(p []byte) (int, error) {
	if r.remaining == 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	r.remaining -= int64(len(p))
	clear(p)
	return len(p), nil
}

func (r *zeroReadCloser) Close() error {
	return nil
}
