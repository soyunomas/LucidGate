//go:build cgo && !nocgo

package proxy

import (
	"io"

	"github.com/google/brotli/go/cbrotli"
)

func newBrotliReader(src io.Reader) io.ReadCloser {
	return cbrotli.NewReader(src)
}

func newBrotliWriter(dst io.Writer) io.WriteCloser {
	return cbrotli.NewWriter(dst, cbrotli.WriterOptions{Quality: 4})
}
