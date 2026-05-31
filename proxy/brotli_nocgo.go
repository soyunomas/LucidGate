//go:build !cgo || nocgo

package proxy

import (
	"io"

	"github.com/andybalholm/brotli"
)

func newBrotliReader(src io.Reader) io.ReadCloser {
	return readCloser{Reader: brotli.NewReader(src)}
}

func newBrotliWriter(dst io.Writer) io.WriteCloser {
	return brotli.NewWriter(dst)
}
