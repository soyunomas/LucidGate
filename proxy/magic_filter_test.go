package proxy

import (
	"bytes"
	"io"
	"net/http"
	"testing"
)

func binaryResponseFromBytes(body []byte) *http.Response {
	resp := &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "application/octet-stream")
	return resp
}

func TestMagicFilterBlocksELFExecutable(t *testing.T) {
	mf := NewMagicFilter([]string{"executable/elf"})
	stream := mf.NewFilter()

	prefix := append([]byte{0x7F, 'E', 'L', 'F'}, bytes.Repeat([]byte{0xAA}, 600)...)
	out, blocked, err := stream.ProcessChunk(prefix)
	if err != nil {
		t.Fatalf("ProcessChunk error = %v", err)
	}
	if !blocked {
		t.Fatalf("expected ELF prefix to be blocked, got out=%q", out)
	}
	if len(out) != 0 {
		t.Fatalf("blocked stream must not emit body bytes, got %d", len(out))
	}

	out, blocked, err = stream.ProcessChunk([]byte("trailing garbage"))
	if err != nil {
		t.Fatalf("post-block ProcessChunk error = %v", err)
	}
	if !blocked || len(out) != 0 {
		t.Fatalf("post-block must remain blocked with empty output, got blocked=%v len=%d", blocked, len(out))
	}
}

func TestMagicFilterBlocksPEExecutable(t *testing.T) {
	mf := NewMagicFilter([]string{"executable/pe"})
	stream := mf.NewFilter()

	body := append([]byte{'M', 'Z'}, bytes.Repeat([]byte{0x90}, magicSniffLen)...)
	out, blocked, err := stream.ProcessChunk(body)
	if err != nil {
		t.Fatalf("ProcessChunk error = %v", err)
	}
	if !blocked || len(out) != 0 {
		t.Fatalf("PE prefix must be blocked: blocked=%v out=%q", blocked, out)
	}
}

func TestMagicFilterBlocksMachOExecutable(t *testing.T) {
	mf := NewMagicFilter([]string{"executable/mach"})
	for label, prefix := range map[string][]byte{
		"fat":  {0xCA, 0xFE, 0xBA, 0xBE},
		"32be": {0xFE, 0xED, 0xFA, 0xCE},
		"64be": {0xFE, 0xED, 0xFA, 0xCF},
		"64le": {0xCF, 0xFA, 0xED, 0xFE},
	} {
		stream := mf.NewFilter()
		body := append(prefix, bytes.Repeat([]byte{0x00}, magicSniffLen)...)
		_, blocked, err := stream.ProcessChunk(body)
		if err != nil {
			t.Fatalf("%s: ProcessChunk error = %v", label, err)
		}
		if !blocked {
			t.Fatalf("%s: expected Mach-O prefix to be blocked", label)
		}
	}
}

func TestMagicFilterBlocksDetectedZip(t *testing.T) {
	mf := NewMagicFilter([]string{"application/zip"})
	stream := mf.NewFilter()

	// Local file header: PK\x03\x04 ...
	body := append([]byte{'P', 'K', 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00}, bytes.Repeat([]byte{0xCC}, 600)...)
	_, blocked, err := stream.ProcessChunk(body)
	if err != nil {
		t.Fatalf("ProcessChunk error = %v", err)
	}
	if !blocked {
		t.Fatalf("expected zip magic to be blocked")
	}
}

func TestMagicFilterPassesPlainText(t *testing.T) {
	mf := NewMagicFilter([]string{"executable/pe", "executable/elf", "application/zip"})
	stream := mf.NewFilter()

	payload := bytes.Repeat([]byte("hello world\n"), 200) // > 512 bytes of ASCII text
	out, blocked, err := stream.ProcessChunk(payload)
	if err != nil {
		t.Fatalf("ProcessChunk error = %v", err)
	}
	if blocked {
		t.Fatalf("plain text must not be blocked")
	}
	if !bytes.Equal(out, payload) {
		t.Fatalf("text passthrough mismatch: got %d bytes, want %d", len(out), len(payload))
	}

	// Subsequent chunks should pass through unchanged.
	tail := []byte("further bytes")
	out, blocked, err = stream.ProcessChunk(tail)
	if err != nil {
		t.Fatalf("ProcessChunk(tail) error = %v", err)
	}
	if blocked || !bytes.Equal(out, tail) {
		t.Fatalf("tail passthrough failed: blocked=%v out=%q", blocked, out)
	}
}

func TestMagicFilterChunkBoundary(t *testing.T) {
	// First chunk too small to decide; second chunk completes the prefix.
	mf := NewMagicFilter([]string{"executable/elf"})
	stream := mf.NewFilter()

	first := []byte{0x7F, 'E'}
	out, blocked, err := stream.ProcessChunk(first)
	if err != nil {
		t.Fatalf("ProcessChunk(first) error = %v", err)
	}
	if blocked {
		t.Fatalf("must not block before having full sniff length")
	}
	if len(out) != 0 {
		t.Fatalf("must not emit before deciding, got %d bytes", len(out))
	}

	second := append([]byte{'L', 'F'}, bytes.Repeat([]byte{0x00}, magicSniffLen)...)
	out, blocked, err = stream.ProcessChunk(second)
	if err != nil {
		t.Fatalf("ProcessChunk(second) error = %v", err)
	}
	if !blocked {
		t.Fatalf("expected ELF prefix to block once full prefix arrives")
	}
	if len(out) != 0 {
		t.Fatalf("blocked output must be empty, got %d", len(out))
	}
}

func TestMagicFilterFlushDecidesShortStream(t *testing.T) {
	mf := NewMagicFilter([]string{"executable/elf"})

	// Short ELF (< 512 B) decided only on Flush.
	stream := mf.NewFilter().(*magicStreamFilter)
	short := append([]byte{0x7F, 'E', 'L', 'F'}, bytes.Repeat([]byte{0xAA}, 100)...)
	out, blocked, err := stream.ProcessChunk(short)
	if err != nil {
		t.Fatalf("ProcessChunk error = %v", err)
	}
	if blocked || len(out) != 0 {
		t.Fatalf("short stream should hold output until Flush, got blocked=%v len=%d", blocked, len(out))
	}
	flushed, err := stream.Flush()
	if err != nil {
		t.Fatalf("Flush error = %v", err)
	}
	if !stream.blocked {
		t.Fatalf("Flush must commit the block decision")
	}
	if len(flushed) != 0 {
		t.Fatalf("Flush of blocked stream must emit nothing, got %d bytes", len(flushed))
	}

	// Short clean stream emits its prefix verbatim on Flush.
	stream = mf.NewFilter().(*magicStreamFilter)
	clean := []byte("short clean text\n")
	out, blocked, err = stream.ProcessChunk(clean)
	if err != nil {
		t.Fatalf("clean ProcessChunk error = %v", err)
	}
	if blocked || len(out) != 0 {
		t.Fatalf("clean short stream should defer emit, got blocked=%v len=%d", blocked, len(out))
	}
	flushed, err = stream.Flush()
	if err != nil {
		t.Fatalf("clean Flush error = %v", err)
	}
	if !bytes.Equal(flushed, clean) {
		t.Fatalf("clean Flush mismatch: got %q want %q", flushed, clean)
	}
}

func TestMagicFilterEmptyConfigDisables(t *testing.T) {
	if mf := NewMagicFilter(nil); mf != nil {
		t.Fatalf("nil list must yield nil filter, got %#v", mf)
	}
	if mf := NewMagicFilter([]string{"   ", ""}); mf != nil {
		t.Fatalf("only-whitespace types must yield nil filter")
	}
}

// Integration: octet-stream with magic active forces inspection and truncates the body.
func TestWriteResponseStreamingBlocksDisguisedExecutable(t *testing.T) {
	magic := NewMagicFilter([]string{"executable/elf"})
	filter := NewContentFilter(nil, nil, nil, magic, nil)

	// Disguised executable served as application/octet-stream with .jpg implied.
	prefix := append([]byte{0x7F, 'E', 'L', 'F'}, bytes.Repeat([]byte{0xAA}, 1024)...)
	resp := binaryResponseFromBytes(prefix)

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	if _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}

	wire := out.String()
	if !bytesContains(wire, "Transfer-Encoding: chunked") {
		t.Fatalf("expected chunked transfer-encoding, got headers: %s", wire)
	}
	if bytesContains(wire, "Content-Length:") {
		t.Fatalf("Content-Length must be stripped when inspecting, got: %s", wire)
	}
	// Body section after the blank line must not contain ELF magic.
	if bytesContains(wire, string([]byte{0x7F, 'E', 'L', 'F'})) {
		t.Fatalf("ELF prefix leaked through to client: %q", wire)
	}
}

// Integration: clean octet-stream payload passes through with magic active.
func TestWriteResponseStreamingPassesCleanBinary(t *testing.T) {
	magic := NewMagicFilter([]string{"executable/elf"})
	filter := NewContentFilter(nil, nil, nil, magic, nil)

	payload := bytes.Repeat([]byte{0x42}, 2048)
	resp := binaryResponseFromBytes(payload)

	var out bytes.Buffer
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})
	if _, err := writeResponseStreaming(&out, resp, cap, filter); err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if !bytes.Contains(out.Bytes(), payload[:32]) {
		t.Fatalf("clean payload prefix should reach client")
	}
}

func bytesContains(haystack string, needle string) bool {
	return bytes.Contains([]byte(haystack), []byte(needle))
}
