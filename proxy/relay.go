package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/flate"
	"github.com/klauspost/compress/gzip"
)

// BodyBytesNotCaptured is returned in log fields when the body length is
// unknown or capture was deliberately skipped.
const BodyBytesNotCaptured int64 = -1

// defaultDumpCaptureBytes caps how much of a streaming/oversized body we mirror
// to disk when DumpDir is set without an explicit MaxCaptureBytes. Keeps memory
// bounded on long SSE / chunked responses (e.g. Gemini streaming output).
const defaultDumpCaptureBytes int64 = 8 << 20 // 8 MiB

const relayBufferSize = 32 * 1024

var relayBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, relayBufferSize)
		return &buf
	},
}

// RelayOptions controls request/response body capture behaviour.
//
//   - LogBodies + MaxCaptureBytes drive the legacy in-memory capture used to
//     report ReqBytes/RespBytes in the structured log line.
//   - DumpDir, when non-empty, also writes the cleartext (decompressed) body
//     of every textual request and response to a single JSONL file inside that
//     directory, intended for offline Blue-Team inspection.
type RelayOptions struct {
	LogBodies       bool
	MaxCaptureBytes int64
	DumpDir         string
	IOTimeout       time.Duration
	Filter          FilterEngine
	RequestFilter   FilterEngine
}

type FilterEngine interface {
	ProcessChunk(in[]byte) (out[]byte, blocked bool, err error)
}

type filterFactory interface {
	NewFilter() FilterEngine
}

type passThroughFilter struct{}

func (passThroughFilter) ProcessChunk(in []byte) ([]byte, bool, error) {
	return in, false, nil
}

func relayHTTP(localConn net.Conn, upstreamConn net.Conn, logger *slog.Logger, opts RelayOptions) error {
	localReader := bufio.NewReader(localConn)
	upstreamReader := bufio.NewReader(upstreamConn)

	for {
		if err := setReadDeadline(localConn, opts.IOTimeout); err != nil {
			return fmt.Errorf("deadline local read: %w", err)
		}
		req, err := http.ReadRequest(localReader)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read local request: %w", err)
		}

		xid := newExchangeID()
		SanitizeHeaders(req)
		normalizeRequestURL(req)

		reqCap := newBodyCapture(req.Body != nil, opts)
		if err := setWriteDeadline(upstreamConn, opts.IOTimeout); err != nil {
			closeRequestBody(req)
			return fmt.Errorf("deadline upstream write: %w", err)
		}
		reqBytes, err := writeRequestStreaming(upstreamConn, req, reqCap, opts.RequestFilter)
		if err != nil {
			closeRequestBody(req)
			return fmt.Errorf("write upstream request: %w", err)
		}
		if opts.DumpDir != "" {
			data, trunc, skipped := reqCap.dumpPayload()
			emitDump(opts.DumpDir, "req", xid, req, nil, data, trunc, skipped, logger)
		}
		closeRequestBody(req)

		if err := setReadDeadline(upstreamConn, opts.IOTimeout); err != nil {
			return fmt.Errorf("deadline upstream read: %w", err)
		}
		resp, err := http.ReadResponse(upstreamReader, req)
		if err != nil {
			return fmt.Errorf("read upstream response: %w", err)
		}
		respCap := newBodyCapture(resp.Body != nil, opts)
		if err := setWriteDeadline(localConn, opts.IOTimeout); err != nil {
			closeResponseBody(resp)
			return fmt.Errorf("deadline local write: %w", err)
		}
		respBytes, err := writeResponseStreaming(localConn, resp, respCap, opts.Filter)
		if err != nil {
			closeResponseBody(resp)
			return fmt.Errorf("write local response: %w", err)
		}
		logExchange(logger, req, resp, reqBytes, respBytes)
		if opts.DumpDir != "" {
			data, trunc, skipped := respCap.dumpPayload()
			emitDump(opts.DumpDir, "resp", xid, req, resp, data, trunc, skipped, logger)
		}

		closeConn := req.Close || resp.Close
		closeResponseBody(resp)
		if closeConn {
			return nil
		}
	}
}

func setReadDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetReadDeadline(time.Now().Add(timeout))
}

func setWriteDeadline(conn net.Conn, timeout time.Duration) error {
	if timeout <= 0 {
		return nil
	}
	return conn.SetWriteDeadline(time.Now().Add(timeout))
}

func SanitizeHeaders(req *http.Request) {
	req.Header.Del("Proxy-Connection")
	req.Header.Del("X-Forwarded-For")
	req.Header.Del("Via")
	req.Header.Del("X-Real-IP")
}

func normalizeRequestURL(req *http.Request) {
	req.RequestURI = ""
	if req.URL == nil {
		return
	}
	if req.URL.IsAbs() {
		req.URL.Scheme = ""
		req.URL.Host = ""
	}
}

func closeRequestBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
}

func closeResponseBody(resp *http.Response) {
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
}

// teeBuffer mirrors a bounded prefix of the bytes written to it. Used to
// capture streaming response bodies without growing memory unbounded.
type teeBuffer struct {
	limit int64
	buf   bytes.Buffer
	full  bool
}

func (t *teeBuffer) Write(p[]byte) (int, error) {
	if t.full {
		return len(p), nil
	}
	remaining := t.limit - int64(t.buf.Len())
	if remaining <= 0 {
		t.full = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		t.buf.Write(p[:remaining])
		t.full = true
	} else {
		t.buf.Write(p)
	}
	return len(p), nil
}

type bodyCapture struct {
	wantLog bool
	tee     *teeBuffer
	skipped string
}

func newBodyCapture(hasBody bool, opts RelayOptions) *bodyCapture {
	c := &bodyCapture{
		wantLog: opts.LogBodies && opts.MaxCaptureBytes != 0,
	}
	if !hasBody {
		return c
	}
	if opts.DumpDir == "" {
		if !c.wantLog {
			c.skipped = "capture disabled"
		}
		return c
	}
	limit := opts.MaxCaptureBytes
	if limit <= 0 {
		limit = defaultDumpCaptureBytes
	}
	c.tee = &teeBuffer{limit: limit}
	return c
}

func (c *bodyCapture) reader(src io.Reader) io.Reader {
	if c == nil || c.tee == nil {
		return src
	}
	return io.TeeReader(src, c.tee)
}

func (c *bodyCapture) logBytes(n int64) int64 {
	if c == nil || !c.wantLog {
		return BodyBytesNotCaptured
	}
	return n
}

func (c *bodyCapture) dumpPayload() ([]byte, bool, string) {
	if c == nil || c.tee == nil {
		if c != nil {
			return nil, false, c.skipped
		}
		return nil, false, ""
	}
	return c.tee.buf.Bytes(), c.tee.full, ""
}

func writeRequestStreaming(w io.Writer, req *http.Request, cap *bodyCapture, filter FilterEngine) (int64, error) {
	if req.Body == nil {
		if err := req.Write(w); err != nil {
			return 0, err
		}
		return 0, nil
	}
	body := io.Reader(req.Body)
	var inspect *InspectReader
	if shouldInspectRequest(req) {
		inspect = newInspectReader(req.Body, reqFilter(filter))
		defer inspect.Close()
		body = inspect
	}
	if err := writeRequestHeader(w, req); err != nil {
		return 0, err
	}
	n, err := writeBodyStreaming(w, body, requestUsesChunked(req), req.Trailer, cap)
	return cap.logBytes(n), err
}

func reqFilter(engine FilterEngine) FilterEngine {
	if content, ok := engine.(*ContentFilter); ok {
		if content.Semantic != nil {
			return content.Semantic.NewFilter()
		}
		return passThroughFilter{}
	}
	if engine != nil {
		if factory, ok := engine.(filterFactory); ok {
			return factory.NewFilter()
		}
		return engine
	}
	return passThroughFilter{}
}

func writeResponseStreaming(w io.Writer, resp *http.Response, cap *bodyCapture, filter FilterEngine) (int64, error) {
	if resp.Body == nil {
		if err := resp.Write(w); err != nil {
			return 0, err
		}
		return 0, nil
	}
	body := io.Reader(resp.Body)
	var transformed io.ReadCloser
	inspectResponse := shouldInspectResponse(resp, filter)
	antivirus := antivirusForResponse(resp, filter)
	if inspectResponse {
		inspected, err := newResponseInspectReader(resp.Body, resp.Header.Get("Content-Encoding"), respFilter(filter, resp.Header.Get("Content-Type"), resp.Request))
		if err != nil {
			return 0, err
		}
		transformed = inspected
		defer transformed.Close()
		body = inspected
		resp.ContentLength = -1
		resp.TransferEncoding =[]string{"chunked"}
		resp.Header.Del("Content-Length")
	}
	if antivirus != nil {
		src, ok := body.(io.ReadCloser)
		if !ok {
			src = readCloser{Reader: body}
		}
		transformed = newAntivirusTricklingReader(requestContext(resp.Request), src, antivirus)
		defer transformed.Close()
		body = transformed
		resp.ContentLength = -1
		resp.TransferEncoding =[]string{"chunked"}
		resp.Header.Del("Content-Length")
	}
	if err := writeResponseHeader(w, resp); err != nil {
		return 0, err
	}
	n, err := writeBodyStreaming(w, body, responseUsesChunked(resp), resp.Trailer, cap)
	return cap.logBytes(n), err
}

func writeResponseStreamingHTTP(w http.ResponseWriter, resp *http.Response, cap *bodyCapture, filter FilterEngine) (int64, error) {
	if resp.Body == nil {
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		return 0, nil
	}
	body := io.Reader(resp.Body)
	var transformed io.ReadCloser
	inspectResponse := shouldInspectResponse(resp, filter)
	antivirus := antivirusForResponse(resp, filter)
	forceChunked := inspectResponse || antivirus != nil
	if inspectResponse {
		inspected, err := newResponseInspectReader(resp.Body, resp.Header.Get("Content-Encoding"), respFilter(filter, resp.Header.Get("Content-Type"), resp.Request))
		if err != nil {
			return 0, err
		}
		transformed = inspected
		defer transformed.Close()
		body = inspected
		resp.ContentLength = -1
		resp.TransferEncoding =[]string{"chunked"}
		resp.Header.Del("Content-Length")
	}
	if antivirus != nil {
		src, ok := body.(io.ReadCloser)
		if !ok {
			src = readCloser{Reader: body}
		}
		transformed = newAntivirusTricklingReader(requestContext(resp.Request), src, antivirus)
		defer transformed.Close()
		body = transformed
		resp.ContentLength = -1
		resp.TransferEncoding =[]string{"chunked"}
		resp.Header.Del("Content-Length")
	}
	copyResponseHeaders(w.Header(), resp.Header)
	if resp.ContentLength >= 0 && !forceChunked {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", resp.ContentLength))
	} else {
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(resp.StatusCode)
	n, err := copyBufferPooled(w, cap.reader(body))
	return cap.logBytes(n), err
}

func copyResponseHeaders(dst, src http.Header) {
	for key := range dst {
		delete(dst, key)
	}
	for key, values := range src {
		if isResponseWriterManagedHeader(key) {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func isResponseWriterManagedHeader(key string) bool {
	switch http.CanonicalHeaderKey(key) {
	case "Content-Length", "Transfer-Encoding":
		return true
	default:
		return false
	}
}

// shouldInjectHTMLBanner decide si una respuesta HTML debe llevar el banner.
// Inyectamos solo en el documento principal: sub-recursos como iframes (ads,
// widgets, embebidos) generarían un banner por iframe y saturan la página.
//
// Heurística (Sec-Fetch-Dest, RFC Fetch Metadata):
//   - "document"  -> top-level navigation: SÍ inyectar.
//   - "iframe", "frame", "embed", "object"... -> NO inyectar.
//   - cabecera ausente (curl, clientes legacy, HTTP/1.0): SÍ inyectar
//     (preserva el comportamiento de pruebas y clientes no-browser).
func shouldInjectHTMLBanner(req *http.Request) bool {
	if req == nil {
		return true
	}
	dest := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Dest")))
	if dest == "" {
		return true
	}
	return dest == "document"
}

func respFilter(engine FilterEngine, contentType string, req *http.Request) FilterEngine {
	if engine == nil {
		return passThroughFilter{}
	}
	content, isContent := engine.(*ContentFilter)
	if !isContent {
		if factory, ok := engine.(filterFactory); ok {
			engine = factory.NewFilter()
		}
		if isHTMLContentType(contentType) && isSemanticPhraseFilter(engine) {
			return newHTMLTextFilter(engine)
		}
		if isScriptOrStyleContentType(contentType) {
			return passThroughFilter{}
		}
		return engine
	}
	var filters[]FilterEngine
	if content.Magic != nil && len(content.Magic.blocked) > 0 {
		filters = append(filters, content.Magic.NewFilter())
	}
	if isFilterMutableResponseType(contentType) {
		if isHTMLContentType(contentType) {
			if content.Semantic != nil {
				filters = append(filters, newHTMLTextFilter(content.Semantic.NewFilter()))
			}
			if content.Substitution != nil && content.Substitution.HasRules() {
				// htmlTextFilter es solo "observador" (descarta la salida del inner)
				// y rompería las sustituciones, así que aplicamos Substitution
				// directamente sobre los bytes crudos del cuerpo.
				filters = append(filters, content.Substitution.NewFilter())
			}
			if content.HTML != nil && len(content.HTML.banner) > 0 && shouldInjectHTMLBanner(req) {
				filters = append(filters, content.HTML.NewFilter())
			}
		} else {
			if content.Semantic != nil {
				filters = append(filters, content.Semantic.NewFilter())
			}
			if content.Masking != nil && content.Masking.maxLen > 0 {
				filters = append(filters, content.Masking.NewFilter())
			}
			if content.Substitution != nil {
				filters = append(filters, content.Substitution.NewFilter())
			}
		}
	}
	return newChainOrPassThrough(filters)
}

func newChainOrPassThrough(filters[]FilterEngine) FilterEngine {
	switch len(filters) {
	case 0:
		return passThroughFilter{}
	case 1:
		return filters[0]
	default:
		return &chainFilter{filters: filters}
	}
}

func isSemanticPhraseFilter(engine FilterEngine) bool {
	_, ok := engine.(*phraseStreamFilter)
	return ok
}

func newResponseInspectReader(src io.ReadCloser, encoding string, engine FilterEngine) (io.ReadCloser, error) {
	encoding = normalizeContentEncoding(encoding)
	if encoding == "" || encoding == "identity" {
		return newInspectReader(src, engine), nil
	}
	return newEncodedInspectReader(src, encoding, engine)
}

type InspectReader struct {
	src     io.Reader
	engine  FilterEngine
	scratch *[]byte
	out[]byte
	blocked bool
	flushed bool
}

func newInspectReader(src io.Reader, engine FilterEngine) *InspectReader {
	bufp := relayBufferPool.Get().(*[]byte)
	return &InspectReader{
		src:     src,
		engine:  engine,
		scratch: bufp,
	}
}

func (r *InspectReader) Read(p[]byte) (int, error) {
	for len(r.out) == 0 {
		if r.blocked {
			return 0, io.EOF
		}
		n, err := r.src.Read(*r.scratch)
		if n > 0 {
			out, blocked, filterErr := r.engine.ProcessChunk((*r.scratch)[:n])
			r.blocked = blocked
			if filterErr != nil {
				return 0, filterErr
			}
			r.out = out
		}
		if err != nil {
			if len(r.out) > 0 && errors.Is(err, io.EOF) {
				break
			}
			if errors.Is(err, io.EOF) {
				if flushErr := r.flushEngine(); flushErr != nil {
					return 0, flushErr
				}
				if len(r.out) > 0 {
					break
				}
			}
			return 0, err
		}
	}
	n := copy(p, r.out)
	r.out = r.out[n:]
	return n, nil
}

func (r *InspectReader) flushEngine() error {
	if r.flushed {
		return nil
	}
	r.flushed = true
	flush, ok := r.engine.(flushingFilter)
	if !ok {
		return nil
	}
	out, err := flush.Flush()
	if err != nil {
		return err
	}
	r.out = out
	return nil
}

func (r *InspectReader) Close() error {
	if r.scratch != nil {
		relayBufferPool.Put(r.scratch)
		r.scratch = nil
	}
	return nil
}

type encodedInspectReader struct {
	pr   *io.PipeReader
	done chan struct{}
	src  io.Closer
	once sync.Once
	err  error
}

func newEncodedInspectReader(src io.ReadCloser, encoding string, engine FilterEngine) (*encodedInspectReader, error) {
	pr, pw := io.Pipe()
	r := &encodedInspectReader{
		pr:   pr,
		done: make(chan struct{}),
		src:  src,
	}
	go r.run(pw, src, encoding, engine)
	return r, nil
}

func (r *encodedInspectReader) run(pw *io.PipeWriter, src io.Reader, encoding string, engine FilterEngine) {
	defer close(r.done)
	decoder, err := newContentDecoder(src, encoding)
	if err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	defer decoder.Close()
	encoder, err := newContentEncoder(pw, encoding)
	if err != nil {
		_ = pw.CloseWithError(err)
		return
	}
	inspect := newInspectReader(decoder, engine)
	_, copyErr := copyBufferPooled(encoder, inspect)
	inspect.Close()
	closeErr := encoder.Close()
	if copyErr != nil {
		_ = pw.CloseWithError(copyErr)
		return
	}
	if closeErr != nil {
		_ = pw.CloseWithError(closeErr)
		return
	}
	_ = pw.Close()
}

func (r *encodedInspectReader) Read(p[]byte) (int, error) {
	return r.pr.Read(p)
}

func (r *encodedInspectReader) Close() error {
	r.once.Do(func() {
		r.err = r.pr.Close()
		if closeErr := r.src.Close(); r.err == nil {
			r.err = closeErr
		}
		<-r.done
	})
	return r.err
}

type readCloser struct {
	io.Reader
	close func() error
}

func (r readCloser) Close() error {
	if r.close == nil {
		return nil
	}
	return r.close()
}

func newContentDecoder(src io.Reader, encoding string) (io.ReadCloser, error) {
	switch encoding {
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(src)
		if err != nil {
			return nil, fmt.Errorf("gzip decoder: %w", err)
		}
		return r, nil
	case "deflate":
		return flate.NewReader(src), nil
	case "br":
		return readCloser{Reader: brotli.NewReader(src)}, nil
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
}

func newContentEncoder(dst io.Writer, encoding string) (io.WriteCloser, error) {
	switch encoding {
	case "gzip", "x-gzip":
		return gzip.NewWriter(dst), nil
	case "deflate":
		return flate.NewWriter(dst, flate.DefaultCompression)
	case "br":
		return brotli.NewWriter(dst), nil
	default:
		return nil, fmt.Errorf("unsupported content encoding %q", encoding)
	}
}

func writeRequestHeader(w io.Writer, req *http.Request) error {
	uri := "/"
	if req.URL != nil {
		uri = req.URL.RequestURI()
		if uri == "" {
			uri = "/"
		}
	}
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\n", req.Method, uri); err != nil {
		return err
	}
	host := req.Host
	if host == "" && req.URL != nil {
		host = req.URL.Host
	}
	if host != "" {
		if _, err := fmt.Fprintf(w, "Host: %s\r\n", host); err != nil {
			return err
		}
	}
	return writeMessageHeaders(w, req.Header, req.ContentLength, requestUsesChunked(req), req.Close)
}

func writeResponseHeader(w io.Writer, resp *http.Response) error {
	status := resp.Status
	if status == "" {
		status = fmt.Sprintf("%d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %s\r\n", status); err != nil {
		return err
	}
	return writeMessageHeaders(w, resp.Header, resp.ContentLength, responseUsesChunked(resp), resp.Close)
}

func writeMessageHeaders(w io.Writer, h http.Header, contentLength int64, chunked bool, closeConn bool) error {
	exclude := map[string]bool{
		"Content-Length":    true,
		"Transfer-Encoding": true,
	}
	if err := h.WriteSubset(w, exclude); err != nil {
		return err
	}
	if contentLength >= 0 && !chunked {
		if _, err := fmt.Fprintf(w, "Content-Length: %d\r\n", contentLength); err != nil {
			return err
		}
	}
	if chunked {
		if _, err := io.WriteString(w, "Transfer-Encoding: chunked\r\n"); err != nil {
			return err
		}
	}
	if closeConn {
		if _, err := io.WriteString(w, "Connection: close\r\n"); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func writeBodyStreaming(w io.Writer, body io.Reader, chunked bool, trailers http.Header, cap *bodyCapture) (int64, error) {
	dst := w
	var chunkWriter io.WriteCloser
	if chunked {
		chunkWriter = httputil.NewChunkedWriter(w)
		dst = chunkWriter
	}
	n, err := copyBufferPooled(dst, cap.reader(body))
	if closeErr := closeChunkedBody(w, chunkWriter, trailers); err == nil {
		err = closeErr
	}
	return n, err
}

func closeChunkedBody(w io.Writer, chunkWriter io.WriteCloser, trailers http.Header) error {
	if chunkWriter == nil {
		return nil
	}
	if err := chunkWriter.Close(); err != nil {
		return err
	}
	if len(trailers) > 0 {
		if err := trailers.Write(w); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, "\r\n")
	return err
}

func requestUsesChunked(req *http.Request) bool {
	if req.ContentLength >= 0 {
		return false
	}
	return hasChunked(req.TransferEncoding)
}

func responseUsesChunked(resp *http.Response) bool {
	if resp.ContentLength >= 0 {
		return false
	}
	return hasChunked(resp.TransferEncoding) || !resp.Close
}

func shouldInspectResponse(resp *http.Response, filter FilterEngine) bool {
	if resp == nil {
		return false
	}
	if !isSupportedInspectEncoding(resp.Header.Get("Content-Encoding")) {
		return false
	}
	if isRangeOrMediaResponse(resp) {
		return false
	}
	if isFilterMutableResponseType(resp.Header.Get("Content-Type")) {
		return true
	}
	return hasMagicFilter(filter)
}

func antivirusForResponse(resp *http.Response, filter FilterEngine) *Antivirus {
	if resp == nil || resp.Body == nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	if isRangeOrMediaResponse(resp) {
		return nil
	}
	if isMutableContentType(resp.Header.Get("Content-Type")) {
		return nil
	}
	content, ok := filter.(*ContentFilter)
	if !ok || content == nil || content.Antivirus == nil || content.Antivirus.Scanner == nil {
		return nil
	}
	return content.Antivirus
}

func isRangeOrMediaResponse(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if resp.StatusCode == http.StatusPartialContent {
		return true
	}
	if resp.Request != nil && resp.Request.Header.Get("Range") != "" {
		return true
	}
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	return strings.HasPrefix(ct, "video/") || strings.HasPrefix(ct, "audio/")
}

func requestContext(req *http.Request) context.Context {
	if req == nil {
		return context.Background()
	}
	return req.Context()
}

func hasMagicFilter(engine FilterEngine) bool {
	content, ok := engine.(*ContentFilter)
	if !ok || content == nil || content.Magic == nil {
		return false
	}
	return len(content.Magic.blocked) > 0
}

func shouldInspectRequest(req *http.Request) bool {
	if req == nil || req.Body == nil {
		return false
	}
	switch req.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return false
	}
	if !isSupportedInspectEncoding(req.Header.Get("Content-Encoding")) {
		return false
	}
	return isMutableRequestContentType(req.Header.Get("Content-Type"))
}

func isMutableRequestContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if strings.HasPrefix(mt, "multipart/") {
		return false
	}
	return isMutableContentType(ct)
}

func isSupportedInspectEncoding(encoding string) bool {
	switch normalizeContentEncoding(encoding) {
	case "", "identity", "gzip", "x-gzip", "deflate", "br":
		return true
	default:
		return false
	}
}

func normalizeContentEncoding(encoding string) string {
	return strings.ToLower(strings.TrimSpace(encoding))
}

func isMutableContentType(ct string) bool {
	if ct == "" {
		return false
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	if strings.Contains(mt, "json") || strings.Contains(mt, "xml") {
		return true
	}
	switch mt {
	case "application/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"application/x-www-form-urlencoded",
		"application/grpc-web-text",
		"application/x-ndjson":
		return true
	}
	return false
}

func isFilterMutableResponseType(ct string) bool {
	if !isMutableContentType(ct) {
		return false
	}
	return !isScriptOrStyleContentType(ct)
}

func isScriptOrStyleContentType(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch mt {
	case "application/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"text/javascript",
		"text/ecmascript",
		"text/css":
		return true
	default:
		return false
	}
}

func isHTMLContentType(ct string) bool {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch mt {
	case "text/html", "application/xhtml+xml":
		return true
	default:
		return false
	}
}

func hasChunked(values[]string) bool {
	for _, value := range values {
		if strings.EqualFold(value, "chunked") {
			return true
		}
	}
	return false
}

func copyBufferPooled(dst io.Writer, src io.Reader) (int64, error) {
	bufp := relayBufferPool.Get().(*[]byte)
	defer relayBufferPool.Put(bufp)
	return io.CopyBuffer(dst, src, *bufp)
}

func logExchange(logger *slog.Logger, req *http.Request, resp *http.Response, reqBytes int64, respBytes int64) {
	if logger == nil {
		return
	}
	path := ""
	if req.URL != nil {
		path = req.URL.RequestURI()
	}
	if path == "" {
		path = "/"
	}
	logger.Info("exchange",
		slog.String("method", req.Method),
		slog.String("host", req.Host),
		slog.String("path", path),
		slog.Int("status", resp.StatusCode),
		slog.Int64("req_bytes", reqBytes),
		slog.Int64("resp_bytes", respBytes),
	)
}

// ---------- Cleartext dumping (Phase 1: Blue-Team capture) ----------

type dumpEntry struct {
	Timestamp   string            `json:"ts"`
	ExchangeID  string            `json:"xid"`
	Direction   string            `json:"dir"` // "req" | "resp"
	Method      string            `json:"method,omitempty"`
	Host        string            `json:"host,omitempty"`
	Path        string            `json:"path,omitempty"`
	Status      int               `json:"status,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Encoding    string            `json:"content_encoding,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Body        string            `json:"body,omitempty"`
	BodyB64     bool              `json:"body_b64,omitempty"`
	BodyBytes   int               `json:"body_bytes"`
	Truncated   bool              `json:"truncated,omitempty"`
	Skipped     string            `json:"skipped,omitempty"`
}

var (
	dumpInitOnce sync.Once
	dumpFile     *os.File
	dumpInitErr  error
	dumpChan     chan[]byte
	exchangeSeq  atomic.Uint64
)

func newExchangeID() string {
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), exchangeSeq.Add(1))
}

func initDumper(dir string) error {
	dumpInitOnce.Do(func() {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			dumpInitErr = err
			return
		}
		path := filepath.Join(dir, fmt.Sprintf("dump_%d.jsonl", time.Now().Unix()))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			dumpInitErr = err
			return
		}
		dumpFile = f
		dumpChan = make(chan[]byte, 4096)
		go asyncDumpLoop()
	})
	return dumpInitErr
}

// emitDump writes one JSONL record describing a request or response. Failures
// are logged but never propagate: an inspection sidecar must not break relay.
func emitDump(dumpDir, direction, xid string, req *http.Request, resp *http.Response, raw[]byte, truncated bool, skipped string, logger *slog.Logger) {
	entry := dumpEntry{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		ExchangeID: xid,
		Direction:  direction,
		Truncated:  truncated,
		Skipped:    skipped,
	}
	if req != nil {
		entry.Method = req.Method
		entry.Host = req.Host
		if req.URL != nil {
			entry.Path = req.URL.RequestURI()
		}
	}
	var headers http.Header
	switch direction {
	case "req":
		if req != nil {
			headers = req.Header
		}
	case "resp":
		if resp != nil {
			entry.Status = resp.StatusCode
			headers = resp.Header
		}
	}
	if headers != nil {
		entry.Headers = flattenHeaders(headers)
		entry.ContentType = headers.Get("Content-Type")
		entry.Encoding = headers.Get("Content-Encoding")
	}

	if len(raw) > 0 {
		if !isTextualContentType(entry.ContentType) {
			if entry.Skipped == "" {
				entry.Skipped = "non-textual content-type"
			}
			entry.BodyBytes = len(raw)
		} else {
			decoded, err := decompressBody(raw, entry.Encoding)
			if err != nil {
				if entry.Skipped == "" {
					entry.Skipped = "decompress error: " + err.Error()
				}
				decoded = raw
			}
			if utf8.Valid(decoded) {
				entry.Body = string(decoded)
			} else {
				entry.Body = base64.StdEncoding.EncodeToString(decoded)
				entry.BodyB64 = true
			}
			entry.BodyBytes = len(decoded)
		}
	}

	writeDumpLine(dumpDir, &entry, logger)
}

func writeDumpLine(dir string, entry *dumpEntry, logger *slog.Logger) {
	if err := initDumper(dir); err != nil {
		if logger != nil {
			logger.Error("dump open failed", slog.Any("error", err))
		}
		return
	}
	line, err := json.Marshal(entry)
	if err != nil {
		if logger != nil {
			logger.Error("dump marshal failed", slog.Any("error", err))
		}
		return
	}
	line = append(line, '\n')
	select {
	case dumpChan <- line:
	default:
		if logger != nil {
			logger.Warn("dump channel full, dropping record", slog.String("xid", entry.ExchangeID))
		}
	}
}

func asyncDumpLoop() {
	bw := bufio.NewWriterSize(dumpFile, 64*1024)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case line := <-dumpChan:
			_, _ = bw.Write(line)
			if bw.Available() < 4096 {
				_ = bw.Flush()
			}
		case <-ticker.C:
			_ = bw.Flush()
		}
	}
}

func flattenHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

// isTextualContentType decides if a payload should be dumped as cleartext.
// Empty Content-Type is treated as textual: many gRPC-Web/JSON RPCs omit it
// or use uncommon variants and we'd rather err on the side of capturing.
//
// Heuristic: anything text/*, anything whose media type contains "json" or
// "xml" (catches application/json+protobuf used by Google AI Studio,
// application/vnd.api+json, application/json, application/xml, …), plus an
// explicit allowlist for known textual containers.
func isTextualContentType(ct string) bool {
	if ct == "" {
		return true
	}
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	if strings.HasPrefix(mt, "text/") {
		return true
	}
	if strings.Contains(mt, "json") || strings.Contains(mt, "xml") {
		return true
	}
	switch mt {
	case "application/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"application/x-www-form-urlencoded",
		"application/grpc-web-text",
		"application/x-ndjson":
		return true
	}
	return false
}

// decompressBody undoes the Content-Encoding wrapper (gzip / x-gzip / deflate /
// br). identity / "" pass through untouched.
func decompressBody(data []byte, encoding string) ([]byte, error) {
	encoding = strings.ToLower(strings.TrimSpace(encoding))
	switch encoding {
	case "", "identity":
		return data, nil
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		defer r.Close()
		return copyDecodedBody(r, "gzip read")
	case "deflate":
		r := flate.NewReader(bytes.NewReader(data))
		defer r.Close()
		return copyDecodedBody(r, "deflate")
	case "br":
		return copyDecodedBody(brotli.NewReader(bytes.NewReader(data)), "brotli")
	}
	return nil, fmt.Errorf("unsupported encoding %q", encoding)
}

func copyDecodedBody(r io.Reader, label string) ([]byte, error) {
	var out bytes.Buffer
	if _, err := copyBufferPooled(&out, r); err != nil {
		return nil, fmt.Errorf("%s: %w", label, err)
	}
	return out.Bytes(), nil
}
