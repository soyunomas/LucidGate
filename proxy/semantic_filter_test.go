package proxy

import (
	"bufio"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPhraseFilterBlocksCaseInsensitivePhrase(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"Credential Dump", "malware kit"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	stream := filter.NewFilter()

	out, blocked, err := stream.ProcessChunk([]byte("clean text before MALWARE KIT after"))
	if err != nil {
		t.Fatalf("ProcessChunk() error = %v", err)
	}
	if !blocked {
		t.Fatal("blocked = false, want true")
	}
	if string(out) != "clean text before MALWARE KIT" {
		t.Fatalf("out = %q, want truncated at match", string(out))
	}
}

func TestPhraseFilterMatchesAcrossChunkBoundary(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"credential dump"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	stream := filter.NewFilter()

	out, blocked, err := stream.ProcessChunk([]byte("partial creden"))
	if err != nil {
		t.Fatalf("ProcessChunk() error = %v", err)
	}
	if blocked || string(out) != "partial creden" {
		t.Fatalf("first chunk out=%q blocked=%t, want passthrough", string(out), blocked)
	}
	out, blocked, err = stream.ProcessChunk([]byte("tial dump trailing data"))
	if err != nil {
		t.Fatalf("ProcessChunk() error = %v", err)
	}
	if !blocked {
		t.Fatal("blocked = false, want true")
	}
	if string(out) != "tial dump" {
		t.Fatalf("out = %q, want only bytes through match completion", string(out))
	}
}

func TestPhraseFilterAllowsCleanStream(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"credential dump", "malware kit"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	stream := filter.NewFilter()

	chunks := []string{"ordinary creden", "tials and kit", "chen notes"}
	var out strings.Builder
	for _, chunk := range chunks {
		got, blocked, err := stream.ProcessChunk([]byte(chunk))
		if err != nil {
			t.Fatalf("ProcessChunk(%q) error = %v", chunk, err)
		}
		if blocked {
			t.Fatalf("ProcessChunk(%q) blocked clean stream", chunk)
		}
		out.Write(got)
	}
	if out.String() != strings.Join(chunks, "") {
		t.Fatalf("out = %q, want full clean stream", out.String())
	}
}

func TestPhraseFilterBlocksWhenScoreThresholdIsReachedAcrossChunks(t *testing.T) {
	filter, err := NewScoredPhraseFilter(nil, []WeightedPhrase{
		{Phrase: "malware", Weight: 40},
		{Phrase: "credential dump", Weight: 70},
	}, 100)
	if err != nil {
		t.Fatalf("NewScoredPhraseFilter() error = %v", err)
	}
	stream := filter.NewFilter()

	out, blocked, err := stream.ProcessChunk([]byte("first malware then creden"))
	if err != nil {
		t.Fatalf("ProcessChunk(first) error = %v", err)
	}
	if blocked || string(out) != "first malware then creden" {
		t.Fatalf("first chunk out=%q blocked=%t, want score below threshold", string(out), blocked)
	}
	out, blocked, err = stream.ProcessChunk([]byte("tial dump trailing data"))
	if err != nil {
		t.Fatalf("ProcessChunk(second) error = %v", err)
	}
	if !blocked {
		t.Fatal("blocked = false, want score threshold block")
	}
	if string(out) != "tial dump" {
		t.Fatalf("out = %q, want bytes through threshold match", string(out))
	}
}

func TestPhraseFilterDoesNotBlockBelowScoreThreshold(t *testing.T) {
	filter, err := NewScoredPhraseFilter(nil, []WeightedPhrase{
		{Phrase: "malware", Weight: 40},
		{Phrase: "credential dump", Weight: 50},
	}, 100)
	if err != nil {
		t.Fatalf("NewScoredPhraseFilter() error = %v", err)
	}
	stream := filter.NewFilter()

	out, blocked, err := stream.ProcessChunk([]byte("malware and credential dump remain below threshold"))
	if err != nil {
		t.Fatalf("ProcessChunk() error = %v", err)
	}
	if blocked {
		t.Fatalf("blocked = true with out=%q, want score below threshold", string(out))
	}
}

func TestPhraseFilterExceptionSuppressesHardBlock(t *testing.T) {
	filter, err := NewPhraseFilterWithExceptions(
		[]string{"malware kit"},
		nil,
		[]string{"malware research"},
		0,
	)
	if err != nil {
		t.Fatalf("NewPhraseFilterWithExceptions() error = %v", err)
	}
	stream := filter.NewFilter()

	// The exception fires before the hard match, so the stream is excepted
	// and the malware-kit hit must be ignored.
	out, blocked, err := stream.ProcessChunk([]byte("the article is about malware research and includes a malware kit example"))
	if err != nil {
		t.Fatalf("ProcessChunk() error = %v", err)
	}
	if blocked {
		t.Fatalf("blocked = true with out=%q, want exception to suppress hard match", string(out))
	}
}

func TestPhraseFilterExceptionAcrossChunkBoundary(t *testing.T) {
	filter, err := NewPhraseFilterWithExceptions(
		[]string{"credential dump"},
		nil,
		[]string{"security audit"},
		0,
	)
	if err != nil {
		t.Fatalf("NewPhraseFilterWithExceptions() error = %v", err)
	}
	stream := filter.NewFilter()

	if _, blocked, err := stream.ProcessChunk([]byte("a routine security au")); err != nil || blocked {
		t.Fatalf("first chunk blocked=%t err=%v, want passthrough", blocked, err)
	}
	if _, blocked, err := stream.ProcessChunk([]byte("dit covered credential dump scenarios")); err != nil || blocked {
		t.Fatalf("second chunk blocked=%t err=%v, want exception to span chunk", blocked, err)
	}
}

func TestPhraseFilterExceptionAfterHardMatchStillBlocks(t *testing.T) {
	filter, err := NewPhraseFilterWithExceptions(
		[]string{"malware kit"},
		nil,
		[]string{"malware research"},
		0,
	)
	if err != nil {
		t.Fatalf("NewPhraseFilterWithExceptions() error = %v", err)
	}
	stream := filter.NewFilter()

	// Hard match comes BEFORE the exception in the byte stream; we cannot
	// rewind already-sent bytes, so the block must fire as documented.
	out, blocked, err := stream.ProcessChunk([]byte("first hit malware kit then context malware research"))
	if err != nil {
		t.Fatalf("ProcessChunk() error = %v", err)
	}
	if !blocked {
		t.Fatalf("blocked = false out=%q, want hard match to block before exception fires", string(out))
	}
}

func TestPhraseFilterExceptionSuppressesScoreThreshold(t *testing.T) {
	filter, err := NewPhraseFilterWithExceptions(
		nil,
		[]WeightedPhrase{{Phrase: "malware", Weight: 60}, {Phrase: "exploit", Weight: 60}},
		[]string{"academic paper"},
		100,
	)
	if err != nil {
		t.Fatalf("NewPhraseFilterWithExceptions() error = %v", err)
	}
	stream := filter.NewFilter()

	out, blocked, err := stream.ProcessChunk([]byte("this academic paper analyzes malware and exploit techniques"))
	if err != nil {
		t.Fatalf("ProcessChunk() error = %v", err)
	}
	if blocked {
		t.Fatalf("blocked = true out=%q, want exception to suppress score threshold", string(out))
	}
}

func TestPhraseFilterRejectsInvalidScoringConfig(t *testing.T) {
	_, err := NewScoredPhraseFilter(nil, []WeightedPhrase{{Phrase: "malware", Weight: 1}}, 0)
	if err == nil {
		t.Fatal("NewScoredPhraseFilter() error = nil, want missing threshold error")
	}
	_, err = NewScoredPhraseFilter(nil, []WeightedPhrase{{Phrase: "malware", Weight: 0}}, 10)
	if err == nil {
		t.Fatal("NewScoredPhraseFilter() error = nil, want weight validation error")
	}
}

func TestMaskingFilterMasksPhraseAcrossChunks(t *testing.T) {
	filter, err := NewMaskingFilter([]string{"secret token"})
	if err != nil {
		t.Fatalf("NewMaskingFilter() error = %v", err)
	}
	stream := filter.NewFilter()

	first, blocked, err := stream.ProcessChunk([]byte("before secret"))
	if err != nil {
		t.Fatalf("ProcessChunk(first) error = %v", err)
	}
	if blocked {
		t.Fatal("blocked = true, want masking only")
	}
	second, blocked, err := stream.ProcessChunk([]byte(" token after"))
	if err != nil {
		t.Fatalf("ProcessChunk(second) error = %v", err)
	}
	if blocked {
		t.Fatal("blocked = true, want masking only")
	}
	tail, err := stream.(flushingFilter).Flush()
	if err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	got := string(first) + string(second) + string(tail)
	if got != "before ************ after" {
		t.Fatalf("masked stream = %q, want masked phrase", got)
	}
}

func TestPhraseFilterDoesNotShareStreamState(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"malware"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	first := filter.NewFilter()
	second := filter.NewFilter()

	if _, blocked, err := first.ProcessChunk([]byte("mal")); err != nil || blocked {
		t.Fatalf("first partial blocked=%t err=%v, want no block", blocked, err)
	}
	out, blocked, err := second.ProcessChunk([]byte("ware"))
	if err != nil {
		t.Fatalf("second ProcessChunk() error = %v", err)
	}
	if blocked {
		t.Fatalf("second stream blocked with isolated state, out=%q", string(out))
	}
}

func TestWriteResponseStreamingPhraseFilterStopsTextResponse(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"blocked phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	resp := textResponse("before blocked phrase after")
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	got, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != int64(len("before blocked phrase")) {
		t.Fatalf("logged bytes = %d, want truncated response size", got)
	}
	if strings.Contains(out.String(), "after") {
		t.Fatalf("serialized response leaked bytes after blocked phrase: %q", out.String())
	}
}

func TestWriteResponseStreamingPhraseFilterAllowsCleanTextResponse(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"blocked phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	resp := textResponse("clean body")
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	got, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != int64(len("clean body")) {
		t.Fatalf("logged bytes = %d, want clean response size", got)
	}
	if !strings.Contains(out.String(), "clean body") {
		t.Fatalf("serialized response missing clean body: %q", out.String())
	}
}

func TestWriteResponseStreamingScoredPhraseFilterStopsTextResponse(t *testing.T) {
	filter, err := NewScoredPhraseFilter(nil, []WeightedPhrase{
		{Phrase: "malware", Weight: 40},
		{Phrase: "credential dump", Weight: 70},
	}, 100)
	if err != nil {
		t.Fatalf("NewScoredPhraseFilter() error = %v", err)
	}
	resp := textResponse("malware before credential dump after")
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	got, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != int64(len("malware before credential dump")) {
		t.Fatalf("logged bytes = %d, want truncated response size", got)
	}
	if strings.Contains(out.String(), "after") {
		t.Fatalf("serialized response leaked bytes after score block: %q", out.String())
	}
}

func TestWriteResponseStreamingHTMLFilterMatchesVisibleTextAcrossTags(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"credential dump"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	resp := textResponse("safe cred<span>ential</span> dump after")
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err = writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	if strings.Contains(raw, "after") {
		t.Fatalf("serialized response leaked bytes after HTML visible-text block: %q", raw)
	}
	if !strings.Contains(raw, "cred<span>ential</span> dump") {
		t.Fatalf("serialized response missing original HTML through match: %q", raw)
	}
}

func TestWriteResponseStreamingHTMLFilterIgnoresAttributesCommentsAndScriptStyle(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"blocked phrase", "credential dump"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	resp := textResponse(`<div data-x="blocked phrase">clean</div><!-- credential dump --><script>blocked phrase</script><style>.x{content:"credential dump"}</style> done`)
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err = writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	for _, want := range []string{`data-x="blocked phrase"`, "<!-- credential dump -->", "<script>blocked phrase</script>", " done"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("serialized response missing %q after ignored HTML content: %q", want, raw)
		}
	}
}

func TestWriteResponseStreamingPhraseFilterBypassesBinaryResponse(t *testing.T) {
	filter, err := NewPhraseFilter([]string{"blocked phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	resp := binaryResponse("blocked phrase")
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err = writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if !strings.Contains(out.String(), "blocked phrase") {
		t.Fatalf("binary response was not passed through: %q", out.String())
	}
}

func TestWriteResponseStreamingMasksTextResponse(t *testing.T) {
	filter := NewContentFilter(nil, mustMaskingFilter(t, []string{"secret token"}), nil, nil, nil)
	resp := baseResponse("before secret token after")
	resp.Header.Set("Content-Type", "text/plain")
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	got, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if got != int64(len("before ************ after")) {
		t.Fatalf("logged bytes = %d, want masked response size", got)
	}
	parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(out.String())), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(parsed.Body)
	_ = parsed.Body.Close()
	if err != nil {
		t.Fatalf("read parsed body error = %v", err)
	}
	if string(body) != "before ************ after" {
		t.Fatalf("masked body = %q, want masked phrase", string(body))
	}
}

func TestWriteResponseStreamingDoesNotMaskHTMLResponse(t *testing.T) {
	filter := NewContentFilter(nil, mustMaskingFilter(t, []string{"secret token"}), nil, nil, nil)
	resp := textResponse(`<p>secret token</p>`)
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	if !strings.Contains(out.String(), `<p>secret token</p>`) {
		t.Fatalf("HTML response was masked or lost: %q", out.String())
	}
}

func TestWriteResponseStreamingInjectsHTMLBannerBeforeBodyClose(t *testing.T) {
	filter := NewContentFilter(nil, nil, NewHTMLInjectionFilter(`<div>LucidGate</div>`), nil, nil)
	resp := textResponse(`<html><body><p>clean</p></body></html>`)
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	body := readSerializedBody(t, out.String())
	if body != `<html><body><p>clean</p><div>LucidGate</div></body></html>` {
		t.Fatalf("body = %q, want banner before body close", body)
	}
}

func TestHTMLInjectionFilterMatchesBodyCloseAcrossChunks(t *testing.T) {
	filter := NewHTMLInjectionFilter(`<aside>LG</aside>`).NewFilter()
	first, blocked, err := filter.ProcessChunk([]byte(`<html><body>hello</bo`))
	if err != nil {
		t.Fatalf("ProcessChunk(first) error = %v", err)
	}
	if blocked {
		t.Fatal("blocked = true, want injection only")
	}
	second, blocked, err := filter.ProcessChunk([]byte(`dy></html>`))
	if err != nil {
		t.Fatalf("ProcessChunk(second) error = %v", err)
	}
	if blocked {
		t.Fatal("blocked = true, want injection only")
	}
	tail, err := filter.(flushingFilter).Flush()
	if err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	got := string(first) + string(second) + string(tail)
	if got != `<html><body>hello<aside>LG</aside></body></html>` {
		t.Fatalf("injected stream = %q", got)
	}
}

func TestWriteResponseStreamingDoesNotInjectBannerIntoPlainText(t *testing.T) {
	filter := NewContentFilter(nil, nil, NewHTMLInjectionFilter(`<div>LucidGate</div>`), nil, nil)
	resp := baseResponse(`plain </body> text`)
	resp.Header.Set("Content-Type", "text/plain")
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err := writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	body := readSerializedBody(t, out.String())
	if body != `plain </body> text` {
		t.Fatalf("body = %q, want unmodified plain text", body)
	}
}

func TestWriteResponseStreamingDoesNotInjectAfterSemanticBlock(t *testing.T) {
	semantic, err := NewPhraseFilter([]string{"blocked phrase"})
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	filter := NewContentFilter(semantic, nil, NewHTMLInjectionFilter(`<div>LucidGate</div>`), nil, nil)
	resp := textResponse(`<html><body>before blocked phrase after</body></html>`)
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err = writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}
	raw := out.String()
	if strings.Contains(raw, "LucidGate") {
		t.Fatalf("serialized response injected banner after semantic block: %q", raw)
	}
	if strings.Contains(raw, "after") {
		t.Fatalf("serialized response leaked content after semantic block: %q", raw)
	}
}

func readSerializedBody(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := http.ReadResponse(bufio.NewReader(strings.NewReader(raw)), nil)
	if err != nil {
		t.Fatalf("ReadResponse() error = %v", err)
	}
	body, err := io.ReadAll(parsed.Body)
	_ = parsed.Body.Close()
	if err != nil {
		t.Fatalf("read parsed body error = %v", err)
	}
	return string(body)
}

func mustMaskingFilter(t *testing.T, phrases []string) *MaskingFilter {
	t.Helper()
	filter, err := NewMaskingFilter(phrases)
	if err != nil {
		t.Fatalf("NewMaskingFilter() error = %v", err)
	}
	return filter
}

func textResponse(body string) *http.Response {
	resp := baseResponse(body)
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	return resp
}

func binaryResponse(body string) *http.Response {
	resp := baseResponse(body)
	resp.Header.Set("Content-Type", "application/octet-stream")
	return resp
}

func baseResponse(body string) *http.Response {
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
	}
}

func TestPhraseFilterLogPhrases(t *testing.T) {
	logFilter, err := NewPhraseFilterWithExceptions(
		[]string{"log phrase"},
		nil,
		[]string{"except log phrase"},
		0,
	)
	if err != nil {
		t.Fatalf("NewPhraseFilterWithExceptions() error = %v", err)
	}

	filter := NewContentFilter(nil, nil, nil, nil, nil).WithLogSemantic(logFilter)

	// Test 1: clean response matches log phrase -> does NOT block, but logs
	resp := textResponse("this contains a log phrase inside")
	resp.Request = httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	var out strings.Builder
	cap := newBodyCapture(resp.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err = writeResponseStreaming(&out, resp, cap, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}

	// The body should pass through fully (untruncated)
	if !strings.Contains(out.String(), "inside") {
		t.Fatalf("log phrase matching blocked or truncated the stream: %q", out.String())
	}

	// Check LogPhraseMatch in context
	pm, ok := resp.Request.Context().Value(LogPhraseCtxKey{}).(LogPhraseMatch)
	if !ok || !pm.Matched || pm.Suppressed || pm.Value != "log phrase" {
		t.Fatalf("log phrase match context mismatch: ok=%v, pm=%#v", ok, pm)
	}

	// Test 2: response matches exception log phrase -> does NOT block, and sets Suppressed
	respExcept := textResponse("this contains an except log phrase inside")
	respExcept.Request = httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	var outExcept strings.Builder
	capExcept := newBodyCapture(respExcept.Body != nil, RelayOptions{LogBodies: true, MaxCaptureBytes: 1})

	_, _, err = writeResponseStreaming(&outExcept, respExcept, capExcept, filter)
	if err != nil {
		t.Fatalf("writeResponseStreaming() error = %v", err)
	}

	pmExcept, okExcept := respExcept.Request.Context().Value(LogPhraseCtxKey{}).(LogPhraseMatch)
	if !okExcept || !pmExcept.Suppressed || pmExcept.Matched {
		t.Fatalf("log phrase exception context mismatch: ok=%v, pm=%#v", okExcept, pmExcept)
	}
}
