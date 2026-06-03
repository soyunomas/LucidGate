package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestRequestSubstitutionLiteralAndRegex(t *testing.T) {
	// Initialize literal and regex rules
	subRules := map[string]string{
		"Madrid": "Barcelona",
		"apple":  "orange",
	}
	regexRules := []RegexSubstitutionRule{
		{
			Pattern:        `user-([0-9]+)`,
			Replace:        `member-$1`,
			MaxWindowBytes: 64,
		},
	}

	filter, err := NewSubstitutionFilterWithRegex(subRules, regexRules)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}
	filter.LengthPreserved = true

	opts := RelayOptions{
		RequestSubstitutionFilter: filter,
		LogBodies:                 true,
		MaxCaptureBytes:           1024,
	}

	// 1. JSON Payload: should substitute literals and regex with captures
	reqJSON := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(`{"city": "Madrid", "fruit": "apple", "id": "user-12345"}`))
	reqJSON.Header.Set("Content-Type", "application/json")
	reqJSON.ContentLength = int64(len(`{"city": "Madrid", "fruit": "apple", "id": "user-12345"}`))

	var out bytes.Buffer
	cap := newBodyCapture(true, opts)

	n, _, err := writeRequestStreaming(&out, reqJSON, cap, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming JSON error = %v", err)
	}

	expectedJSON := `{"city": "Barcel", "fruit": "orang", "id": "member-123"}`
	gotBody := out.String()
	if !strings.Contains(gotBody, expectedJSON) {
		t.Errorf("expected JSON response to contain %q, got: %q", expectedJSON, gotBody)
	}
	if n != int64(len(expectedJSON)) {
		t.Errorf("expected cap logged bytes to be %d, got %d", len(expectedJSON), n)
	}

	// 2. Form URL Encoded: should substitute correctly
	reqForm := httptest.NewRequest(http.MethodPut, "http://localhost/api", strings.NewReader(`city=Madrid&fruit=apple&id=user-999`))
	reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqForm.ContentLength = int64(len(`city=Madrid&fruit=apple&id=user-999`))

	out.Reset()
	cap = newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&out, reqForm, cap, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming Form error = %v", err)
	}

	expectedForm := `city=Barcel&fruit=orang&id=member-9`
	gotForm := out.String()
	if !strings.Contains(gotForm, expectedForm) {
		t.Errorf("expected Form response to contain %q, got: %q", expectedForm, gotForm)
	}
}

func TestRequestSubstitutionHonorsBypassFilters(t *testing.T) {
	filter, err := NewSubstitutionFilterWithRegex(map[string]string{
		"LG_IN_TEST": "LG_IN_MUTX",
	}, nil)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}

	opts := RelayOptions{
		RequestSubstitutionFilter: filter,
		LogBodies:                 true,
		MaxCaptureBytes:           1024,
	}
	body := `{"prompt":"LG_IN_TEST"}`
	req := httptest.NewRequest(http.MethodPost, "https://claude.ai/api/test", strings.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), BypassFiltersCtxKey{}, true))
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = int64(len(body))

	var out bytes.Buffer
	cap := newBodyCapture(true, opts)
	if _, _, err := writeRequestStreaming(&out, req, cap, opts, nil); err != nil {
		t.Fatalf("writeRequestStreaming() error = %v", err)
	}
	got := out.String()
	if !strings.Contains(got, body) {
		t.Fatalf("request body was modified despite bypass filters: %q", got)
	}
	if strings.Contains(got, "LG_IN_MUTX") {
		t.Fatalf("request substitution applied despite bypass filters: %q", got)
	}
}

func TestRequestSubstitutionChunkedFraming(t *testing.T) {
	subRules := map[string]string{
		"Madrid": "Barcelona", // Changes length
	}
	filter, err := NewSubstitutionFilterWithRegex(subRules, nil)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}

	opts := RelayOptions{
		RequestSubstitutionFilter: filter,
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(`Madrid`))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = 6

	var out bytes.Buffer
	cap := newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&out, req, cap, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming error = %v", err)
	}

	serialized := out.String()
	// Check headers: Content-Length must be preserved, Transfer-Encoding: chunked must be absent
	if !strings.Contains(serialized, "Content-Length: 6") {
		t.Error("expected Content-Length header to be preserved")
	}
	if strings.Contains(serialized, "Transfer-Encoding: chunked") {
		t.Error("expected Transfer-Encoding: chunked header to be absent")
	}

	// Verify body is sent as plain text with length-preserved replacement ("Barcel")
	if !strings.Contains(serialized, "Barcel") {
		t.Errorf("expected length-preserved replacement 'Barcel', got: %q", serialized)
	}
}

func TestRequestSubstitutionExclusions(t *testing.T) {
	subRules := map[string]string{
		"Madrid": "Barcelona",
	}
	filter, err := NewSubstitutionFilterWithRegex(subRules, nil)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}

	opts := RelayOptions{
		RequestSubstitutionFilter: filter,
	}

	// 1. Multipart Form Data: should undergo substitution now!
	reqMultipart := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(`Madrid`))
	reqMultipart.Header.Set("Content-Type", "multipart/form-data; boundary=x")
	reqMultipart.ContentLength = 6

	var out bytes.Buffer
	cap := newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&out, reqMultipart, cap, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming Multipart error = %v", err)
	}
	serializedMultipart := out.String()
	if !strings.Contains(serializedMultipart, "Content-Length: 6") {
		t.Error("expected Content-Length header to be preserved for multipart/form-data")
	}
	if strings.Contains(serializedMultipart, "Transfer-Encoding: chunked") {
		t.Error("expected Transfer-Encoding: chunked header to be absent for multipart/form-data")
	}
	if !strings.Contains(serializedMultipart, "Barcel") {
		t.Errorf("expected substituted body with 'Barcel', got: %q", serializedMultipart)
	}

	// 1b. Other Multipart (e.g. multipart/mixed): should bypass substitution
	reqMixed := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(`Madrid`))
	reqMixed.Header.Set("Content-Type", "multipart/mixed; boundary=x")
	reqMixed.ContentLength = 6

	out.Reset()
	cap = newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&out, reqMixed, cap, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming Mixed error = %v", err)
	}
	if !strings.Contains(out.String(), "Content-Length: 6") || !strings.Contains(out.String(), "Madrid") {
		t.Errorf("expected unmodified multipart/mixed body, got: %q", out.String())
	}

	// 2. Compressed Gzip Upload: should bypass substitution
	reqGzip := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(`Madrid`))
	reqGzip.Header.Set("Content-Type", "text/plain")
	reqGzip.Header.Set("Content-Encoding", "gzip")
	reqGzip.ContentLength = 6

	out.Reset()
	cap = newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&out, reqGzip, cap, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming Gzip error = %v", err)
	}
	if !strings.Contains(out.String(), "Content-Length: 6") || !strings.Contains(out.String(), "Madrid") {
		t.Errorf("expected unmodified compressed body, got: %q", out.String())
	}

	// 3. HTTP/1.0 Request: should skip substitution and increment skipped metrics
	reqH10 := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(`Madrid`))
	reqH10.Proto = "HTTP/1.0"
	reqH10.ProtoMajor = 1
	reqH10.ProtoMinor = 0
	reqH10.Header.Set("Content-Type", "text/plain")
	reqH10.ContentLength = 6

	out.Reset()
	cap = newBodyCapture(true, opts)

	// Reset metric
	RequestSubstitutionSkippedTotal.Reset()

	_, _, err = writeRequestStreaming(&out, reqH10, cap, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming HTTP/1.0 error = %v", err)
	}

	if !strings.Contains(out.String(), "Content-Length: 6") || !strings.Contains(out.String(), "Madrid") {
		t.Errorf("expected unmodified HTTP/1.0 body, got: %q", out.String())
	}

	skippedCount := testutil.ToFloat64(RequestSubstitutionSkippedTotal.WithLabelValues("framing"))
	if skippedCount != 1 {
		t.Errorf("expected skipped metric 'framing' to be 1, got %f", skippedCount)
	}
}

func TestRequestSubstitutionMetricsAndLogs(t *testing.T) {
	subRules := map[string]string{
		"Madrid": "Barcelona",
	}
	regexRules := []RegexSubstitutionRule{
		{
			Pattern:        `user-([0-9]+)`,
			Replace:        `member-$1`,
			MaxWindowBytes: 64,
		},
	}

	filter, err := NewSubstitutionFilterWithRegex(subRules, regexRules)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}

	// Reset metrics
	RequestSubstitutionsTotal.Reset()

	var literalMatched, regexMatched bool
	filter.OnMatch = func(kind string, pattern string) {
		RequestSubstitutionsTotal.WithLabelValues(kind).Inc()
		if kind == "literal" && pattern == "Madrid" {
			literalMatched = true
		}
		if kind == "regex" && pattern == "user-([0-9]+)" {
			regexMatched = true
		}
	}

	opts := RelayOptions{
		RequestSubstitutionFilter: filter,
	}

	req := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(`Madrid user-123`))
	req.Header.Set("Content-Type", "text/plain")
	req.ContentLength = int64(len(`Madrid user-123`))

	var out bytes.Buffer
	cap := newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&out, req, cap, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming error = %v", err)
	}

	if !literalMatched {
		t.Error("expected literal search 'Madrid' to trigger OnMatch callback")
	}
	if !regexMatched {
		t.Error("expected regex search 'user-([0-9]+)' to trigger OnMatch callback")
	}

	litCount := testutil.ToFloat64(RequestSubstitutionsTotal.WithLabelValues("literal"))
	regCount := testutil.ToFloat64(RequestSubstitutionsTotal.WithLabelValues("regex"))

	if litCount != 1 {
		t.Errorf("expected RequestSubstitutionsTotal literal metric to be 1, got %f", litCount)
	}
	if regCount != 1 {
		t.Errorf("expected RequestSubstitutionsTotal regex metric to be 1, got %f", regCount)
	}
}

func BenchmarkRequestSubstitutionLargeUpload(b *testing.B) {
	// Create large body payload (1MB) that has NO matches
	largePayload := make([]byte, 1024*1024)
	for i := range largePayload {
		largePayload[i] = 'A'
	}

	// 1. Without rules
	optsNoRules := RelayOptions{}

	b.Run("NoRules", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(largePayload)))
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "http://localhost/api", bytes.NewReader(largePayload))
			req.Header.Set("Content-Type", "text/plain")
			req.ContentLength = int64(len(largePayload))
			cap := newBodyCapture(true, optsNoRules)
			_, _, _ = writeRequestStreaming(io.Discard, req, cap, optsNoRules, nil)
		}
	})

	// 2. With rules (no matches in large payload)
	subRules := map[string]string{
		"Madrid": "Barcelona",
		"apple":  "orange",
	}
	regexRules := []RegexSubstitutionRule{
		{Pattern: `user-([0-9]+)`, Replace: `member-$1`, MaxWindowBytes: 64},
	}
	filter, _ := NewSubstitutionFilterWithRegex(subRules, regexRules)
	optsWithRules := RelayOptions{
		RequestSubstitutionFilter: filter,
	}

	b.Run("WithRulesNoMatches", func(b *testing.B) {
		b.ReportAllocs()
		b.SetBytes(int64(len(largePayload)))
		for i := 0; i < b.N; i++ {
			req := httptest.NewRequest(http.MethodPost, "http://localhost/api", bytes.NewReader(largePayload))
			req.Header.Set("Content-Type", "text/plain")
			req.ContentLength = int64(len(largePayload))
			cap := newBodyCapture(true, optsWithRules)
			_, _, _ = writeRequestStreaming(io.Discard, req, cap, optsWithRules, nil)
		}
	})
}

func TestRequestSubstitutionPastebinExfiltration(t *testing.T) {
	subRules := map[string]string{}
	regexRules := []RegexSubstitutionRule{
		{
			Pattern:        `(?i)(^|[^a-zA-Z0-9]|%[0-9a-fA-F]{2})(Project|Proyecto)(?:\s*|%20|\+)(Phoenix|Titan|Falcon|Omega|NEXUS)\b`,
			Replace:        `$1$2-[REDACTED_INTERNAL_PROJECT]`,
			MaxWindowBytes: 64,
		},
		{
			Pattern:        `ya29\.[a-zA-Z0-9_-]{20,}\b`,
			Replace:        `[REDACTED_GCP_TOKEN]`,
			MaxWindowBytes: 128,
		},
		{
			Pattern:        `\b(s\.|hvs\.)[a-zA-Z0-9_-]{24,}\b`,
			Replace:        `[REDACTED_VAULT_TOKEN]`,
			MaxWindowBytes: 128,
		},
		{
			Pattern:        `sk-proj-[a-zA-Z0-9-]{20,}\b`,
			Replace:        `[REDACTED_OPENAI_KEY]`,
			MaxWindowBytes: 128,
		},
		{
			Pattern:        `(^|[^a-zA-Z0-9]|%[0-9a-fA-F]{2})((?i:password|passwd|secret|api_key|secret_key|auth_token|private_key))((?:\s*|%20|\+)*(?:"|%22|'|%27)?(?::|=|%3[Aa]|%3[Dd])(?:\s*|%20|\+|"|%22)*)((?:[^&%"'\n\r]+|%(?:[1-9A-Fa-f][0-9A-Fa-f]|0[0-9B-CE-Fa-f]|2[013-57-9A-Fa-f]))+)`,
			Replace:        `${1}${2}${3}[REDACTED_SECRET]`,
			MaxWindowBytes: 256,
		},
		{
			Pattern:        `([a-z0-9-]+\.)*internal\.(company\.com|corp)\b`,
			Replace:        `[INTERNAL_DOMAIN_REDACTED]`,
			MaxWindowBytes: 128,
		},
	}

	filter, err := NewSubstitutionFilterWithRegex(subRules, regexRules)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}

	opts := RelayOptions{
		RequestSubstitutionFilter: filter,
	}

	jsonBody := `{"password":"tiny","token":"s.AbcDeF1234567890aBcDeF123","message":"keep-json-valid"}`
	reqJSON := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(jsonBody))
	reqJSON.Header.Set("Content-Type", "application/json")
	reqJSON.ContentLength = int64(len(jsonBody))

	var outJSON bytes.Buffer
	capJSON := newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&outJSON, reqJSON, capJSON, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming JSON syntax error = %v", err)
	}
	jsonParts := strings.SplitN(outJSON.String(), "\r\n\r\n", 2)
	if len(jsonParts) != 2 {
		t.Fatalf("serialized JSON request missing body separator: %q", outJSON.String())
	}
	if !json.Valid([]byte(jsonParts[1])) {
		t.Fatalf("request substitution produced invalid JSON body: %q", jsonParts[1])
	}
	if strings.Contains(jsonParts[1], "tiny") || strings.Contains(jsonParts[1], "s.AbcDeF") {
		t.Fatalf("expected JSON secrets to be redacted, got: %q", jsonParts[1])
	}

	userText := `Asunto: Análisis de urgencia para el despliegue del proyecto NEXUS - Fase 2

Hola equipo, les paso la información necesaria para conectar los entornos de desarrollo con el clúster de producción. Por favor, asegúrense de no compartir esto fuera del canal privado de Slack.

1.  Credenciales de acceso a la DB de Clientes: Host: db-prod-cluster-01.internal.corp User: admin_service_account Password: Secr3t_Passw0rd_2024!_Xy9z

2.  Token de acceso para la API de IA (vía Google Cloud): ya29.a0AfH6SMAAAAA1234567890abcdefghijklmnopqrstuvwxyz-888888888888888888888888

def connect_to_vault():
    vault_url = "https://vault.empresa.com/v1"
    token = "s.AbcDeF1234567890aBcDeF123"
    client = VaultClient(url=vault_url, token=token)
    return client

4.  Notas adicionales: Estamos viendo exfiltraciones en los logs de tráfico, pero creemos que es por la configuración de los headers en el puerto 8080. También, por si sirve de ayuda, aquí tienen la API KEY de nuestro proveedor externo: sk-proj-777-999-ABC-DEF-111-222.

Quedo a la espera de que terminen la migración. Por favor, borren este mensaje una vez configurado todo.`

	// Test 1: Plain text request body (e.g., text/plain)
	reqPlain := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(userText))
	reqPlain.Header.Set("Content-Type", "text/plain")
	reqPlain.ContentLength = int64(len(userText))

	var outPlain bytes.Buffer
	capPlain := newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&outPlain, reqPlain, capPlain, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming Plain text error = %v", err)
	}

	gotPlain := outPlain.String()
	t.Logf("gotPlain: %s", gotPlain)
	if !strings.Contains(gotPlain, "[REDACTED_INTERNAL_PROJECT]") {
		t.Error("expected Project NEXUS to be redacted in plain text")
	}
	if !strings.Contains(gotPlain, "[INTERNAL_DOMAIN_REDACTED]") {
		t.Error("expected db-prod-cluster-01.internal.corp to be redacted in plain text")
	}
	if !strings.Contains(gotPlain, "[REDACTED_GCP_TOKEN]") {
		t.Error("expected Google Cloud Token to be redacted in plain text")
	}
	if !strings.Contains(gotPlain, "[REDACTED_SECRET]") {
		t.Error("expected token and password to be redacted in plain text")
	}
	if !strings.Contains(gotPlain, "[REDACTED_OPENAI_KEY]") {
		t.Error("expected sk-proj... API key to be redacted in plain text")
	}

	// Test 2: Form URL Encoded request body (e.g., application/x-www-form-urlencoded)
	// Let's URL encode the values in a way that simulates form submission
	formBody := "api_option=paste&api_paste_code=" +
		"Asunto%3A+An%C3%A1lisis+de+urgencia+para+el+despliegue+del+proyecto+NEXUS+-+Fase+2%0A%0A" +
		"Password%3A+Secr3t_Passw0rd_2024%21_Xy9z%0A%0A" +
		"ya29.a0AfH6SMAAAAA1234567890abcdefghijklmnopqrstuvwxyz-888888888888888888888888%0A%0A" +
		"token+%3D+%22s.AbcDeF1234567890aBcDeF123%22%0A%0A" +
		"sk-proj-777-999-ABC-DEF-111-222%0A%0A" +
		"db-prod-cluster-01.internal.corp"

	reqForm := httptest.NewRequest(http.MethodPost, "http://localhost/api", strings.NewReader(formBody))
	reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqForm.ContentLength = int64(len(formBody))

	var outForm bytes.Buffer
	capForm := newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&outForm, reqForm, capForm, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming Form error = %v", err)
	}

	gotForm := outForm.String()
	t.Logf("gotForm: %s", gotForm)
	if !strings.Contains(gotForm, "[REDACTED_INTERNAL_PROJECT]") {
		t.Error("expected Project NEXUS to be redacted in form-encoded body")
	}
	if !strings.Contains(gotForm, "[INTERNAL_DOMAIN_REDACTED]") {
		t.Error("expected db-prod-cluster-01.internal.corp to be redacted in form-encoded body")
	}
	if !strings.Contains(gotForm, "[REDACTED_GCP_TOKEN]") {
		t.Error("expected Google Cloud Token to be redacted in form-encoded body")
	}
	if !strings.Contains(gotForm, "[REDACTED_SECRET]") {
		t.Error("expected token and password to be redacted in form-encoded body")
	}
	if !strings.Contains(gotForm, "[REDACTED_OPENAI_KEY]") {
		t.Error("expected sk-proj... API key to be redacted in form-encoded body")
	}

	// Test 3: Multipart Form Data request body (simulating browser Pastebin post)
	var mpBuf bytes.Buffer
	mpWriter := multipart.NewWriter(&mpBuf)

	_ = mpWriter.WriteField("api_option", "paste")
	_ = mpWriter.WriteField("api_paste_code", userText)
	_ = mpWriter.Close()

	reqMultipartPost := httptest.NewRequest(http.MethodPost, "http://localhost/api", &mpBuf)
	reqMultipartPost.Header.Set("Content-Type", mpWriter.FormDataContentType())
	reqMultipartPost.ContentLength = int64(mpBuf.Len())

	var outMultipart bytes.Buffer
	capMultipart := newBodyCapture(true, opts)

	_, _, err = writeRequestStreaming(&outMultipart, reqMultipartPost, capMultipart, opts, nil)
	if err != nil {
		t.Fatalf("writeRequestStreaming Multipart Pastebin error = %v", err)
	}

	gotMultipart := outMultipart.String()
	t.Logf("gotMultipart: %s", gotMultipart)
	if !strings.Contains(gotMultipart, "[REDACTED_INTERNAL_PROJECT]") {
		t.Error("expected Project NEXUS to be redacted in multipart body")
	}
	if !strings.Contains(gotMultipart, "[INTERNAL_DOMAIN_REDACTED]") {
		t.Error("expected db-prod-cluster-01.internal.corp to be redacted in multipart body")
	}
	if !strings.Contains(gotMultipart, "[REDACTED_GCP_TOKEN]") {
		t.Error("expected Google Cloud Token to be redacted in multipart body")
	}
	if !strings.Contains(gotMultipart, "[REDACTED_SECRET]") {
		t.Error("expected token and password to be redacted in multipart body")
	}
	if !strings.Contains(gotMultipart, "[REDACTED_OPENAI_KEY]") {
		t.Error("expected sk-proj... API key to be redacted in multipart body")
	}
}

func TestRequestSubstitutionBlockOnMatch(t *testing.T) {
	subRules := map[string]string{}
	regexRules := []RegexSubstitutionRule{
		{
			Pattern:        `ya29\.[a-zA-Z0-9_-]{20,}\b`,
			Replace:        `[REDACTED_GCP_TOKEN]`,
			MaxWindowBytes: 128,
		},
	}

	filter, err := NewSubstitutionFilterWithRegex(subRules, regexRules)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}

	opts := RelayOptions{
		RequestSubstitutionFilter: filter,
	}

	// Create request with Google AI Studio host and Content-Type
	req := httptest.NewRequest(http.MethodPost, "http://aistudio.google.com/test", strings.NewReader("ya29.a0AfH6SMAAAAA1234567890abcdefghijklmnopqrstuvwxyz"))
	req.Header.Set("Content-Type", "application/json+protobuf")
	req.ContentLength = int64(len("ya29.a0AfH6SMAAAAA1234567890abcdefghijklmnopqrstuvwxyz"))

	var out bytes.Buffer
	cap := newBodyCapture(true, opts)

	_, dec, err := writeRequestStreaming(&out, req, cap, opts, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !dec.Blocked {
		t.Error("expected request to be blocked")
	}
	if dec.MatchType != "exfiltration preventer" {
		t.Errorf("expected MatchType 'exfiltration preventer', got %q", dec.MatchType)
	}
}
