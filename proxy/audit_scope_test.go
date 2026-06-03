package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAuditScopeClassifiesRootsAndDependencies(t *testing.T) {
	now := time.Unix(1000, 0)
	scope := NewAuditScope(AuditScopeConfig{
		Enabled:         true,
		Roots:           []string{"example.com", "app.example.net"},
		DependencyTTL:   time.Minute,
		MaxDependencies: 8,
		Now: func() time.Time {
			return now
		},
	})

	rootReq := httptest.NewRequest("GET", "https://example.com/", nil)
	root := scope.Decide(rootReq, "www.example.com")
	if root.Class != AuditClassRoot || !root.MutationAllowed || !root.InspectAllowed || !root.DumpAllowed {
		t.Fatalf("root decision = %#v", root)
	}

	depReq := httptest.NewRequest("GET", "https://cdn.example-cdn.test/app.js", nil)
	depReq.Header.Set("Referer", "https://www.example.com/app")
	dep := scope.Decide(depReq, "cdn.example-cdn.test")
	if dep.Class != AuditClassDependency || dep.Root != "www.example.com" || dep.MutationAllowed || !dep.InspectAllowed || !dep.DumpAllowed {
		t.Fatalf("dependency decision = %#v", dep)
	}

	known := scope.Decide(httptest.NewRequest("GET", "https://cdn.example-cdn.test/app.css", nil), "cdn.example-cdn.test")
	if known.Class != AuditClassDependency || known.Root != "www.example.com" {
		t.Fatalf("known dependency decision = %#v", known)
	}

	none := scope.Decide(httptest.NewRequest("GET", "https://other.test/", nil), "other.test")
	if none.Class != AuditClassNone || none.MutationAllowed || none.InspectAllowed || none.DumpAllowed {
		t.Fatalf("none decision = %#v", none)
	}
}

func TestAuditScopeDependencyExpires(t *testing.T) {
	now := time.Unix(1000, 0)
	scope := NewAuditScope(AuditScopeConfig{
		Enabled:         true,
		Roots:           []string{"target.test"},
		DependencyTTL:   time.Second,
		MaxDependencies: 8,
		Now: func() time.Time {
			return now
		},
	})
	scope.RegisterDependency("target.test", "cdn.test", "test")
	if dec := scope.Decide(nil, "cdn.test"); dec.Class != AuditClassDependency {
		t.Fatalf("dependency before expiry = %#v", dec)
	}
	now = now.Add(2 * time.Second)
	if dec := scope.Decide(nil, "cdn.test"); dec.Class != AuditClassNone {
		t.Fatalf("dependency after expiry = %#v", dec)
	}
}

func TestRelayOptionsForAuditScopeRestrictsMutation(t *testing.T) {
	substitution, err := NewSubstitutionFilterWithRegex(map[string]string{"secret": "redacted"}, nil)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}
	masking, err := NewMaskingFilter([]string{"mask"})
	if err != nil {
		t.Fatalf("NewMaskingFilter() error = %v", err)
	}
	content := NewContentFilter(
		NewPhraseFilterMustForTest(t, []string{"audit"}),
		masking,
		NewHTMLInjectionFilter("<b>banner</b>"),
		NewMagicFilter([]string{"executable/elf"}),
		substitution,
	).WithLogSemantic(NewPhraseFilterMustForTest(t, []string{"log-only"}))

	opts := RelayOptions{
		LogBodies:                 true,
		DumpDir:                   "/tmp/dumps",
		Filter:                    content,
		RequestFilter:             content,
		RequestSubstitutionFilter: substitution,
	}

	dep := opts.ForAuditScope(AuditScopeDecision{Class: AuditClassDependency, InspectAllowed: true, DumpAllowed: true})
	if dep.RequestSubstitutionFilter != nil {
		t.Fatal("dependency scope should disable request substitution")
	}
	depContent, ok := dep.Filter.(*ContentFilter)
	if !ok {
		t.Fatalf("dependency filter type = %T", dep.Filter)
	}
	if depContent.Masking != nil || depContent.HTML != nil || depContent.Substitution != nil {
		t.Fatalf("dependency filter kept mutating filters: %#v", depContent)
	}
	if depContent.Semantic == nil || depContent.LogSemantic == nil || depContent.Magic == nil {
		t.Fatalf("dependency filter dropped audit filters: %#v", depContent)
	}
	if !dep.LogBodies || dep.DumpDir == "" {
		t.Fatalf("dependency should keep audit capture: %#v", dep)
	}

	none := opts.ForAuditScope(AuditScopeDecision{Class: AuditClassNone})
	if none.LogBodies || none.DumpDir != "" || none.RequestSubstitutionFilter != nil {
		t.Fatalf("none scope did not disable capture/mutation: %#v", none)
	}
	if _, ok := none.Filter.(passThroughFilter); !ok {
		t.Fatalf("none scope filter = %T, want passThroughFilter", none.Filter)
	}
}

func TestRelayHTTPAppliesAuditScopeToResponseMutation(t *testing.T) {
	bodyRoot := relayOnceForAuditScope(t, "root.test")
	if bodyRoot != "public" {
		t.Fatalf("root response body = %q, want mutated body", bodyRoot)
	}

	bodyNone := relayOnceForAuditScope(t, "outside.test")
	if bodyNone != "secret" {
		t.Fatalf("none response body = %q, want original body", bodyNone)
	}
}

func NewPhraseFilterMustForTest(t *testing.T, phrases []string) *PhraseFilter {
	t.Helper()
	filter, err := NewPhraseFilter(phrases)
	if err != nil {
		t.Fatalf("NewPhraseFilter() error = %v", err)
	}
	return filter
}

func relayOnceForAuditScope(t *testing.T, host string) string {
	t.Helper()

	localClient, localProxy := net.Pipe()
	upstreamProxy, upstreamServer := net.Pipe()
	defer localClient.Close()
	defer upstreamServer.Close()

	substitution, err := NewSubstitutionFilterWithRegex(map[string]string{"secret": "public"}, nil)
	if err != nil {
		t.Fatalf("NewSubstitutionFilterWithRegex() error = %v", err)
	}
	opts := RelayOptions{
		IOTimeout: time.Second,
		Filter:    NewContentFilter(nil, nil, nil, nil, substitution),
		AuditScope: NewAuditScope(AuditScopeConfig{
			Enabled:         true,
			Roots:           []string{"root.test"},
			DependencyTTL:   time.Minute,
			MaxDependencies: 8,
		}),
	}

	relayErr := make(chan error, 1)
	go func() {
		relayErr <- relayHTTP(localProxy, upstreamProxy, nil, opts)
	}()

	upstreamErr := make(chan error, 1)
	go func() {
		req, err := http.ReadRequest(bufio.NewReader(upstreamServer))
		if err != nil {
			upstreamErr <- err
			return
		}
		closeRequestBody(req)
		_, err = io.WriteString(upstreamServer, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nsecret")
		upstreamErr <- err
	}()

	_, err = io.WriteString(localClient, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	if err != nil {
		t.Fatalf("write local request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(localClient), nil)
	if err != nil {
		t.Fatalf("read local response: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read local body: %v", err)
	}
	_ = localClient.Close()
	if err := <-upstreamErr; err != nil {
		t.Fatalf("upstream error: %v", err)
	}
	if err := <-relayErr; err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
		t.Fatalf("relay error: %v", err)
	}
	return string(data)
}
