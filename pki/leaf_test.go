package pki

import (
	"crypto/x509"
	"net"
	"sync"
	"testing"
	"time"
)

func TestGenerateLeafCertIsSignedByRootCA(t *testing.T) {
	ca, err := GenerateRootCA(testNow())
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}

	cert, err := GenerateLeafCert("GitHub.COM:443", ca.Certificate, ca.PrivateKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert() error = %v", err)
	}
	if cert.Leaf == nil {
		t.Fatal("leaf certificate was not parsed")
	}
	if got := cert.Leaf.DNSNames; len(got) != 1 || got[0] != "github.com" {
		t.Fatalf("DNSNames = %v, want [github.com]", got)
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: "github.com",
		Roots:   rootPool(ca.Certificate),
	}); err != nil {
		t.Fatalf("leaf verification failed: %v", err)
	}
}

func TestGenerateLeafCertUsesIPSAN(t *testing.T) {
	ca, err := GenerateRootCA(testNow())
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}

	cert, err := GenerateLeafCert("127.0.0.1", ca.Certificate, ca.PrivateKey)
	if err != nil {
		t.Fatalf("GenerateLeafCert() error = %v", err)
	}
	if got := cert.Leaf.IPAddresses; len(got) != 1 || !got[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("IPAddresses = %v, want [127.0.0.1]", got)
	}
}

func TestLeafCacheReusesCertificate(t *testing.T) {
	ca, err := GenerateRootCA(testNow())
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	cache := NewLeafCache(ca.Certificate, ca.PrivateKey)

	first, err := cache.Get("github.com:443")
	if err != nil {
		t.Fatalf("first Get() error = %v", err)
	}
	second, err := cache.Get("GITHUB.com")
	if err != nil {
		t.Fatalf("second Get() error = %v", err)
	}

	if first != second {
		t.Fatal("cache did not reuse certificate pointer")
	}
	if got := cache.Len(); got != 1 {
		t.Fatalf("cache Len() = %d, want 1", got)
	}
}

func TestLeafCacheConcurrentGet(t *testing.T) {
	ca, err := GenerateRootCA(testNow())
	if err != nil {
		t.Fatalf("GenerateRootCA() error = %v", err)
	}
	cache := NewLeafCache(ca.Certificate, ca.PrivateKey)

	const workers = 16
	results := make(chan *x509.Certificate, workers)
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			cert, err := cache.Get("example.com:443")
			if err != nil {
				errs <- err
				return
			}
			results <- cert.Leaf
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		t.Fatalf("Get() error = %v", err)
	}
	var first *x509.Certificate
	for cert := range results {
		if first == nil {
			first = cert
			continue
		}
		if cert != first {
			t.Fatal("concurrent Get() returned different certificate instances")
		}
	}
	if got := cache.Len(); got != 1 {
		t.Fatalf("cache Len() = %d, want 1", got)
	}
}

func testNow() time.Time {
	return time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
}
