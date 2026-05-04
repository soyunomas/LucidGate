package pki

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreateCACreatesValidFiles(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateCA() error = %v", err)
	}
	if ca.Certificate == nil || ca.PrivateKey == nil {
		t.Fatal("LoadOrCreateCA() returned incomplete ca")
	}
	if !ca.Certificate.IsCA {
		t.Fatal("certificate is not a ca")
	}
	if got := ca.Certificate.Subject.CommonName; got != rootCommonName {
		t.Fatalf("CommonName = %q, want %q", got, rootCommonName)
	}
	if ca.Certificate.NotAfter.Before(time.Now().AddDate(9, 11, 0)) {
		t.Fatalf("NotAfter = %s, want about 10 years", ca.Certificate.NotAfter)
	}

	if _, err := os.Stat(filepath.Join(dir, CertFilename)); err != nil {
		t.Fatalf("ca cert not written: %v", err)
	}
	keyInfo, err := os.Stat(filepath.Join(dir, KeyFilename))
	if err != nil {
		t.Fatalf("ca key not written: %v", err)
	}
	if got := keyInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("key mode = %o, want 600", got)
	}
}

func TestLoadOrCreateCAReusesExistingCA(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("first LoadOrCreateCA() error = %v", err)
	}
	second, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateCA() error = %v", err)
	}

	if first.Certificate.SerialNumber.Cmp(second.Certificate.SerialNumber) != 0 {
		t.Fatalf("serial changed: first=%s second=%s", first.Certificate.SerialNumber, second.Certificate.SerialNumber)
	}
	if _, err := second.Certificate.Verify(x509.VerifyOptions{
		Roots: rootPool(second.Certificate),
	}); err != nil {
		t.Fatalf("self verification failed: %v", err)
	}
}

func rootPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}
