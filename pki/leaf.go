package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

const leafValidity = 24 * time.Hour

// sharedLeafKey is a single ECDSA P-256 key reused for every leaf certificate
// produced by GenerateLeafCert. Because LucidGate is a MITM whose leaves never
// leave the proxy, sharing the keypair is safe and saves ~2 ms of keygen per
// new SNI (the dominant cost of GenerateLeafCert before this change). The key
// is lazily generated on first use so that test binaries that never touch
// pki/leaf.go pay nothing.
var (
	sharedLeafKeyOnce sync.Once
	sharedLeafKey     *ecdsa.PrivateKey
	sharedLeafKeyErr  error
	sharedLeafKeyDER  []byte
	sharedLeafKeyPEM  []byte
)

func loadSharedLeafKey() (*ecdsa.PrivateKey, []byte, []byte, error) {
	sharedLeafKeyOnce.Do(func() {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			sharedLeafKeyErr = fmt.Errorf("generate shared leaf key: %w", err)
			return
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			sharedLeafKeyErr = fmt.Errorf("marshal shared leaf key: %w", err)
			return
		}
		sharedLeafKey = key
		sharedLeafKeyDER = der
		sharedLeafKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	})
	return sharedLeafKey, sharedLeafKeyDER, sharedLeafKeyPEM, sharedLeafKeyErr
}

func GenerateLeafCert(hostname string, rootCA *x509.Certificate, rootKey crypto.PrivateKey) (*tls.Certificate, error) {
	host := normalizeHostname(hostname)
	if host == "" {
		return nil, errors.New("empty hostname")
	}
	signer, ok := rootKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("root key is not a signer")
	}
	if rootCA == nil || !rootCA.IsCA {
		return nil, errors.New("root certificate is not a ca")
	}

	key, _, keyPEM, err := loadSharedLeafKey()
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	notAfter := now.Add(leafValidity)
	if notAfter.After(rootCA.NotAfter) {
		notAfter = rootCA.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	der, err := x509.CreateCertificate(rand.Reader, template, rootCA, &key.PublicKey, signer)
	if err != nil {
		return nil, fmt.Errorf("create leaf certificate: %w", err)
	}

	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM,
	)
	if err != nil {
		return nil, fmt.Errorf("load leaf key pair: %w", err)
	}
	cert.Leaf, err = x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse leaf certificate: %w", err)
	}

	return &cert, nil
}

// DefaultLeafCacheSize bounds the LeafCache to avoid unbounded memory growth
// under SNI scans / wildcard CDNs (*.googlevideo.com, *.fbcdn.net) that would
// otherwise fill the map indefinitely. Empirically 4096 entries cover any
// real-world workload while keeping the cache under ~16 MiB.
const DefaultLeafCacheSize = 4096

// LeafCache is a bounded LRU of leaf TLS certificates indexed by hostname.
// Concurrent Get() calls for the same uncached hostname are deduplicated so
// that x509.CreateCertificate runs at most once per host, even under burst.
type LeafCache struct {
	rootCA   *x509.Certificate
	rootKey  crypto.PrivateKey
	mu       sync.Mutex
	lru      *lruCache
	pending  map[string]*pendingCert
	maxEntry int
}

type pendingCert struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

func NewLeafCache(rootCA *x509.Certificate, rootKey crypto.PrivateKey) *LeafCache {
	return NewLeafCacheWithSize(rootCA, rootKey, DefaultLeafCacheSize)
}

func NewLeafCacheWithSize(rootCA *x509.Certificate, rootKey crypto.PrivateKey, maxEntries int) *LeafCache {
	if maxEntries <= 0 {
		maxEntries = DefaultLeafCacheSize
	}
	return &LeafCache{
		rootCA:   rootCA,
		rootKey:  rootKey,
		lru:      newLRUCache(maxEntries),
		pending:  make(map[string]*pendingCert),
		maxEntry: maxEntries,
	}
}

func (c *LeafCache) Get(hostname string) (*tls.Certificate, error) {
	host := normalizeHostname(hostname)
	if host == "" {
		return nil, errors.New("empty hostname")
	}

	c.mu.Lock()
	if cert, ok := c.lru.get(host); ok {
		c.mu.Unlock()
		if leafStillValid(cert) {
			return cert, nil
		}
		// expired or near expiry: drop and regenerate
		c.mu.Lock()
		c.lru.remove(host)
	}
	if pending, ok := c.pending[host]; ok {
		c.mu.Unlock()
		<-pending.done
		return pending.cert, pending.err
	}
	pending := &pendingCert{done: make(chan struct{})}
	c.pending[host] = pending
	c.mu.Unlock()

	cert, err := GenerateLeafCert(host, c.rootCA, c.rootKey)
	pending.cert = cert
	pending.err = err
	close(pending.done)

	c.mu.Lock()
	delete(c.pending, host)
	if err == nil {
		c.lru.put(host, cert)
	}
	c.mu.Unlock()
	return cert, err
}

func (c *LeafCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.len()
}

// leafStillValid reports whether the cached cert has at least one hour of
// validity left. We regenerate aggressively to avoid serving a cert that
// expires mid-handshake on a long-lived client.
func leafStillValid(cert *tls.Certificate) bool {
	if cert == nil || cert.Leaf == nil {
		return false
	}
	return time.Until(cert.Leaf.NotAfter) > time.Hour
}

// lruCache is a small dependency-free LRU. It avoids pulling
// hashicorp/golang-lru just for this single use site (~80 LOC saved in
// dependency surface vs. ~30 LOC here). Not safe for concurrent use; the
// enclosing LeafCache holds the mutex.
type lruCache struct {
	cap  int
	ll   *list
	idx  map[string]*lruNode
}

type lruNode struct {
	prev, next *lruNode
	key        string
	cert       *tls.Certificate
}

type list struct {
	head, tail *lruNode
}

func newLRUCache(cap int) *lruCache {
	return &lruCache{cap: cap, ll: &list{}, idx: make(map[string]*lruNode, cap)}
}

func (c *lruCache) len() int { return len(c.idx) }

func (c *lruCache) get(key string) (*tls.Certificate, bool) {
	n, ok := c.idx[key]
	if !ok {
		return nil, false
	}
	c.ll.moveFront(n)
	return n.cert, true
}

func (c *lruCache) put(key string, cert *tls.Certificate) {
	if n, ok := c.idx[key]; ok {
		n.cert = cert
		c.ll.moveFront(n)
		return
	}
	n := &lruNode{key: key, cert: cert}
	c.ll.pushFront(n)
	c.idx[key] = n
	if len(c.idx) > c.cap {
		victim := c.ll.tail
		if victim != nil {
			c.ll.remove(victim)
			delete(c.idx, victim.key)
		}
	}
}

func (c *lruCache) remove(key string) {
	if n, ok := c.idx[key]; ok {
		c.ll.remove(n)
		delete(c.idx, key)
	}
}

func (l *list) pushFront(n *lruNode) {
	n.prev = nil
	n.next = l.head
	if l.head != nil {
		l.head.prev = n
	}
	l.head = n
	if l.tail == nil {
		l.tail = n
	}
}

func (l *list) moveFront(n *lruNode) {
	if l.head == n {
		return
	}
	l.remove(n)
	l.pushFront(n)
}

func (l *list) remove(n *lruNode) {
	if n.prev != nil {
		n.prev.next = n.next
	} else {
		l.head = n.next
	}
	if n.next != nil {
		n.next.prev = n.prev
	} else {
		l.tail = n.prev
	}
	n.prev, n.next = nil, nil
}

func normalizeHostname(hostname string) string {
	host := strings.TrimSpace(hostname)
	if host == "" {
		return ""
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	return strings.ToLower(host)
}
