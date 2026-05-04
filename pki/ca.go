package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	CertFilename = "ca.crt"
	KeyFilename  = "ca.key"

	rootCommonName = "LucidGate Local Root CA"
)

type CertificateAuthority struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.Signer
	CertPEM     []byte
	KeyPEM      []byte
}

func LoadOrCreateCA(dir string) (*CertificateAuthority, error) {
	ca, err := LoadCA(dir)
	if err == nil {
		return ca, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	ca, err = GenerateRootCA(time.Now())
	if err != nil {
		return nil, err
	}
	if err := SaveCA(dir, ca); err != nil {
		return nil, err
	}
	return ca, nil
}

func GenerateRootCA(now time.Time) (*CertificateAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ca key: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   rootCommonName,
			Organization: []string{"LucidGate"},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create ca certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated ca certificate: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal ca key: %w", err)
	}

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: der,
		}),
		KeyPEM: pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyDER,
		}),
	}, nil
}

func SaveCA(dir string, ca *CertificateAuthority) error {
	if ca == nil || len(ca.CertPEM) == 0 || len(ca.KeyPEM) == 0 {
		return errors.New("empty certificate authority")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create ca dir: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, CertFilename), ca.CertPEM, 0o644); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, KeyFilename), ca.KeyPEM, 0o600); err != nil {
		return fmt.Errorf("write ca key: %w", err)
	}
	return nil
}

func LoadCA(dir string) (*CertificateAuthority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, CertFilename))
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, KeyFilename))
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return nil, errors.New("decode ca cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("certificate is not a ca")
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("decode ca key pem")
	}
	key, err := parsePrivateKey(keyBlock)
	if err != nil {
		return nil, err
	}

	return &CertificateAuthority{
		Certificate: cert,
		PrivateKey:  key,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

func parsePrivateKey(block *pem.Block) (crypto.Signer, error) {
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse ec private key: %w", err)
		}
		return key, nil
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse pkcs8 private key: %w", err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, errors.New("pkcs8 key is not a signer")
		}
		return signer, nil
	default:
		return nil, fmt.Errorf("unsupported private key type %q", block.Type)
	}
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}
