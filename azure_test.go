package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestParsePrivateKey(t *testing.T) {
	t.Run("RSA PKCS1", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		got, err := parsePrivateKey(x509.MarshalPKCS1PrivateKey(key))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got.(*rsa.PrivateKey); !ok {
			t.Error("expected *rsa.PrivateKey")
		}
	})

	t.Run("RSA PKCS8", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		got, err := parsePrivateKey(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got.(*rsa.PrivateKey); !ok {
			t.Error("expected *rsa.PrivateKey")
		}
	})

	t.Run("ECDSA PKCS8", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalPKCS8PrivateKey(key)
		got, err := parsePrivateKey(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got.(*ecdsa.PrivateKey); !ok {
			t.Error("expected *ecdsa.PrivateKey")
		}
	})

	t.Run("ECDSA SEC1", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		der, _ := x509.MarshalECPrivateKey(key)
		got, err := parsePrivateKey(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := got.(*ecdsa.PrivateKey); !ok {
			t.Error("expected *ecdsa.PrivateKey")
		}
	})

	t.Run("invalid bytes", func(t *testing.T) {
		if _, err := parsePrivateKey([]byte("not a key")); err == nil {
			t.Error("expected error for invalid DER")
		}
	})
}

// selfSignedCert generates a PEM-encoded certificate and private key for testing.
func selfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return
}

func TestConvertToPFX(t *testing.T) {
	certPEM, keyPEM := selfSignedCert(t)

	t.Run("RSA with password", func(t *testing.T) {
		pfx, err := convertToPFX(certPEM, keyPEM, "testpassword")
		if err != nil {
			t.Fatal(err)
		}
		if len(pfx) == 0 {
			t.Error("expected non-empty PFX")
		}
	})

	t.Run("RSA without password", func(t *testing.T) {
		pfx, err := convertToPFX(certPEM, keyPEM, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(pfx) == 0 {
			t.Error("expected non-empty PFX")
		}
	})

	t.Run("ECDSA key", func(t *testing.T) {
		ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		template := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "ec.example.com"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
		}
		certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &ecKey.PublicKey, ecKey)
		ecCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
		ecKeyDER, _ := x509.MarshalECPrivateKey(ecKey)
		ecKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecKeyDER})

		pfx, err := convertToPFX(ecCertPEM, ecKeyPEM, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(pfx) == 0 {
			t.Error("expected non-empty PFX")
		}
	})

	t.Run("invalid key PEM", func(t *testing.T) {
		if _, err := convertToPFX(certPEM, []byte("not pem"), ""); err == nil {
			t.Error("expected error for invalid key PEM")
		}
	})

	t.Run("empty cert PEM", func(t *testing.T) {
		if _, err := convertToPFX([]byte("not pem"), keyPEM, ""); err == nil {
			t.Error("expected error for empty cert PEM")
		}
	})

	t.Run("cert chain", func(t *testing.T) {
		// Simulate a bundle: leaf + CA cert (just reuse same cert as both)
		bundle := append(certPEM, certPEM...)
		pfx, err := convertToPFX(bundle, keyPEM, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(pfx) == 0 {
			t.Error("expected non-empty PFX for chain")
		}
	})
}
