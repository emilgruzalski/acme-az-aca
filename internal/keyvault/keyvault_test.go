package keyvault

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestDomainsMissingFromCert(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "a.example.com"},
		DNSNames:     []string{"a.example.com", "*.wild.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name    string
		der     []byte
		domains []string
		want    []string
	}{
		{"all covered", der, []string{"a.example.com", "sub.wild.example.com"}, nil},
		{"one missing", der, []string{"a.example.com", "b.example.com"}, []string{"b.example.com"}},
		{"all missing", der, []string{"x.example.com", "y.example.com"}, []string{"x.example.com", "y.example.com"}},
		{"empty der falls through", nil, []string{"a.example.com"}, nil},
		{"garbage der falls through", []byte("not a cert"), []string{"a.example.com"}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := domainsMissingFromCert(tc.der, tc.domains)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestAccountKeyPEMRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, err := marshalAccountKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseAccountKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", parsed)
	}
	if !rsaKey.Equal(key) {
		t.Error("round-tripped key does not match original")
	}

	t.Run("invalid PEM", func(t *testing.T) {
		if _, err := parseAccountKeyPEM([]byte("not pem")); err == nil {
			t.Error("expected error for invalid PEM")
		}
	})
}
