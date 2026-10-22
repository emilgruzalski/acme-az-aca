// Package pfx converts PEM certificates and keys to PKCS#12 (PFX), the format
// Key Vault imports.
package pfx

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

// Encode converts a PEM certificate bundle (leaf first) and its PEM private
// key into a PFX, in memory, protected with password.
func Encode(certPEM, keyPEM []byte, password string) ([]byte, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := ParsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	var certs []*x509.Certificate
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in PEM data")
	}

	leaf := certs[0]
	var caCerts []*x509.Certificate
	if len(certs) > 1 {
		caCerts = certs[1:]
	}

	pfxData, err := gopkcs12.Modern.Encode(privateKey, leaf, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("encoding PFX: %w", err)
	}

	return pfxData, nil
}

// ParsePrivateKey tries PKCS1 (RSA), PKCS8 (RSA/ECDSA), and SEC1 (ECDSA) formats.
func ParsePrivateKey(der []byte) (any, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		}
		return nil, fmt.Errorf("unsupported key type in PKCS8 block")
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unrecognized private key format (tried PKCS1, PKCS8, EC)")
}
