package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

func checkIfRenewalNeeded(ctx context.Context, client *azcertificates.Client, certName string, renewBeforeDays int) (bool, error) {
	cert, err := client.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		return true, fmt.Errorf("getting certificate: %w", err)
	}

	if cert.Attributes == nil || cert.Attributes.Expires == nil {
		return true, fmt.Errorf("certificate attributes or expiration date is missing")
	}

	expiresOn := *cert.Attributes.Expires
	renewalDate := expiresOn.AddDate(0, 0, -renewBeforeDays)

	needsRenewal := time.Now().After(renewalDate)
	if needsRenewal {
		slog.Info("Certificate renewal needed", "expires", expiresOn, "threshold_days", renewBeforeDays)
	} else {
		slog.Info("Certificate valid", "expires", expiresOn, "threshold_days", renewBeforeDays)
	}

	return needsRenewal, nil
}

func convertToPFX(certPEM, keyPEM []byte, password string) ([]byte, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := parsePrivateKey(keyBlock.Bytes)
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

// parsePrivateKey tries PKCS1 (RSA), PKCS8 (RSA/ECDSA), and SEC1 (ECDSA) formats.
func parsePrivateKey(der []byte) (any, error) {
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

func uploadToKeyVault(ctx context.Context, client *azcertificates.Client, certName string, pfxData []byte, password string) error {
	certString := base64.StdEncoding.EncodeToString(pfxData)
	_, err := client.ImportCertificate(ctx, certName, azcertificates.ImportCertificateParameters{
		Base64EncodedCertificate: &certString,
		Password:                 &password,
	}, nil)
	if err != nil {
		return fmt.Errorf("importing certificate: %w", err)
	}
	return nil
}
