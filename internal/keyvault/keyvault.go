// Package keyvault reads and writes the certificate and the ACME account key
// in Azure Key Vault.
package keyvault

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"

	"github.com/emilgruzalski/acme-az-aca/internal/pfx"
)

func isNotFound(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusNotFound
}

// NeedsRenewal reports whether a new certificate must be obtained:
// none exists yet, the existing one doesn't cover all configured domains, or
// it expires within the renewal window. A missing certificate (404) is the
// normal first-run path; any other Key Vault error aborts the cycle so a
// transient outage doesn't trigger a needless reissue against LE rate limits.
func NeedsRenewal(ctx context.Context, client *azcertificates.Client, certName string, domains []string, renewBeforeDays int) (bool, error) {
	cert, err := client.GetCertificate(ctx, certName, "", nil)
	if err != nil {
		if isNotFound(err) {
			slog.Info("certificate not found in key vault, initial issuance needed", "cert", certName)
			return true, nil
		}
		return false, fmt.Errorf("getting certificate: %w", err)
	}

	if missing := domainsMissingFromCert(cert.CER, domains); len(missing) > 0 {
		slog.Info("certificate does not cover all configured domains, renewal needed", "missing", missing)
		return true, nil
	}

	if cert.Attributes == nil || cert.Attributes.Expires == nil {
		slog.Warn("certificate has no expiration attribute, renewing", "cert", certName)
		return true, nil
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

// domainsMissingFromCert returns the configured domains the certificate does
// not cover. An empty or unparseable DER is treated as "can't tell" so the
// decision falls through to the expiry check.
func domainsMissingFromCert(der []byte, domains []string) []string {
	if len(der) == 0 {
		return nil
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		slog.Warn("parsing key vault certificate failed, skipping domain coverage check", "error", err)
		return nil
	}
	var missing []string
	for _, domain := range domains {
		if cert.VerifyHostname(domain) != nil {
			missing = append(missing, domain)
		}
	}
	return missing
}

// AccountKey returns the ACME account key persisted in Key Vault,
// creating and storing one on first run so restarts reuse the same LE
// account instead of registering a new one (LE limits new registrations).
// Persistence failures fall back to an ephemeral key so missing secret
// permissions never block certificate renewal.
func AccountKey(ctx context.Context, secrets *azsecrets.Client, secretName string) (crypto.PrivateKey, error) {
	if secretName == "" {
		slog.Info("acme account key persistence disabled, using ephemeral account")
		return rsa.GenerateKey(rand.Reader, 2048)
	}

	resp, err := secrets.GetSecret(ctx, secretName, "", nil)
	switch {
	case err == nil:
		if resp.Value == nil {
			return nil, fmt.Errorf("acme account key secret %q has no value", secretName)
		}
		key, err := parseAccountKeyPEM([]byte(*resp.Value))
		if err != nil {
			return nil, fmt.Errorf("parsing acme account key from secret %q (delete the secret to re-register): %w", secretName, err)
		}
		slog.Info("acme account key loaded from key vault", "secret", secretName)
		return key, nil
	case isNotFound(err):
		// First run: generate below and persist.
	default:
		slog.Warn("reading acme account key failed, using ephemeral account", "secret", secretName, "error", err)
		return rsa.GenerateKey(rand.Reader, 2048)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating acme account key: %w", err)
	}
	pemBytes, err := marshalAccountKeyPEM(key)
	if err == nil {
		value := string(pemBytes)
		_, err = secrets.SetSecret(ctx, secretName, azsecrets.SetSecretParameters{Value: &value}, nil)
	}
	if err != nil {
		slog.Warn("persisting acme account key failed, account will be re-registered on restart",
			"secret", secretName, "error", err)
	} else {
		slog.Info("acme account key persisted to key vault", "secret", secretName)
	}
	return key, nil
}

func marshalAccountKeyPEM(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling acme account key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func parseAccountKeyPEM(pemBytes []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	return pfx.ParsePrivateKey(block.Bytes)
}

// ImportCertificate imports a PFX into Key Vault as a new version of certName.
func ImportCertificate(ctx context.Context, client *azcertificates.Client, certName string, pfxData []byte, password string) error {
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
