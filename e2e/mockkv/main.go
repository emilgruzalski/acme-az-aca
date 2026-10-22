// Command mockkv stands in for Azure in the end-to-end test: the Key Vault
// certificates and secrets endpoints the app calls, and the managed identity
// token endpoint Container Apps exposes (IDENTITY_ENDPOINT/IDENTITY_HEADER).
//
// Imports are validated the way a real vault would reject them: the PFX must
// decode, its key must match the leaf, and the chain must verify to Pebble's
// root. GET /e2e/state on the identity port reports what was stored, for the
// test script's assertions.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	gopkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	identityHeader = "e2e-identity-header"
	accessToken    = "e2e-access-token"
)

type vault struct {
	host       string
	pebbleRoot string // URL of Pebble's current root
	pebbleCA   string // path to the CA for Pebble's HTTPS API

	mu      sync.Mutex
	certs   map[string]*x509.Certificate
	secrets map[string]string
	imports int
}

func main() {
	v := &vault{
		host:       mustEnv("KV_HOST"),
		pebbleRoot: mustEnv("PEBBLE_ROOT_URL"),
		pebbleCA:   mustEnv("PEBBLE_CA"),
		certs:      map[string]*x509.Certificate{},
		secrets:    map[string]string{},
	}

	tlsCert, err := v.serverCert(mustEnv("CA_OUT"))
	if err != nil {
		log.Fatal(err)
	}

	identity := http.NewServeMux()
	identity.HandleFunc("GET /msi/token", v.token)
	identity.HandleFunc("GET /e2e/state", v.state)
	go func() { log.Fatal(http.ListenAndServe(":8081", identity)) }()

	srv := &http.Server{
		Addr:              ":443",
		Handler:           http.HandlerFunc(v.keyVault),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{tlsCert}},
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("mock key vault on https://%s", v.host)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

// serverCert creates a throwaway CA, writes it to caOut for the app to trust
// via SSL_CERT_FILE, and issues the vault's TLS certificate from it.
func (v *vault) serverCert(caOut string) (tls.Certificate, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mockkv CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(caOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return tls.Certificate{}, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: v.host}, DNSNames: []string{v.host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// token implements the App Service / Container Apps managed identity protocol.
func (v *vault) token(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-IDENTITY-HEADER") != identityHeader {
		http.Error(w, "missing or wrong X-IDENTITY-HEADER", http.StatusUnauthorized)
		return
	}
	resource := r.URL.Query().Get("resource")
	log.Printf("token issued for %s", resource)
	writeJSON(w, http.StatusOK, map[string]string{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"resource":     resource,
		"expires_on":   fmt.Sprint(time.Now().Add(time.Hour).Unix()),
	})
}

func (v *vault) state(w http.ResponseWriter, _ *http.Request) {
	v.mu.Lock()
	defer v.mu.Unlock()
	certs := map[string][]string{}
	for name, c := range v.certs {
		certs[name] = c.DNSNames
	}
	secrets := []string{}
	for name := range v.secrets {
		secrets = append(secrets, name)
	}
	writeJSON(w, http.StatusOK, map[string]any{"imports": v.imports, "certificates": certs, "secrets": secrets})
}

func (v *vault) keyVault(w http.ResponseWriter, r *http.Request) {
	// Key Vault answers unauthenticated requests with a bearer challenge;
	// the SDK reads the token audience from it before sending the real request.
	if r.Header.Get("Authorization") != "Bearer "+accessToken {
		w.Header().Set("WWW-Authenticate",
			`Bearer authorization="https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000", resource="https://vault.azure.net"`)
		writeJSON(w, http.StatusUnauthorized, kvError("Unauthorized", "AKV10000: Request is missing a Bearer or PoP token."))
		return
	}
	log.Printf("%s %s", r.Method, r.URL.Path)

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 2 {
		writeJSON(w, http.StatusBadRequest, kvError("BadParameter", "unsupported path "+r.URL.Path))
		return
	}
	kind, name := parts[0], parts[1]

	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case kind == "certificates" && len(parts) == 2 && r.Method == http.MethodGet:
		cert, ok := v.certs[name]
		if !ok {
			writeJSON(w, http.StatusNotFound, kvError("CertificateNotFound", "A certificate with (name/id) "+name+" was not found in this key vault."))
			return
		}
		writeJSON(w, http.StatusOK, v.certBundle(name, cert))

	case kind == "certificates" && len(parts) == 3 && parts[2] == "import" && r.Method == http.MethodPost:
		var body struct {
			Value string `json:"value"`
			Pwd   string `json:"pwd"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, kvError("BadParameter", err.Error()))
			return
		}
		cert, err := v.validatePFX(body.Value, body.Pwd)
		if err != nil {
			log.Printf("import rejected: %v", err)
			writeJSON(w, http.StatusBadRequest, kvError("BadParameter", err.Error()))
			return
		}
		v.certs[name] = cert
		v.imports++
		log.Printf("import #%d %s: SANs=%v issuer=%q expires=%s",
			v.imports, name, cert.DNSNames, cert.Issuer.CommonName, cert.NotAfter.Format(time.RFC3339))
		writeJSON(w, http.StatusOK, v.certBundle(name, cert))

	case kind == "secrets" && len(parts) == 2 && r.Method == http.MethodGet:
		value, ok := v.secrets[name]
		if !ok {
			writeJSON(w, http.StatusNotFound, kvError("SecretNotFound", "A secret with (name/id) "+name+" was not found in this key vault."))
			return
		}
		writeJSON(w, http.StatusOK, v.secretBundle(name, value))

	case kind == "secrets" && len(parts) == 2 && r.Method == http.MethodPut:
		var body struct {
			Value string `json:"value"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, kvError("BadParameter", err.Error()))
			return
		}
		v.secrets[name] = body.Value
		writeJSON(w, http.StatusOK, v.secretBundle(name, body.Value))

	default:
		writeJSON(w, http.StatusBadRequest, kvError("BadParameter", "unsupported "+r.Method+" "+r.URL.Path))
	}
}

// validatePFX decodes a base64 PFX, checks its key matches the leaf, and
// verifies the bundled chain to Pebble's root.
func (v *vault) validatePFX(b64, password string) (*x509.Certificate, error) {
	pfx, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("value is not base64: %w", err)
	}
	key, leaf, chain, err := gopkcs12.DecodeChain(pfx, password)
	if err != nil {
		return nil, fmt.Errorf("decoding PFX: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("PFX key is not a signing key")
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(leaf.PublicKey) {
		return nil, errors.New("PFX key does not match the leaf certificate")
	}

	roots := x509.NewCertPool()
	rootPEM, err := v.fetchPebbleRoot()
	if err != nil {
		return nil, err
	}
	if !roots.AppendCertsFromPEM(rootPEM) {
		return nil, errors.New("pebble root is not PEM")
	}
	intermediates := x509.NewCertPool()
	for _, c := range chain {
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates}); err != nil {
		return nil, fmt.Errorf("chain (%d CA certs) does not verify to the pebble root: %w", len(chain), err)
	}
	return leaf, nil
}

func (v *vault) fetchPebbleRoot() ([]byte, error) {
	caPEM, err := os.ReadFile(v.pebbleCA)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	resp, err := client.Get(v.pebbleRoot)
	if err != nil {
		return nil, fmt.Errorf("fetching pebble root: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching pebble root: %s", resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func (v *vault) certBundle(name string, cert *x509.Certificate) map[string]any {
	return map[string]any{
		"id":  fmt.Sprintf("https://%s/certificates/%s/1", v.host, name),
		"cer": base64.StdEncoding.EncodeToString(cert.Raw),
		"attributes": map[string]any{
			"enabled": true,
			"nbf":     cert.NotBefore.Unix(),
			"exp":     cert.NotAfter.Unix(),
		},
	}
}

func (v *vault) secretBundle(name, value string) map[string]any {
	return map[string]any{"id": fmt.Sprintf("https://%s/secrets/%s/1", v.host, name), "value": value}
}

func kvError(code, msg string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": msg}}
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}
