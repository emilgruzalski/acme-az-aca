package main

import (
	"context"
	"crypto"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type acmeUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// challengeProvider implements lego's challenge.Provider interface
// and http.Handler to serve ACME HTTP-01 tokens via the built-in HTTP server.
type challengeProvider struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func (p *challengeProvider) Present(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[token] = keyAuth
	return nil
}

func (p *challengeProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tokens, token)
	return nil
}

func (p *challengeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if token == "" {
		http.NotFound(w, r)
		return
	}
	p.mu.RLock()
	keyAuth, ok := p.tokens[token]
	p.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write([]byte(keyAuth))
}

// newACMEClient loads (or creates) the persisted ACME account key, registers
// with the configured CA, and wires the HTTP-01 challenge provider. ACME
// account registration is idempotent per key, so re-registering with a
// persisted key resolves to the existing account.
func newACMEClient(ctx context.Context, cfg config, secrets *azsecrets.Client) (*lego.Client, *challengeProvider, error) {
	key, err := acmeAccountKey(ctx, secrets, cfg.AccountSecretName)
	if err != nil {
		return nil, nil, fmt.Errorf("acme account key: %w", err)
	}

	user := &acmeUser{Email: cfg.Email, key: key}
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.ACMECAURL

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("acme client: %w", err)
	}

	challenge := &challengeProvider{tokens: make(map[string]string)}
	if err := client.Challenge.SetHTTP01Provider(challenge); err != nil {
		return nil, nil, fmt.Errorf("acme http-01 provider: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, nil, fmt.Errorf("acme registration: %w", err)
	}
	user.Registration = reg
	slog.Info("acme account registered", "email", cfg.Email, "ca", cfg.ACMECAURL)

	return client, challenge, nil
}
