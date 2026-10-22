// Package acme wraps the lego ACME client and serves HTTP-01 challenges.
package acme

import (
	"crypto"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

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

// ChallengeProvider implements lego's challenge.Provider interface
// and http.Handler to serve ACME HTTP-01 tokens via the built-in HTTP server.
type ChallengeProvider struct {
	mu     sync.RWMutex
	tokens map[string]string
}

func (p *ChallengeProvider) Present(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokens[token] = keyAuth
	return nil
}

func (p *ChallengeProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.tokens, token)
	return nil
}

func (p *ChallengeProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

// NewClient registers accountKey with the ACME CA at caURL and wires the
// HTTP-01 challenge provider, which the caller must serve on port 80. ACME
// account registration is idempotent per key, so re-registering with a
// persisted key resolves to the existing account.
func NewClient(email, caURL string, accountKey crypto.PrivateKey) (*lego.Client, *ChallengeProvider, error) {
	user := &acmeUser{Email: email, key: accountKey}
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = caURL

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("acme client: %w", err)
	}

	challenge := &ChallengeProvider{tokens: make(map[string]string)}
	if err := client.Challenge.SetHTTP01Provider(challenge); err != nil {
		return nil, nil, fmt.Errorf("acme http-01 provider: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, nil, fmt.Errorf("acme registration: %w", err)
	}
	user.Registration = reg
	slog.Info("acme account registered", "email", email, "ca", caURL)

	return client, challenge, nil
}
