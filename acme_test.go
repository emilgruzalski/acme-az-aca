package main

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-acme/lego/v4/registration"
)

func TestChallengeProvider_PresentAndCleanUp(t *testing.T) {
	p := &challengeProvider{tokens: make(map[string]string)}

	if err := p.Present("example.com", "token1", "keyauth1"); err != nil {
		t.Fatalf("Present: %v", err)
	}

	p.mu.RLock()
	got, ok := p.tokens["token1"]
	p.mu.RUnlock()
	if !ok || got != "keyauth1" {
		t.Errorf("after Present: got %q (ok=%v), want keyauth1", got, ok)
	}

	if err := p.CleanUp("example.com", "token1", "keyauth1"); err != nil {
		t.Fatalf("CleanUp: %v", err)
	}

	p.mu.RLock()
	_, ok = p.tokens["token1"]
	p.mu.RUnlock()
	if ok {
		t.Error("token should be removed after CleanUp")
	}
}

func TestChallengeProvider_ServeHTTP(t *testing.T) {
	p := &challengeProvider{tokens: make(map[string]string)}
	_ = p.Present("example.com", "mytoken", "mykeyauth")

	tests := []struct {
		path     string
		wantCode int
		wantBody string
	}{
		{"/.well-known/acme-challenge/mytoken", http.StatusOK, "mykeyauth"},
		{"/.well-known/acme-challenge/unknown", http.StatusNotFound, ""},
		{"/.well-known/acme-challenge/", http.StatusNotFound, ""},
	}

	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)

		if w.Code != tc.wantCode {
			t.Errorf("path %s: got status %d, want %d", tc.path, w.Code, tc.wantCode)
		}
		if tc.wantBody != "" && w.Body.String() != tc.wantBody {
			t.Errorf("path %s: got body %q, want %q", tc.path, w.Body.String(), tc.wantBody)
		}
	}
}

func TestAcmeUser(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	reg := &registration.Resource{URI: "https://example.com/acme/reg/1"}
	u := &acmeUser{Email: "test@example.com", Registration: reg, key: key}

	if got := u.GetEmail(); got != "test@example.com" {
		t.Errorf("GetEmail: got %q", got)
	}
	if got := u.GetRegistration(); got != reg {
		t.Error("GetRegistration: mismatch")
	}
	if got := u.GetPrivateKey(); got != key {
		t.Error("GetPrivateKey: mismatch")
	}
}
