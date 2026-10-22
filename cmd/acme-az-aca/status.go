package main

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// cycleStatus tracks the outcome of the last renewal cycle and serves it as
// JSON, so a failing renewal is observable without digging through logs.
type cycleStatus struct {
	mu          sync.Mutex
	lastCheck   time.Time
	lastSuccess time.Time
	lastError   string
}

func (s *cycleStatus) record(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheck = time.Now().UTC()
	if err != nil {
		s.lastError = err.Error()
		return
	}
	s.lastSuccess = s.lastCheck
	s.lastError = ""
}

func (s *cycleStatus) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := struct {
		Healthy     bool       `json:"healthy"`
		LastCheck   *time.Time `json:"last_check,omitempty"`
		LastSuccess *time.Time `json:"last_success,omitempty"`
		LastError   string     `json:"last_error,omitempty"`
	}{Healthy: s.lastError == "", LastError: s.lastError}
	if !s.lastCheck.IsZero() {
		resp.LastCheck = &s.lastCheck
	}
	if !s.lastSuccess.IsZero() {
		resp.LastSuccess = &s.lastSuccess
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
