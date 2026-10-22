package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCycleStatus(t *testing.T) {
	get := func(t *testing.T, s *cycleStatus) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
		var body map[string]any
		if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body
	}

	s := &cycleStatus{}
	if body := get(t, s); body["healthy"] != true || body["last_check"] != nil {
		t.Errorf("before first cycle: got %v", body)
	}

	s.record(errors.New("key vault unreachable"))
	body := get(t, s)
	if body["healthy"] != false || body["last_error"] != "key vault unreachable" {
		t.Errorf("after failed cycle: got %v", body)
	}
	if body["last_check"] == nil || body["last_success"] != nil {
		t.Errorf("after failed cycle: got %v", body)
	}

	s.record(nil)
	body = get(t, s)
	if body["healthy"] != true || body["last_error"] != nil || body["last_success"] == nil {
		t.Errorf("after successful cycle: got %v", body)
	}
}
