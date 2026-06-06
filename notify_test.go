package main

import "testing"

func TestSendErrorNotification_Disabled(t *testing.T) {
	if err := sendErrorNotification(config{NotifyEnabled: false}, "subject", "body"); err != nil {
		t.Errorf("expected nil for disabled config, got %v", err)
	}
}

func TestSendErrorNotification_IncompleteConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
	}{
		{"missing host", config{NotifyEnabled: true, SMTPUsername: "u", SMTPPassword: "p"}},
		{"missing username", config{NotifyEnabled: true, SMTPHost: "host", SMTPPassword: "p"}},
		{"missing password", config{NotifyEnabled: true, SMTPHost: "host", SMTPUsername: "u"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sendErrorNotification(tc.cfg, "subject", "body"); err == nil {
				t.Error("expected error for incomplete SMTP config")
			}
		})
	}
}
