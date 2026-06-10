package main

import "testing"

func TestNotifyOnError_Disabled(t *testing.T) {
	// Must not attempt delivery (and thus not log a failure) when disabled;
	// an SMTP host that cannot resolve would otherwise error.
	notifyOnError(config{NotifyEnabled: false, SMTPHost: "smtp.invalid"}, "subject", "body")
}

func TestSendErrorNotification_IncompleteConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  config
	}{
		{"missing host", config{SMTPUsername: "u", SMTPPassword: "p"}},
		{"missing username", config{SMTPHost: "host", SMTPPassword: "p"}},
		{"missing password", config{SMTPHost: "host", SMTPUsername: "u"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sendErrorNotification(tc.cfg, "subject", "body"); err == nil {
				t.Error("expected error for incomplete SMTP config")
			}
		})
	}
}
