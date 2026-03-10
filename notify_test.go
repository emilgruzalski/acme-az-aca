package main

import (
	"testing"
)

func TestLoadEmailConfig(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		t.Setenv("NOTIFY_EMAIL_ENABLED", "")
		cfg := loadEmailConfig()
		if cfg.Enabled {
			t.Error("expected disabled")
		}
	})

	t.Run("enabled with all fields", func(t *testing.T) {
		t.Setenv("NOTIFY_EMAIL_ENABLED", "true")
		t.Setenv("SMTP_HOST", "smtp.example.com")
		t.Setenv("SMTP_PORT", "465")
		t.Setenv("SMTP_USERNAME", "user")
		t.Setenv("SMTP_PASSWORD", "pass")
		t.Setenv("SMTP_FROM", "from@example.com")
		t.Setenv("SMTP_TO", "to@example.com")

		cfg := loadEmailConfig()
		if !cfg.Enabled {
			t.Error("expected enabled")
		}
		if cfg.SMTPHost != "smtp.example.com" {
			t.Errorf("SMTPHost: got %q", cfg.SMTPHost)
		}
		if cfg.SMTPPort != "465" {
			t.Errorf("SMTPPort: got %q", cfg.SMTPPort)
		}
		if cfg.Username != "user" {
			t.Errorf("Username: got %q", cfg.Username)
		}
		if cfg.FromEmail != "from@example.com" {
			t.Errorf("FromEmail: got %q", cfg.FromEmail)
		}
		if cfg.ToEmail != "to@example.com" {
			t.Errorf("ToEmail: got %q", cfg.ToEmail)
		}
	})

	t.Run("SMTP_FROM defaults to EMAIL", func(t *testing.T) {
		t.Setenv("EMAIL", "me@example.com")
		t.Setenv("SMTP_FROM", "")
		cfg := loadEmailConfig()
		if cfg.FromEmail != "me@example.com" {
			t.Errorf("expected FromEmail=me@example.com, got %q", cfg.FromEmail)
		}
	})

	t.Run("SMTP_TO defaults to EMAIL", func(t *testing.T) {
		t.Setenv("EMAIL", "me@example.com")
		t.Setenv("SMTP_TO", "")
		cfg := loadEmailConfig()
		if cfg.ToEmail != "me@example.com" {
			t.Errorf("expected ToEmail=me@example.com, got %q", cfg.ToEmail)
		}
	})

	t.Run("default SMTP port", func(t *testing.T) {
		t.Setenv("SMTP_PORT", "")
		cfg := loadEmailConfig()
		if cfg.SMTPPort != "587" {
			t.Errorf("expected default port 587, got %q", cfg.SMTPPort)
		}
	})
}

func TestSendErrorNotification_Disabled(t *testing.T) {
	err := sendErrorNotification(emailConfig{Enabled: false}, "subject", "body")
	if err != nil {
		t.Errorf("expected nil for disabled config, got %v", err)
	}
}

func TestSendErrorNotification_IncompleteConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  emailConfig
	}{
		{"missing host", emailConfig{Enabled: true, Username: "u", Password: "p"}},
		{"missing username", emailConfig{Enabled: true, SMTPHost: "host", Password: "p"}},
		{"missing password", emailConfig{Enabled: true, SMTPHost: "host", Username: "u"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := sendErrorNotification(tc.cfg, "subject", "body"); err == nil {
				t.Error("expected error for incomplete SMTP config")
			}
		})
	}
}
