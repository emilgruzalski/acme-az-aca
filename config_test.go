package main

import (
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// envconfig validates required fields via env presence; setting required
	// vars upfront keeps each subcase focused on what it's actually exercising.
	setRequired := func(t *testing.T) {
		t.Helper()
		t.Setenv("DOMAINS", "example.com")
		t.Setenv("EMAIL", "test@example.com")
		t.Setenv("AZURE_KEYVAULT_NAME", "myvault")
	}

	t.Run("missing DOMAINS", func(t *testing.T) {
		t.Setenv("DOMAINS", "")
		t.Setenv("EMAIL", "test@example.com")
		t.Setenv("AZURE_KEYVAULT_NAME", "myvault")
		if _, err := loadConfig(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing EMAIL", func(t *testing.T) {
		t.Setenv("DOMAINS", "example.com")
		t.Setenv("EMAIL", "")
		t.Setenv("AZURE_KEYVAULT_NAME", "myvault")
		if _, err := loadConfig(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing AZURE_KEYVAULT_NAME", func(t *testing.T) {
		t.Setenv("DOMAINS", "example.com")
		t.Setenv("EMAIL", "test@example.com")
		t.Setenv("AZURE_KEYVAULT_NAME", "")
		if _, err := loadConfig(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("invalid intervals", func(t *testing.T) {
		cases := []struct{ key, value string }{
			{"CHECK_INTERVAL", "0s"},
			{"CHECK_INTERVAL", "-1h"},
			{"RETRY_INTERVAL", "0s"},
			{"RENEW_BEFORE_DAYS", "-1"},
		}
		for _, tc := range cases {
			t.Run(tc.key+"="+tc.value, func(t *testing.T) {
				setRequired(t)
				t.Setenv(tc.key, tc.value)
				if _, err := loadConfig(); err == nil {
					t.Errorf("expected error for %s=%s", tc.key, tc.value)
				}
			})
		}
	})

	t.Run("defaults", func(t *testing.T) {
		setRequired(t)
		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.CertName != "acme-cert" {
			t.Errorf("CertName default: got %q", cfg.CertName)
		}
		if cfg.CheckInterval != 24*time.Hour {
			t.Errorf("CheckInterval default: got %v", cfg.CheckInterval)
		}
		if cfg.RetryInterval != time.Hour {
			t.Errorf("RetryInterval default: got %v", cfg.RetryInterval)
		}
		if cfg.AccountSecretName != "acme-account-key" {
			t.Errorf("AccountSecretName default: got %q", cfg.AccountSecretName)
		}
		if cfg.RenewBeforeDays != 30 {
			t.Errorf("RenewBeforeDays default: got %d", cfg.RenewBeforeDays)
		}
		if cfg.ACMECAURL != "https://acme-v02.api.letsencrypt.org/directory" {
			t.Errorf("ACMECAURL default: got %q", cfg.ACMECAURL)
		}
		if cfg.SMTPPort != "587" {
			t.Errorf("SMTPPort default: got %q", cfg.SMTPPort)
		}
		if cfg.NotifyEnabled {
			t.Error("NotifyEnabled should default to false")
		}
		if cfg.SMTPFrom != cfg.Email || cfg.SMTPTo != cfg.Email {
			t.Errorf("SMTP From/To should fall back to Email; got %q / %q", cfg.SMTPFrom, cfg.SMTPTo)
		}
	})

	t.Run("overrides", func(t *testing.T) {
		setRequired(t)
		t.Setenv("DOMAINS", "example.com,www.example.com")
		t.Setenv("AZURE_CERT_NAME", "mycert")
		t.Setenv("PFX_PASSWORD", "secret")
		t.Setenv("CHECK_INTERVAL", "12h")
		t.Setenv("RETRY_INTERVAL", "30m")
		t.Setenv("RENEW_BEFORE_DAYS", "14")
		t.Setenv("ACME_ACCOUNT_SECRET_NAME", "my-account-key")
		t.Setenv("ACME_CA_URL", "https://acme-staging-v02.api.letsencrypt.org/directory")
		t.Setenv("SMTP_FROM", "noreply@example.com")
		t.Setenv("SMTP_TO", "ops@example.com")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Domains) != 2 || cfg.Domains[0] != "example.com" || cfg.Domains[1] != "www.example.com" {
			t.Errorf("Domains: %v", cfg.Domains)
		}
		if cfg.CertName != "mycert" {
			t.Errorf("CertName: %q", cfg.CertName)
		}
		if cfg.PFXPassword != "secret" {
			t.Errorf("PFXPassword: %q", cfg.PFXPassword)
		}
		if cfg.CheckInterval != 12*time.Hour {
			t.Errorf("CheckInterval: %v", cfg.CheckInterval)
		}
		if cfg.RetryInterval != 30*time.Minute {
			t.Errorf("RetryInterval: %v", cfg.RetryInterval)
		}
		if cfg.RenewBeforeDays != 14 {
			t.Errorf("RenewBeforeDays: %d", cfg.RenewBeforeDays)
		}
		if cfg.AccountSecretName != "my-account-key" {
			t.Errorf("AccountSecretName: %q", cfg.AccountSecretName)
		}
		if cfg.ACMECAURL != "https://acme-staging-v02.api.letsencrypt.org/directory" {
			t.Errorf("ACMECAURL: %q", cfg.ACMECAURL)
		}
		if cfg.SMTPFrom != "noreply@example.com" || cfg.SMTPTo != "ops@example.com" {
			t.Errorf("SMTP From/To overrides not applied: %q / %q", cfg.SMTPFrom, cfg.SMTPTo)
		}
	})
}
