package main

import (
	"testing"
	"time"
)

func TestEnvWithDefault(t *testing.T) {
	t.Setenv("TEST_ENVKEY", "value")
	if got := envWithDefault("TEST_ENVKEY", "default"); got != "value" {
		t.Errorf("got %q, want %q", got, "value")
	}
	if got := envWithDefault("UNSET_ENVKEY_XYZ", "default"); got != "default" {
		t.Errorf("got %q, want %q", got, "default")
	}
}

func TestEnvDuration(t *testing.T) {
	t.Setenv("TEST_DUR", "2h")
	if got := envDuration("TEST_DUR", time.Hour); got != 2*time.Hour {
		t.Errorf("got %v, want 2h", got)
	}

	t.Setenv("TEST_DUR_BAD", "notaduration")
	if got := envDuration("TEST_DUR_BAD", time.Hour); got != time.Hour {
		t.Errorf("got %v, want 1h (default)", got)
	}

	if got := envDuration("UNSET_DUR_XYZ", time.Minute); got != time.Minute {
		t.Errorf("got %v, want 1m (default)", got)
	}
}

func TestEnvInt(t *testing.T) {
	t.Setenv("TEST_INT", "42")
	if got := envInt("TEST_INT", 0); got != 42 {
		t.Errorf("got %d, want 42", got)
	}

	t.Setenv("TEST_INT_BAD", "notanint")
	if got := envInt("TEST_INT_BAD", 7); got != 7 {
		t.Errorf("got %d, want 7 (default)", got)
	}

	if got := envInt("UNSET_INT_XYZ", 5); got != 5 {
		t.Errorf("got %d, want 5 (default)", got)
	}
}

func TestLoadConfig(t *testing.T) {
	base := func(t *testing.T) {
		t.Helper()
		t.Setenv("DOMAINS", "example.com")
		t.Setenv("EMAIL", "test@example.com")
		t.Setenv("AZURE_KEYVAULT_NAME", "myvault")
		t.Setenv("AZURE_CERT_NAME", "mycert")
	}

	t.Run("missing DOMAINS", func(t *testing.T) {
		t.Setenv("DOMAINS", "")
		if _, err := loadConfig(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing EMAIL", func(t *testing.T) {
		base(t)
		t.Setenv("EMAIL", "")
		if _, err := loadConfig(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing AZURE_KEYVAULT_NAME", func(t *testing.T) {
		base(t)
		t.Setenv("AZURE_KEYVAULT_NAME", "")
		if _, err := loadConfig(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("missing AZURE_CERT_NAME", func(t *testing.T) {
		base(t)
		t.Setenv("AZURE_CERT_NAME", "")
		if _, err := loadConfig(); err == nil {
			t.Error("expected error")
		}
	})

	t.Run("valid config", func(t *testing.T) {
		t.Setenv("DOMAINS", "example.com,www.example.com")
		t.Setenv("EMAIL", "test@example.com")
		t.Setenv("AZURE_KEYVAULT_NAME", "myvault")
		t.Setenv("AZURE_CERT_NAME", "mycert")
		t.Setenv("PFX_PASSWORD", "secret")
		t.Setenv("CHECK_INTERVAL", "12h")
		t.Setenv("RENEW_BEFORE_DAYS", "14")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.Domains) != 2 || cfg.Domains[0] != "example.com" || cfg.Domains[1] != "www.example.com" {
			t.Errorf("unexpected domains: %v", cfg.Domains)
		}
		if cfg.Email != "test@example.com" {
			t.Errorf("unexpected email: %s", cfg.Email)
		}
		if cfg.KeyVaultName != "myvault" {
			t.Errorf("unexpected vault name: %s", cfg.KeyVaultName)
		}
		if cfg.PFXPassword != "secret" {
			t.Errorf("unexpected PFX password: %s", cfg.PFXPassword)
		}
		if cfg.CheckInterval != 12*time.Hour {
			t.Errorf("unexpected interval: %v", cfg.CheckInterval)
		}
		if cfg.RenewBeforeDays != 14 {
			t.Errorf("unexpected renew days: %d", cfg.RenewBeforeDays)
		}
	})

	t.Run("defaults for optional fields", func(t *testing.T) {
		base(t)
		t.Setenv("CHECK_INTERVAL", "")
		t.Setenv("RENEW_BEFORE_DAYS", "")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.CheckInterval != 24*time.Hour {
			t.Errorf("expected default 24h, got %v", cfg.CheckInterval)
		}
		if cfg.RenewBeforeDays != 30 {
			t.Errorf("expected default 30, got %d", cfg.RenewBeforeDays)
		}
	})
}
