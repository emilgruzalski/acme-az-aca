package main

import (
	"fmt"
	"time"

	"github.com/kelseyhightower/envconfig"
)

type config struct {
	// Required
	Domains      []string `envconfig:"DOMAINS" required:"true"`
	Email        string   `envconfig:"EMAIL" required:"true"`
	KeyVaultName string   `envconfig:"AZURE_KEYVAULT_NAME" required:"true"`

	// Certificate handling
	CertName        string        `envconfig:"AZURE_CERT_NAME" default:"acme-cert"`
	PFXPassword     string        `envconfig:"PFX_PASSWORD"`
	CheckInterval   time.Duration `envconfig:"CHECK_INTERVAL" default:"24h"`
	RetryInterval   time.Duration `envconfig:"RETRY_INTERVAL" default:"1h"`
	RenewBeforeDays int           `envconfig:"RENEW_BEFORE_DAYS" default:"30"`
	ACMECAURL       string        `envconfig:"ACME_CA_URL" default:"https://acme-v02.api.letsencrypt.org/directory"`

	// ACME account key persistence; set to "" to disable and register a fresh
	// account on every start.
	AccountSecretName string `envconfig:"ACME_ACCOUNT_SECRET_NAME" default:"acme-account-key"`

	// SMTP error notifications (optional)
	NotifyEnabled bool   `envconfig:"NOTIFY_EMAIL_ENABLED" default:"false"`
	SMTPHost      string `envconfig:"SMTP_HOST"`
	SMTPPort      string `envconfig:"SMTP_PORT" default:"587"`
	SMTPUsername  string `envconfig:"SMTP_USERNAME"`
	SMTPPassword  string `envconfig:"SMTP_PASSWORD"`
	SMTPFrom      string `envconfig:"SMTP_FROM"`
	SMTPTo        string `envconfig:"SMTP_TO"`
}

func loadConfig() (config, error) {
	var cfg config
	if err := envconfig.Process("", &cfg); err != nil {
		return cfg, err
	}
	// envconfig's `required` tag accepts an env var set to "" as present;
	// in K8s / Container Apps that's a common misconfig, so fail fast.
	switch {
	case len(cfg.Domains) == 0 || cfg.Domains[0] == "":
		return cfg, fmt.Errorf("DOMAINS is required")
	case cfg.Email == "":
		return cfg, fmt.Errorf("EMAIL is required")
	case cfg.KeyVaultName == "":
		return cfg, fmt.Errorf("AZURE_KEYVAULT_NAME is required")
	case cfg.CheckInterval <= 0:
		return cfg, fmt.Errorf("CHECK_INTERVAL must be positive, got %s", cfg.CheckInterval)
	case cfg.RetryInterval <= 0:
		return cfg, fmt.Errorf("RETRY_INTERVAL must be positive, got %s", cfg.RetryInterval)
	case cfg.RenewBeforeDays < 0:
		return cfg, fmt.Errorf("RENEW_BEFORE_DAYS must not be negative, got %d", cfg.RenewBeforeDays)
	}
	if cfg.SMTPFrom == "" {
		cfg.SMTPFrom = cfg.Email
	}
	if cfg.SMTPTo == "" {
		cfg.SMTPTo = cfg.Email
	}
	return cfg, nil
}
