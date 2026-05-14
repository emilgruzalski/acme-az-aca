package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/kelseyhightower/envconfig"
)

type config struct {
	// Required
	Domains      []string `envconfig:"DOMAINS" required:"true"`
	Email        string   `envconfig:"EMAIL" required:"true"`
	KeyVaultName string   `envconfig:"AZURE_KEYVAULT_NAME" required:"true"`

	// Certificate handling
	CertName        string        `envconfig:"AZURE_CERT_NAME" default:"wildcard-cert"`
	PFXPassword     string        `envconfig:"PFX_PASSWORD"`
	CheckInterval   time.Duration `envconfig:"CHECK_INTERVAL" default:"24h"`
	RenewBeforeDays int           `envconfig:"RENEW_BEFORE_DAYS" default:"30"`
	ACMECAURL       string        `envconfig:"ACME_CA_URL" default:"https://acme-v02.api.letsencrypt.org/directory"`

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
	}
	if cfg.SMTPFrom == "" {
		cfg.SMTPFrom = cfg.Email
	}
	if cfg.SMTPTo == "" {
		cfg.SMTPTo = cfg.Email
	}
	return cfg, nil
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("azure credential: %w", err)
	}

	kvClient, err := azcertificates.NewClient(
		fmt.Sprintf("https://%s.vault.azure.net/", cfg.KeyVaultName),
		cred, nil,
	)
	if err != nil {
		return fmt.Errorf("key vault client: %w", err)
	}

	legoClient, challenge, err := newACMEClient(cfg)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/.well-known/acme-challenge/", challenge)

	server := &http.Server{
		Addr:              ":80",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()
	slog.Info("http server listening", "addr", server.Addr)
	slog.Info("certificate manager started",
		"domains", cfg.Domains,
		"interval", cfg.CheckInterval,
		"renew_before_days", cfg.RenewBeforeDays,
	)

	runCheck := func() {
		if err := processCertificates(ctx, legoClient, kvClient, cfg); err != nil {
			slog.Error("certificate cycle failed", "domains", cfg.Domains, "error", err)
			notifyOnError(cfg, "Certificate Processing Error",
				fmt.Sprintf("Domains: %v\n\n%v", cfg.Domains, err))
		}
	}

	runCheck()

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			return server.Shutdown(shutdownCtx)
		case err := <-serverErr:
			return fmt.Errorf("http server: %w", err)
		case <-ticker.C:
			runCheck()
		}
	}
}

func newACMEClient(cfg config) (*lego.Client, *challengeProvider, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("acme account key: %w", err)
	}

	user := &acmeUser{Email: cfg.Email, key: key}
	legoCfg := lego.NewConfig(user)
	legoCfg.CADirURL = cfg.ACMECAURL

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("acme client: %w", err)
	}

	challenge := &challengeProvider{tokens: make(map[string]string)}
	if err := client.Challenge.SetHTTP01Provider(challenge); err != nil {
		return nil, nil, fmt.Errorf("acme http-01 provider: %w", err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, nil, fmt.Errorf("acme registration: %w", err)
	}
	user.Registration = reg
	slog.Info("acme account registered", "email", cfg.Email, "ca", cfg.ACMECAURL)

	return client, challenge, nil
}

func processCertificates(ctx context.Context, legoClient *lego.Client, kvClient *azcertificates.Client, cfg config) error {
	needsRenewal, err := checkIfRenewalNeeded(ctx, kvClient, cfg.CertName, cfg.RenewBeforeDays)
	if err != nil {
		slog.Warn("renewal check failed, proceeding with renewal", "error", err)
	}
	if !needsRenewal {
		slog.Info("certificate still valid, skipping")
		return nil
	}

	resource, err := legoClient.Certificate.Obtain(certificate.ObtainRequest{
		Domains: cfg.Domains,
		Bundle:  true,
	})
	if err != nil {
		return fmt.Errorf("obtaining certificate: %w", err)
	}

	pfx, err := convertToPFX(resource.Certificate, resource.PrivateKey, cfg.PFXPassword)
	if err != nil {
		return fmt.Errorf("converting to PFX: %w", err)
	}

	if err := uploadToKeyVault(ctx, kvClient, cfg.CertName, pfx, cfg.PFXPassword); err != nil {
		return fmt.Errorf("uploading to key vault: %w", err)
	}

	slog.Info("certificate renewed", "domains", cfg.Domains)
	return nil
}
