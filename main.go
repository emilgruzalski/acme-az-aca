package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type config struct {
	Domains         []string
	Email           string
	KeyVaultName    string
	CertName        string
	PFXPassword     string
	CheckInterval   time.Duration
	RenewBeforeDays int
}

func loadConfig() (config, error) {
	domains := strings.Split(os.Getenv("DOMAINS"), ",")
	if len(domains) == 0 || (len(domains) == 1 && domains[0] == "") {
		return config{}, fmt.Errorf("DOMAINS environment variable is required")
	}

	email := os.Getenv("EMAIL")
	if email == "" {
		return config{}, fmt.Errorf("EMAIL environment variable is required")
	}

	keyVaultName := os.Getenv("AZURE_KEYVAULT_NAME")
	if keyVaultName == "" {
		return config{}, fmt.Errorf("AZURE_KEYVAULT_NAME environment variable is required")
	}

	certName := os.Getenv("AZURE_CERT_NAME")
	if certName == "" {
		return config{}, fmt.Errorf("AZURE_CERT_NAME environment variable is required")
	}

	return config{
		Domains:         domains,
		Email:           email,
		KeyVaultName:    keyVaultName,
		CertName:        certName,
		PFXPassword:     os.Getenv("PFX_PASSWORD"),
		CheckInterval:   envDuration("CHECK_INTERVAL", 24*time.Hour),
		RenewBeforeDays: envInt("RENEW_BEFORE_DAYS", 30),
	}, nil
}

func main() {
	if err := run(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Azure Key Vault client (created once)
	azCred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return fmt.Errorf("creating Azure credential: %w", err)
	}

	kvClient, err := azcertificates.NewClient(
		fmt.Sprintf("https://%s.vault.azure.net/", cfg.KeyVaultName),
		azCred,
		nil,
	)
	if err != nil {
		return fmt.Errorf("creating Key Vault client: %w", err)
	}

	// ACME account (registered once)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generating ACME account key: %w", err)
	}

	user := &acmeUser{Email: cfg.Email, key: privateKey}

	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = "https://acme-v02.api.letsencrypt.org/directory"

	challenge := &challengeProvider{tokens: make(map[string]string)}

	legoClient, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("creating ACME client: %w", err)
	}

	if err := legoClient.Challenge.SetHTTP01Provider(challenge); err != nil {
		return fmt.Errorf("setting HTTP-01 provider: %w", err)
	}

	reg, err := legoClient.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("registering ACME account: %w", err)
	}
	user.Registration = reg
	slog.Info("ACME account registered", "email", cfg.Email)

	// HTTP server for health checks and ACME challenges
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/.well-known/acme-challenge/", challenge)

	server := &http.Server{Addr: ":80", Handler: mux}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("HTTP server error", "error", err)
			os.Exit(1)
		}
	}()
	slog.Info("HTTP server started", "addr", ":80")

	slog.Info("Starting certificate management",
		"domains", cfg.Domains,
		"check_interval", cfg.CheckInterval,
		"renew_before_days", cfg.RenewBeforeDays,
	)

	notifyCfg := loadEmailConfig()

	runCheck := func() {
		err := processCertificates(ctx, legoClient, kvClient, cfg)
		if err != nil {
			slog.Error("Error processing certificates", "domains", cfg.Domains, "error", err)
			if notifyCfg.Enabled {
				msg := fmt.Sprintf("Error processing certificates for domains: %v\n\nError details:\n%v", cfg.Domains, err)
				if notifyErr := sendErrorNotification(notifyCfg, "Certificate Processing Error", msg); notifyErr != nil {
					slog.Error("Failed to send error notification", "error", notifyErr)
				}
			}
		}
	}

	// Run first check immediately
	runCheck()

	ticker := time.NewTicker(cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("Shutting down...")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			return server.Shutdown(shutdownCtx)
		case <-ticker.C:
			runCheck()
		}
	}
}

func processCertificates(ctx context.Context, legoClient *lego.Client, kvClient *azcertificates.Client, cfg config) error {
	needsRenewal, err := checkIfRenewalNeeded(ctx, kvClient, cfg.CertName, cfg.RenewBeforeDays)
	if err != nil {
		slog.Warn("Error checking certificate renewal, proceeding with renewal", "error", err)
	}

	if !needsRenewal {
		slog.Info("Certificate is still valid and not due for renewal")
		return nil
	}

	certificates, err := legoClient.Certificate.Obtain(certificate.ObtainRequest{
		Domains: cfg.Domains,
		Bundle:  true,
	})
	if err != nil {
		return fmt.Errorf("obtaining certificate: %w", err)
	}

	pfxData, err := convertToPFX(certificates.Certificate, certificates.PrivateKey, cfg.PFXPassword)
	if err != nil {
		return fmt.Errorf("converting to PFX: %w", err)
	}

	if err := uploadToKeyVault(ctx, kvClient, cfg.CertName, pfxData, cfg.PFXPassword); err != nil {
		return fmt.Errorf("uploading to Key Vault: %w", err)
	}

	slog.Info("Successfully processed certificates", "domains", cfg.Domains)
	return nil
}

func envWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func envDuration(key string, defaultValue time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return defaultValue
}

func envInt(key string, defaultValue int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return defaultValue
}
