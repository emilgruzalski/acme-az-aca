package main

import (
	"context"
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
)

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
