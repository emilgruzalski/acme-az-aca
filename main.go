package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
)

// cycleStatus tracks the outcome of the last renewal cycle and serves it as
// JSON, so a failing renewal is observable without digging through logs.
type cycleStatus struct {
	mu          sync.Mutex
	lastCheck   time.Time
	lastSuccess time.Time
	lastError   string
}

func (s *cycleStatus) record(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastCheck = time.Now().UTC()
	if err != nil {
		s.lastError = err.Error()
		return
	}
	s.lastSuccess = s.lastCheck
	s.lastError = ""
}

func (s *cycleStatus) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resp := struct {
		Healthy     bool       `json:"healthy"`
		LastCheck   *time.Time `json:"last_check,omitempty"`
		LastSuccess *time.Time `json:"last_success,omitempty"`
		LastError   string     `json:"last_error,omitempty"`
	}{Healthy: s.lastError == ""}
	if !s.lastCheck.IsZero() {
		resp.LastCheck = &s.lastCheck
	}
	if !s.lastSuccess.IsZero() {
		resp.LastSuccess = &s.lastSuccess
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
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

	vaultURL := fmt.Sprintf("https://%s.vault.azure.net/", cfg.KeyVaultName)
	kvClient, err := azcertificates.NewClient(vaultURL, cred, nil)
	if err != nil {
		return fmt.Errorf("key vault certificates client: %w", err)
	}
	secretsClient, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		return fmt.Errorf("key vault secrets client: %w", err)
	}

	legoClient, challenge, err := newACMEClient(ctx, cfg, secretsClient)
	if err != nil {
		return err
	}

	status := &cycleStatus{}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.Handle("/status", status)
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
		"retry_interval", cfg.RetryInterval,
		"renew_before_days", cfg.RenewBeforeDays,
	)

	// A failed cycle retries after the shorter RetryInterval instead of
	// waiting out the full CheckInterval.
	runCheck := func() time.Duration {
		err := processCertificates(ctx, legoClient, kvClient, cfg)
		status.record(err)
		if err != nil {
			slog.Error("certificate cycle failed", "domains", cfg.Domains, "error", err)
			notifyOnError(cfg, "Certificate Processing Error",
				fmt.Sprintf("Domains: %v\n\n%v", cfg.Domains, err))
			return min(cfg.RetryInterval, cfg.CheckInterval)
		}
		return cfg.CheckInterval
	}

	timer := time.NewTimer(runCheck())
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("shutting down")
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			return server.Shutdown(shutdownCtx)
		case err := <-serverErr:
			return fmt.Errorf("http server: %w", err)
		case <-timer.C:
			timer.Reset(runCheck())
		}
	}
}

func processCertificates(ctx context.Context, legoClient *lego.Client, kvClient *azcertificates.Client, cfg config) error {
	needsRenewal, err := checkIfRenewalNeeded(ctx, kvClient, cfg.CertName, cfg.Domains, cfg.RenewBeforeDays)
	if err != nil {
		return fmt.Errorf("checking renewal: %w", err)
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
