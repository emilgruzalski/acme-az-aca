# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-03-10

### Added

- Automatic Let's Encrypt certificate management via ACME HTTP-01 challenge
- Multi-domain support in a single certificate (Subject Alternative Names)
- Built-in HTTP server on port 80 for challenge verification and `/healthz` health endpoint
- Azure Key Vault integration — checks expiration date, imports renewed PFX certificate
- In-memory PEM-to-PFX conversion using `go-pkcs12` with modern AES-256-CBC/SHA-256 encoding (no OpenSSL dependency)
- Support for both RSA (PKCS1/PKCS8) and ECDSA (PKCS8/SEC1) private keys
- Configurable renewal threshold (`RENEW_BEFORE_DAYS`, default 30 days) and check interval (`CHECK_INTERVAL`, default 24h)
- Graceful shutdown on `SIGINT`/`SIGTERM` with 5-second drain timeout
- Optional SMTP error notifications (`NOTIFY_EMAIL_ENABLED`)
- Structured logging via `log/slog` (Go standard library)
- Minimal distroless Docker image (~20 MB, non-root user)
- Azure SDK `security/keyvault/azcertificates` v1.4.0 with `DefaultAzureCredential` support (Managed Identity and Service Principal)
