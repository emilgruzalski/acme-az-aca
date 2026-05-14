# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-05-14

### Added

- `ACME_CA_URL` env var — switch between LE production and staging without a rebuild
- `Makefile` (build, test, vet, fmt, tidy, docker, clean)
- `ReadHeaderTimeout` on the HTTP challenge listener

### Changed

- Config loading uses `kelseyhightower/envconfig` (struct tags, single `config` struct)
- Sources split per concern: `config.go`, `acme.go`, `main.go`
- HTTP server errors flow through a channel instead of `os.Exit` from a goroutine

### Removed

- `docs/architecture.svg` (replaced by an inline ASCII diagram in the README)
- Bespoke env helpers and the separate `emailConfig` type
- Duplicate `ENV` defaults from the Dockerfile and the stale legacy Azure SDK dependency

## [1.0.0] - 2026-03-10

Initial release.

- Let's Encrypt issuance and renewal via ACME HTTP-01
- In-memory PEM-to-PFX conversion (RSA and ECDSA), no OpenSSL dependency
- Azure Key Vault import via `DefaultAzureCredential` (Managed Identity or Service Principal)
- Optional SMTP error notifications
- Distroless non-root image, structured `log/slog` output
