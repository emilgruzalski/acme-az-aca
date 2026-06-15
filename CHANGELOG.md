# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] - 2026-06-15

### Added

- Multi-arch release images for `linux/amd64` and `linux/arm64`, published as a single manifest list. The Dockerfile cross-compiles from the build host's arch (`CGO_ENABLED=0`), so no QEMU emulation is involved.

## [1.2.1] - 2026-06-11

### Added

- CI security gates: `govulncheck` and a gating Trivy image scan (HIGH/CRITICAL) on every run; results are uploaded as SARIF to the GitHub Security tab.
- Release images get an SPDX SBOM, BuildKit SBOM/provenance attestations, and a keyless cosign signature.
- Weekly `scan.yml` workflow rescanning the published ghcr.io image and the Go dependencies, so CVEs discovered after a release surface without a commit.
- Release automation: pushing a `v*` tag creates a GitHub Release with the matching CHANGELOG section as notes and the SPDX SBOM attached as an asset.

### Changed

- CI is a repo-local workflow tailored to this app (gofmt and `go mod tidy` checks, vet, golangci-lint v2, race tests, Docker build with image push to ghcr.io on `v*` tags) instead of the shared reusable workflow.
- Go 1.26.4; all dependencies upgraded, notably `lego` v4.22 → v4.35 and the Azure Key Vault SDKs to v1.5.0.
- Dockerfile base images are pinned by digest (Dependabot keeps the digests fresh) and the binary is built with `-trimpath` for reproducibility.

### Removed

- `Makefile` — CI is self-contained now; locally the equivalents are `gofmt -l .`, `go vet ./...`, `golangci-lint run`, `go test -race -cover ./...`, and `go build`.

## [1.2.0] - 2026-06-10

### Added

- ACME account key is persisted as a Key Vault secret (`ACME_ACCOUNT_SECRET_NAME`, default `acme-account-key`), so restarts reuse the same Let's Encrypt account instead of registering a new one each time (LE rate-limits new registrations per IP). Requires `Key Vault Secrets Officer`; falls back to an ephemeral account with a warning when the role is missing. Set the variable to an empty string to disable.
- Renewal is now also triggered when the stored certificate doesn't cover every domain in `DOMAINS` (SAN check), not just on approaching expiry — adding a domain takes effect on the next cycle.
- `RETRY_INTERVAL` env var (default `1h`) — a failed cycle retries after this delay instead of waiting out the full `CHECK_INTERVAL`.
- `/status` endpoint returning the last cycle outcome as JSON (`healthy`, `last_check`, `last_success`, `last_error`).
- Config validation: `CHECK_INTERVAL`/`RETRY_INTERVAL` must be positive (a non-positive interval previously panicked the ticker), `RENEW_BEFORE_DAYS` must not be negative.
- Dependabot updates for Go modules, GitHub Actions, and the Docker base images; CI also runs on pushes to `main`.

### Changed

- **Breaking:** default `AZURE_CERT_NAME` renamed from `wildcard-cert` to `acme-cert` (HTTP-01 cannot issue wildcard certificates, so the old name was misleading). Deployments relying on the default must set `AZURE_CERT_NAME=wildcard-cert` explicitly to keep the existing certificate binding.
- A transient Key Vault error during the renewal check now aborts the cycle (notifying and retrying after `RETRY_INTERVAL`) instead of proceeding with an unnecessary reissue that burned Let's Encrypt duplicate-certificate rate limits. A missing certificate (404) still triggers initial issuance.
- SMTP notifications use an explicit client with a 30s session deadline — `smtp.SendMail` dials with no timeout, so a hung SMTP server could stall the renewal loop indefinitely.

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
