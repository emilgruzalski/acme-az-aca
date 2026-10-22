# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.6] - 2026-10-22

### Changed

- Bumped `github.com/Azure/azure-sdk-for-go/sdk/azcore` from `v1.23.1` to `v1.23.3` and `sdk/azidentity` from `v1.14.1` to `v1.15.0` (Dependabot #27, #28); `sdk/internal` `v1.12.0` → `v1.13.0` and `microsoft-authentication-library-for-go` `v1.8.0` → `v1.10.1` come along as their requirements. The `azidentity` release adds Azure Arc user-assigned identities and `WorkloadIdentityCredential` identity binding, and hardens the Service Fabric managed-identity endpoint; none of that changes how this app authenticates (`DefaultAzureCredential` in Container Apps).
- Bumped `software.sslmate.com/src/go-pkcs12` from `v0.7.3` to `v0.7.4` (Dependabot #26).
- Runtime base image `gcr.io/distroless/static:nonroot` digest `f7f8f72` → `e2e927e` (Dependabot #22). Package changes: `base-files` `13.8+deb13u6` → `13.8+deb13u7` and `tzdata` / `tzdata-legacy` `2026b` → `2026c`. `netbase` and `media-types` are unchanged, and the CA bundle is byte-identical (150 certificates, same hash), so the set of roots the ACME client trusts does not move.
- CI: `anchore/sbom-action` `v0.24.2` → `v0.24.3` (Dependabot #25, already merged to `main`).
- CI: `golangci-lint` `v2.13.2` → `v2.15.0`. On Go 1.27.3, v2.13.2 fails every package with `typecheck` errors because it cannot read the toolchain's newer export data (`export data version 5 is greater than maximum supported version 4`). v2.15.0 reads it and reports no issues.

### Security

- Go 1.27.1 → 1.27.3, fixing [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809) in `crypto/x509`, which `govulncheck` reports as reachable. The Dockerfile `golang:1.27` builder is pinned to the digest carrying 1.27.3 (`f20d83a`). This supersedes Dependabot #23: its digest (`3680233`) was only a Debian refresh of the image that still ships Go 1.27.1.
- Bumped `golang.org/x/net` from `v0.58.0` to `v0.60.0`, fixing five advisories `govulncheck` reports as reachable: [GO-2026-6603](https://pkg.go.dev/vuln/GO-2026-6603), [GO-2026-6610](https://pkg.go.dev/vuln/GO-2026-6610), [GO-2026-6611](https://pkg.go.dev/vuln/GO-2026-6611), [GO-2026-6612](https://pkg.go.dev/vuln/GO-2026-6612) and [GO-2026-6617](https://pkg.go.dev/vuln/GO-2026-6617). These were already failing the `govulncheck` job on `main` and on every open Dependabot PR. The rest of the `golang.org/x/*` set moves with it: `crypto` `v0.57.0`, `mod` `v0.41.0`, `sync` `v0.23.0`, `sys` `v0.48.0`, `text` `v0.42.0`, `tools` `v0.49.0`.
- `govulncheck` still lists [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) (the unmaintained `x/crypto/openpgp` package) as present in a required module. It has no fix, and this code never imports the package, so the job does not fail on it.

## [1.2.5] - 2026-09-10

### Changed

- Runtime base image `gcr.io/distroless/static:nonroot` digest `963fa6c` → `f7f8f72` (Dependabot). The only package change is `base-files` `13.8+deb13u5` → `13.8+deb13u6`, i.e. the Debian 13.5 → 13.6 point release; `netbase`, `media-types`, `tzdata` (2026b) and the CA bundle (150 certificates, identical hash) are unchanged, so nothing the ACME client trusts or resolves moves.

## [1.2.4] - 2026-09-10

### Changed

- Go 1.26.8 → 1.27.1. The Dockerfile builder moves to `golang:1.27` (Dependabot, pinned to the digest carrying 1.27.1) and the `go` directive follows it, so the `test` job, the image build and local builds all agree on the toolchain.
- Bumped `github.com/Azure/azure-sdk-for-go/sdk/azcore` from `v1.22.0` to `v1.23.1` and `sdk/azidentity` from `v1.13.1` to `v1.14.1`; `microsoft-authentication-library-for-go` `v1.7.2` → `v1.8.0` and `golang.org/x/net` `v0.57.0` → `v0.58.0` come along as their requirements. The Key Vault SDKs (`azcertificates`, `azsecrets` `v1.5.0`) are already current.
- CI: `golangci-lint` `v2.11.4` → `v2.13.2`, `anchore/sbom-action` `v0.24.0` → `v0.24.2`. Every other action in `ci.yml` and `scan.yml` was checked against its latest release and is already current (`checkout@v7`, `setup-go@v7`, `golangci-lint-action@v9`, `govulncheck-action@v1.1.0`, `setup-buildx-action@v4`, `login-action@v4`, `metadata-action@v6`, `build-push-action@v7`, `trivy-action@v0.36.0`, `codeql-action/upload-sarif@v4`, `cosign-installer@v4.1.2`, `download-artifact@v8`).

### Fixed

- CI: the Trivy image gate now enforces `severity: HIGH,CRITICAL` as written. With `format: sarif` the action was silently dropping the severity filter unless `limit-severities-for-sarif` is set, so `exit-code: 1` failed the job on any finding at any severity — which is what blocked v1.2.3 on two MEDIUMs. Trade-off: the SARIF uploaded to the Security tab is now limited to HIGH/CRITICAL too. Applies to `ci.yml` and `scan.yml`.
- CI: `govulncheck` now runs on the toolchain from `go.mod`. `golang/govulncheck-action` defaults `go-version-input` to `stable`, which `setup-go` prefers over `go-version-file`; blanking it makes the scan use the Go the shipped binary is actually built with instead of whatever is newest. Applies to `ci.yml` and `scan.yml`.

## [1.2.3] - 2026-09-10

### Changed

- Bumped `software.sslmate.com/src/go-pkcs12` from `v0.7.2` to `v0.7.3`.
- Bumped `golang.org/x/text` from `v0.38.0` to `v0.41.0`, fixing [GO-2026-5970](https://pkg.go.dev/vuln/GO-2026-5970) (infinite loop on invalid input in `norm`), reachable via `lego`'s certificate `Obtain` path.
- Bumped `golang.org/x/crypto` from `v0.53.0` to `v0.56.0`, clearing three `x/crypto/ssh` CVEs the Trivy image gate reports: [CVE-2026-56854](https://avd.aquasec.com/nvd/cve-2026-56854) (CRITICAL, auth bypass from unenforced source-address restrictions), plus [CVE-2026-56855](https://avd.aquasec.com/nvd/cve-2026-56855) and [CVE-2026-78662](https://avd.aquasec.com/nvd/cve-2026-78662) (MEDIUM, denial of service). This code never calls `ssh`, so `govulncheck` treats all three as unreachable, but the module is recorded in the binary's build info and Trivy gates on module version, not reachability. The rest of the `golang.org/x/*` set moves with it: `mod` `v0.38.0`, `net` `v0.57.0`, `sync` `v0.22.0`, `sys` `v0.47.0`, `tools` `v0.48.0`.
- Go 1.26.4 → 1.26.8, clearing six standard-library advisories reachable from this code: [GO-2026-6218](https://pkg.go.dev/vuln/GO-2026-6218), [GO-2026-6090](https://pkg.go.dev/vuln/GO-2026-6090), [GO-2026-6089](https://pkg.go.dev/vuln/GO-2026-6089) and [GO-2026-5026](https://pkg.go.dev/vuln/GO-2026-5026) in `net/http`, [GO-2026-6088](https://pkg.go.dev/vuln/GO-2026-6088) in `encoding/xml`, and [GO-2026-5972](https://pkg.go.dev/vuln/GO-2026-5972) in `encoding/asn1`. The `test` job and the image build take their toolchain from `go.mod`, so the `go` directive governs both. Note the `govulncheck` job does not: `golang/govulncheck-action` defaults `go-version` to `stable`, which overrides the `go-version-file: go.mod` the workflow passes, so that job runs on whatever Go is current (1.27.1 today) no matter what this directive says.
- Dockerfile `golang:1.26` builder digest refreshed to the image carrying Go 1.26.8, keeping the pinned base in step with the `go` directive so image builds don't fetch a toolchain at build time.


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
