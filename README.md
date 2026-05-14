# acme-az-aca

Automates Let's Encrypt certificate issuance and renewal for Azure Container Apps. Runs as a sidecar — handles HTTP-01 challenges, converts PEM to PFX in-memory, and imports directly into Azure Key Vault.

## How it works

Runs as a long-lived sidecar alongside your app containers. An ingress rule routes `/.well-known/acme-challenge/*` to this container; everything else hits your apps normally.

```text
                  ┌─ Azure Container Apps Environment ──────────────┐
                  │                                                 │
                  │   UI app (dev.example.com)                      │
  Internet ─► LB ─┼─► UI app (prd.example.com)                      │
                  │   acme-az-aca   :80  /healthz                   │
                  │        │                                        │
                  │        │ PFX import                             │
                  │        ▼                                        │
                  │   Azure Key Vault ◄─── cert binding (ACA reads) │
                  └─────────────────────────────────────────────────┘

  Routing inside the environment:
    /.well-known/acme-challenge/*   →   acme-az-aca
    everything else                 →   UI apps
```

On each cycle (default: 24h):

1. Check the cert in Key Vault — if it's not expiring within the threshold (default: 30 days), skip and sleep.
2. Request a new cert from Let's Encrypt via ACME HTTP-01.
3. Let's Encrypt calls `http://<domain>/.well-known/acme-challenge/<token>` — the ingress routes it here, we respond with the token.
4. Convert PEM → PFX in-memory (no OpenSSL, handles RSA and ECDSA).
5. Import the PFX into Key Vault. Container Apps picks it up for custom domain bindings.

If any step fails and SMTP is configured, an error notification goes out and the cycle retries on the next interval.

## Requirements

- Azure Key Vault
- Service Principal or Managed Identity with **Key Vault Certificates Officer** on the vault
- Port 80 publicly reachable from the internet (Let's Encrypt needs to reach the ingress for HTTP-01)
- DNS for every domain in `DOMAINS` pointing to the Container Apps Environment load balancer

## Build

```bash
docker build -t acme-az-aca .
```

## Run locally

```bash
docker run -d \
  -p 80:80 \
  -e DOMAINS="dev.example.com,prd.example.com" \
  -e EMAIL="admin@example.com" \
  -e AZURE_TENANT_ID="<tenant-id>" \
  -e AZURE_CLIENT_ID="<client-id>" \
  -e AZURE_CLIENT_SECRET="<client-secret>" \
  -e AZURE_KEYVAULT_NAME="<keyvault-name>" \
  acme-az-aca
```

Port 80 must be publicly reachable for the ACME challenge — running locally without a tunnel won't get you a cert, but is fine for testing startup and the `/healthz` endpoint.

## Deploy to Azure Container Apps

```bash
az containerapp create \
  --name acme-az-aca \
  --resource-group mygroup \
  --environment myenv \
  --image <your-registry>/acme-az-aca:latest \
  --target-port 80 \
  --ingress external \
  --env-vars \
    DOMAINS="dev.example.com,prd.example.com" \
    EMAIL="admin@example.com" \
    AZURE_KEYVAULT_NAME="<keyvault-name>"
```

> [!IMPORTANT]
> Set up the ingress rule routing `/.well-known/acme-challenge/*` to this container **before** the first certificate run. Without it the HTTP-01 challenge times out and you'll burn Let's Encrypt rate limits (5 failed validations/domain/hour, 5 duplicate certs/week).

## Configuration

### Required

| Variable | Description |
| --- | --- |
| `DOMAINS` | Comma-separated domain list (e.g. `dev.example.com,prd.example.com`) |
| `EMAIL` | Contact email for Let's Encrypt account registration |
| `AZURE_KEYVAULT_NAME` | Azure Key Vault name |

### Optional

| Variable | Default | Description |
| --- | --- | --- |
| `AZURE_CERT_NAME` | `wildcard-cert` | Certificate name in Key Vault |
| `CHECK_INTERVAL` | `24h` | Renewal check interval (Go duration format) |
| `RENEW_BEFORE_DAYS` | `30` | Days before expiry to trigger renewal |
| `PFX_PASSWORD` | *(empty)* | PFX password |
| `NOTIFY_EMAIL_ENABLED` | `false` | Enable SMTP error notifications |
| `SMTP_HOST` | — | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `SMTP_FROM` | `$EMAIL` | Notification sender address |
| `SMTP_TO` | `$EMAIL` | Notification recipient address |

### Authentication

Uses [`DefaultAzureCredential`](https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#NewDefaultAzureCredential). In Container Apps, assign a managed identity with Key Vault Certificates Officer — no credentials in env vars needed. For local runs or CI, fall back to a Service Principal via `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, and `AZURE_CLIENT_SECRET`.

### SMTP notifications

```bash
NOTIFY_EMAIL_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password   # App Password, not your account password
```

## Troubleshooting

**HTTP-01 challenge fails**
Let's Encrypt couldn't reach port 80. Check that the `/.well-known/acme-challenge/*` ingress rule is in place, DNS for all domains resolves to the load balancer, and nothing is blocking inbound port 80.

**Key Vault access denied**
The identity (managed or SP) is missing the `Key Vault Certificates Officer` role assignment on the vault. If the vault is still on the legacy access policy model, the equivalent permissions are `get` and `import` on certificates.

**Certificate not updating in Container Apps**
The import itself usually succeeds — check the container logs for `importing certificate`. ACA custom domain binding refresh can take a few minutes after the import.

**Hitting Let's Encrypt rate limits**
5 failed validations per domain per hour, 5 duplicate certs per week. Test against the staging CA first — change `legoConfig.CADirURL` in `main.go` to `https://acme-staging-v02.api.letsencrypt.org/directory`. Staging certs aren't trusted by browsers but the flow is identical.

## Security

- Runs as `nonroot` in a distroless image — no shell, no package manager
- Prefer Managed Identity over Service Principal credentials
- Pass secrets via Container Apps secrets or Key Vault references, not plain env vars
- Port 80 only needs to be reachable while Let's Encrypt is actively verifying challenges

## License

Apache License 2.0 — see [LICENSE](LICENSE).
