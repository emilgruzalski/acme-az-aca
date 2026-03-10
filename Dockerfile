FROM golang:1.24 AS builder

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /acme-az-aca ./...

FROM gcr.io/distroless/static:nonroot

COPY --from=builder /acme-az-aca /acme-az-aca

# Certificate management configuration
ENV CHECK_INTERVAL=24h
ENV RENEW_BEFORE_DAYS=30
ENV AZURE_CERT_NAME="wildcard-cert"

# Email notification configuration (optional)
ENV NOTIFY_EMAIL_ENABLED="false"
ENV SMTP_PORT="587"

EXPOSE 80

USER nonroot:nonroot

ENTRYPOINT ["/acme-az-aca"]
