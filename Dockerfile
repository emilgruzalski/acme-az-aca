# Builder runs natively on the build host's arch; Go cross-compiles to the
# target arch (CGO_ENABLED=0), so no QEMU emulation is needed.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:2920bb124f1a2e12a1d39f0cab756ae0068441ee1da7655dec7f5e374944095b AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /acme-az-aca ./cmd/acme-az-aca

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

COPY --from=builder /acme-az-aca /acme-az-aca

EXPOSE 80

USER nonroot:nonroot

ENTRYPOINT ["/acme-az-aca"]
