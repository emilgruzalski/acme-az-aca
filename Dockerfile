# Builder runs natively on the build host's arch; Go cross-compiles to the
# target arch (CGO_ENABLED=0), so no QEMU emulation is needed.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /acme-az-aca ./cmd/acme-az-aca

FROM gcr.io/distroless/static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88

COPY --from=builder /acme-az-aca /acme-az-aca

EXPOSE 80

USER nonroot:nonroot

ENTRYPOINT ["/acme-az-aca"]
