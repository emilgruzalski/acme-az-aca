# Builder runs natively on the build host's arch; Go cross-compiles to the
# target arch (CGO_ENABLED=0), so no QEMU emulation is needed.
FROM --platform=$BUILDPLATFORM golang:1.27@sha256:512690a5660563b57d37ecc31129e7f136e831db2aed24a1dbeb8ad7380dc0fa AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /acme-az-aca ./...

FROM gcr.io/distroless/static:nonroot@sha256:963fa6c544fe5ce420f1f54fb88b6fb01479f054c8056d0f74cc2c6000df5240

COPY --from=builder /acme-az-aca /acme-az-aca

EXPOSE 80

USER nonroot:nonroot

ENTRYPOINT ["/acme-az-aca"]
