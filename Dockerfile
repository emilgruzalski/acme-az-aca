# Builder runs natively on the build host's arch; Go cross-compiles to the
# target arch (CGO_ENABLED=0), so no QEMU emulation is needed.
FROM --platform=$BUILDPLATFORM golang:1.27rc3@sha256:6a284ec7a8c67eff5882aaa53b07a57ee397553f8c85a92e5fc97c517f12201f AS builder

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
