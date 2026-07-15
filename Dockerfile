# Builder runs natively on the build host's arch; Go cross-compiles to the
# target arch (CGO_ENABLED=0), so no QEMU emulation is needed.
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:87a41d2539e5671777734e91f467499ed5eafb1fb1f77221dff2744db7a51775 AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /usr/src/app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /acme-az-aca ./...

FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --from=builder /acme-az-aca /acme-az-aca

EXPOSE 80

USER nonroot:nonroot

ENTRYPOINT ["/acme-az-aca"]
