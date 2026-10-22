FROM golang:1.27@sha256:f20d83a83e18dbd2a4714b8ffd4b30b287b6243962dd75608e86abcc63ba4efc AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /mockkv . && mkdir /shared

FROM gcr.io/distroless/static:nonroot@sha256:e2e927ec666bae08560abb3c55d0659eceabb657f56b6782ab500a9fc7f555e3

COPY --from=builder /mockkv /mockkv
# The compose volume mounted here starts as a copy of this directory, so it
# must already be writable by nonroot for the CA file mockkv writes into it.
COPY --from=builder --chown=nonroot:nonroot /shared /shared

ENTRYPOINT ["/mockkv"]
