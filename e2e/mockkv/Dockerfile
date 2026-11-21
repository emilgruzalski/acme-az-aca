FROM golang:1.27@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /mockkv . && mkdir /shared

FROM gcr.io/distroless/static:nonroot@sha256:d62067879de890a1def9da0e7766b7d20810a5e5555cef8506b752437d7a3e88

COPY --from=builder /mockkv /mockkv
# The compose volume mounted here starts as a copy of this directory, so it
# must already be writable by nonroot for the CA file mockkv writes into it.
COPY --from=builder --chown=nonroot:nonroot /shared /shared

ENTRYPOINT ["/mockkv"]
