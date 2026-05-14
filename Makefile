BINARY  := acme-az-aca
IMAGE   := acme-az-aca
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

GO_LDFLAGS := -s -w

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the binary into ./bin
	CGO_ENABLED=0 go build -ldflags="$(GO_LDFLAGS)" -o bin/$(BINARY) ./...

.PHONY: test
test: ## Run tests with race detector and coverage
	go test -race -cover ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: fmt
fmt: ## gofmt check (fails on unformatted files)
	@out=$$(gofmt -l . | grep -v '^vendor/' || true); \
		if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

.PHONY: tidy
tidy: ## go mod tidy
	go mod tidy

.PHONY: docker
docker: ## Build the container image tagged with $VERSION and latest
	docker build -t $(IMAGE):$(VERSION) -t $(IMAGE):latest .

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin/
