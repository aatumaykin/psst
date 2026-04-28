.PHONY: build test lint clean build-linux-amd64 build-linux-arm64 release snapshot

GOLANGCI_LINT_VERSION := v2.11.4
GOLANGCI_LINT := $(shell command -v golangci-lint 2> /dev/null)

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := -s -w \
  -X github.com/aatumaykin/psst/internal/version.Version=$(VERSION) \
  -X github.com/aatumaykin/psst/internal/version.Commit=$(COMMIT) \
  -X github.com/aatumaykin/psst/internal/version.Date=$(DATE)

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o psst ./cmd/psst/

test:
	go test -race ./... -v

lint:
ifndef GOLANGCI_LINT
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
endif
	golangci-lint run ./...

clean:
	rm -f psst

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o psst-linux-amd64 ./cmd/psst/

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o psst-linux-arm64 ./cmd/psst/

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean
