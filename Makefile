.PHONY: build test lint clean build-linux-amd64 build-linux-arm64

GOLANGCI_LINT_VERSION := v2.11.4
GOLANGCI_LINT := $(shell command -v golangci-lint 2> /dev/null)

build:
	go build -o psst ./cmd/psst/

test:
	go test ./... -v

lint:
ifndef GOLANGCI_LINT
	@echo "Installing golangci-lint $(GOLANGCI_LINT_VERSION)..."
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin $(GOLANGCI_LINT_VERSION)
endif
	golangci-lint run ./...

clean:
	rm -f psst

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build -o psst-linux-amd64 ./cmd/psst/

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build -o psst-linux-arm64 ./cmd/psst/
