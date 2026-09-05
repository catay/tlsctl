.PHONY: all build test lint fmt check-fmt clean release-local vuln

BINARY := tlsctl
VERSION := $(shell tr -d '[:space:]' < VERSION)
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/catay/tlsctl/v2/cmd.version=$(VERSION) -X github.com/catay/tlsctl/v2/cmd.commit=$(COMMIT) -X github.com/catay/tlsctl/v2/cmd.date=$(BUILD_DATE)

all: check-fmt lint test build

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

test:
	go test -race ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w -l cmd internal main.go

check-fmt:
	@test -z "$$(gofmt -s -l cmd internal main.go)" || { gofmt -s -l cmd internal main.go; exit 1; }

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...

clean:
	rm -f tlsctl
	rm -rf dist
	go clean

release-local:
	goreleaser release --snapshot --clean
