.PHONY: all build test lint fmt clean release-local

BINARY := tlsctl

all: clean lint fmt test build

build:
	goreleaser build --single-target --snapshot --clean -o $(BINARY)

test:
	go test ./...

lint:
	golangci-lint run ./...

fmt:
	gofmt -s -w -l .

clean:
	rm -rf $(BINARY) dist
	go clean

release-local:
	goreleaser release --snapshot --clean
