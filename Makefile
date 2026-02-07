.PHONY: build test lint clean release-local

BINARY := tlsctl

build:
	goreleaser build --single-target --snapshot --clean -o $(BINARY)

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BINARY) dist
	go clean

release-local:
	goreleaser release --snapshot --clean
