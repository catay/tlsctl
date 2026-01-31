.PHONY: build test clean release-local

BINARY := tlsctl

build:
	goreleaser build --single-target --snapshot --clean -o $(BINARY)

test:
	go test ./...

clean:
	rm -rf $(BINARY) dist
	go clean

release-local:
	goreleaser release --snapshot --clean
