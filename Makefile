.PHONY: build test clean release-local

BINARY := tlsctl

build:
	go build -o $(BINARY) .

test:
	go test ./...

clean:
	rm -f $(BINARY)
	go clean

release-local:
	goreleaser release --snapshot --clean
