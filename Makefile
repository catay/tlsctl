.PHONY: build test clean

BINARY := tlsctl

build:
	go build -o $(BINARY) .

test:
	go test ./...

clean:
	rm -f $(BINARY)
	go clean
