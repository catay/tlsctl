# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o tlsctl .

# Final stage
FROM alpine:3.20

RUN set -eux; addgroup -g 6666 tlsctl && adduser -u 6666 -G tlsctl -D -H tlsctl

COPY --from=builder /build/tlsctl /usr/bin/tlsctl

USER tlsctl:tlsctl

ENTRYPOINT ["/usr/bin/tlsctl"]
