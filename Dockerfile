# Build stage
FROM golang:1.27.1-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG COMMIT=none
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath \
    -ldflags="-s -w -X github.com/catay/tlsctl/v2/cmd.version=$(cat VERSION) -X github.com/catay/tlsctl/v2/cmd.commit=${COMMIT} -X github.com/catay/tlsctl/v2/cmd.date=${BUILD_DATE}" \
    -o tlsctl .

# Final stage
FROM alpine:3.24

RUN apk add --no-cache ca-certificates

RUN set -eux; addgroup -g 6666 tlsctl && adduser -u 6666 -G tlsctl -D -H tlsctl

COPY --from=builder /build/tlsctl /usr/bin/tlsctl

USER tlsctl:tlsctl

ENTRYPOINT ["/usr/bin/tlsctl"]
