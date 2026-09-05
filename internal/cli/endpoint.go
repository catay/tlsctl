package cli

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
)

// NormalizeEndpoint parses and normalizes a host or host:port endpoint.
// An optional startTLSProto can be provided to select the default port
// for STARTTLS protocols (smtp=587, imap=143, pop3=110, ldap=389).
func NormalizeEndpoint(endpoint string, startTLSProto ...string) (string, error) {
	if looksLikeURL(endpoint) {
		return "", fmt.Errorf("expected host[:port], not a URL")
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err == nil && strings.HasPrefix(endpoint, "[") {
		if ip, parseErr := netip.ParseAddr(host); parseErr != nil || !ip.Is6() {
			return "", fmt.Errorf("brackets require an IPv6 address")
		}
	}
	if err != nil {
		host = endpoint
		port = ""
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
			if ip, err := netip.ParseAddr(host); err != nil || !ip.Is6() {
				return "", fmt.Errorf("brackets require an IPv6 address")
			}
		}
		if _, err := netip.ParseAddr(host); strings.ContainsAny(host, "[]:%") && err != nil {
			return "", fmt.Errorf("invalid host or port: %s", endpoint)
		}
	}
	if strings.ContainsAny(host, ":[]%") {
		if _, err := netip.ParseAddr(host); err != nil {
			return "", fmt.Errorf("invalid IP address: %s", host)
		}
	}

	if strings.ContainsAny(host, " \t\r\n") {
		return "", fmt.Errorf("invalid hostname: whitespace is not allowed")
	}
	if host == "" {
		return "", fmt.Errorf("invalid hostname: hostname cannot be empty")
	}

	if port == "" {
		port = defaultPort(startTLSProto...)
	} else {
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 0 || portNum > 65535 {
			return "", fmt.Errorf("invalid port: port must be a number in the range 0-65535")
		}
	}

	return net.JoinHostPort(host, port), nil
}

func looksLikeURL(endpoint string) bool {
	if strings.Contains(endpoint, "://") {
		return true
	}
	return strings.ContainsAny(endpoint, "/?#@")
}

func defaultPort(startTLSProto ...string) string {
	if len(startTLSProto) > 0 {
		if port, ok := tlsquery.StartTLSPort(startTLSProto[0]); ok {
			return port
		}
	}
	return "443"
}
