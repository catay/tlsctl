package cli

import (
	"fmt"
	"net"
	"strconv"
)

// NormalizeEndpoint parses and normalizes a host or host:port endpoint.
// An optional startTLSProto can be provided to select the default port
// for STARTTLS protocols (smtp=587, imap=143, pop3=110, ldap=389).
func NormalizeEndpoint(endpoint string, startTLSProto ...string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
		port = ""
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

func defaultPort(startTLSProto ...string) string {
	if len(startTLSProto) > 0 {
		switch startTLSProto[0] {
		case "smtp":
			return "587"
		case "imap":
			return "143"
		case "pop3":
			return "110"
		case "ldap":
			return "389"
		}
	}
	return "443"
}
