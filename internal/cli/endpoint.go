package cli

import (
	"fmt"
	"net"
	"strconv"
)

func NormalizeEndpoint(endpoint string) (string, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
		port = "443"
	}

	if host == "" {
		return "", fmt.Errorf("invalid hostname: hostname cannot be empty")
	}

	if port == "" {
		port = "443"
	} else {
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 0 || portNum > 65535 {
			return "", fmt.Errorf("invalid port: port must be a number in the range 0-65535")
		}
	}

	return net.JoinHostPort(host, port), nil
}
