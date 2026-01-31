package cmd

import (
	"encoding/json"

	"gopkg.in/yaml.v3"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tlsctl/internal/tlsquery"
)

var outputFormat string
var showPEM bool

var clientCmd = &cobra.Command{
	Use:   "client FQDN[:PORT]",
	Short: "Query TLS certificate information for a given endpoint",
	Long:  `Connects to a TLS endpoint and displays certificate metadata.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runClient,
}

func init() {
	rootCmd.AddCommand(clientCmd)
	clientCmd.Flags().StringVarP(&outputFormat, "output", "o", "text", "Output format (text, json, yaml)")
	clientCmd.Flags().BoolVar(&showPEM, "show-pem", false, "Include PEM-encoded certificate in output")
}

func runClient(cmd *cobra.Command, args []string) error {
	endpoint, err := normalizeEndpoint(args[0])
	if err != nil {
		return err
	}

	certInfo, err := tlsquery.Query(endpoint)
	if err != nil {
		return err
	}

	return outputChain(certInfo, outputFormat, showPEM)
}

func normalizeEndpoint(endpoint string) (string, error) {
	parts := strings.Split(endpoint, ":")
	if len(parts) > 2 {
		return "", fmt.Errorf("invalid endpoint format: expected FQDN[:PORT], got %q", endpoint)
	}

	host := parts[0]
	if host == "" {
		return "", fmt.Errorf("invalid hostname: hostname cannot be empty")
	}

	port := "443"
	if len(parts) == 2 && parts[1] != "" {
		port = parts[1]
		portNum, err := strconv.Atoi(port)
		if err != nil || portNum < 0 || portNum > 65535 {
			return "", fmt.Errorf("invalid port: port must be a number in the range 0-65535")
		}
	}

	return host + ":" + port, nil
}

func outputChain(chain *tlsquery.ChainInfo, format string, showPEM bool) error {
	outputChain := chain
	if !showPEM {
		outputChain = &tlsquery.ChainInfo{
			Certificates: make([]tlsquery.CertInfo, len(chain.Certificates)),
		}
		for i, cert := range chain.Certificates {
			outputChain.Certificates[i] = cert
			outputChain.Certificates[i].PEM = ""
		}
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(outputChain)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		encoder.SetIndent(2)
		return encoder.Encode(outputChain)
	case "text":
		for i, cert := range outputChain.Certificates {
			if i > 0 {
				fmt.Println()
			}
			fmt.Printf("[%s]\n", strings.ToUpper(cert.Type))
			fmt.Printf("Version:               %d\n", cert.Version)
			fmt.Printf("Serial Number:         %s\n", cert.SerialNumber)
			fmt.Printf("Signature Algorithm:   %s\n", cert.SignatureAlgorithm)
			fmt.Printf("Issuer:                %s\n", cert.Issuer)
			fmt.Printf("Subject:               %s\n", cert.Subject)
			fmt.Printf("Not Before:            %s\n", cert.NotBefore)
			fmt.Printf("Not After:             %s\n", cert.NotAfter)
			fmt.Printf("Public Key Algorithm:  %s\n", cert.PublicKeyAlgorithm)
			if len(cert.KeyUsage) > 0 {
				fmt.Printf("Key Usage:             %s\n", strings.Join(cert.KeyUsage, ", "))
			}
			if len(cert.ExtKeyUsage) > 0 {
				fmt.Printf("Extended Key Usage:    %s\n", strings.Join(cert.ExtKeyUsage, ", "))
			}
			if cert.BasicConstraints != nil {
				if cert.BasicConstraints.IsCA {
					fmt.Printf("Basic Constraints:     CA:TRUE, pathlen:%d\n", cert.BasicConstraints.MaxPathLen)
				} else {
					fmt.Printf("Basic Constraints:     CA:FALSE\n")
				}
			}
			if cert.SubjectKeyID != "" {
				fmt.Printf("Subject Key ID:        %s\n", cert.SubjectKeyID)
			}
			if cert.AuthorityKeyID != "" {
				fmt.Printf("Authority Key ID:      %s\n", cert.AuthorityKeyID)
			}
			if len(cert.SubjectAltNames) > 0 {
				fmt.Printf("Subject Alt Names:     %s\n", strings.Join(cert.SubjectAltNames, ", "))
			}
			if len(cert.EmailAddresses) > 0 {
				fmt.Printf("Email Addresses:       %s\n", strings.Join(cert.EmailAddresses, ", "))
			}
			if len(cert.IPAddresses) > 0 {
				fmt.Printf("IP Addresses:          %s\n", strings.Join(cert.IPAddresses, ", "))
			}
			if len(cert.OCSPServers) > 0 {
				fmt.Printf("OCSP Servers:          %s\n", strings.Join(cert.OCSPServers, ", "))
			}
			if len(cert.IssuingCertURL) > 0 {
				fmt.Printf("CA Issuers:            %s\n", strings.Join(cert.IssuingCertURL, ", "))
			}
			if len(cert.CRLDistPoints) > 0 {
				fmt.Printf("CRL Distribution:      %s\n", strings.Join(cert.CRLDistPoints, ", "))
			}
			if cert.PEM != "" {
				fmt.Printf("PEM:\n%s", cert.PEM)
			}
		}
		return nil
	default:
		return fmt.Errorf("invalid output format: %q (valid: text, json, yaml)", format)
	}
}
