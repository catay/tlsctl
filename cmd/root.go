package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tlsctl/internal/tlsquery"
)

var jsonOutput bool

var rootCmd = &cobra.Command{
	Use:   "tlsctl FQDN:PORT",
	Short: "Query TLS certificate information for a given endpoint",
	Long:  `tlsctl connects to a TLS endpoint and displays certificate metadata including CN, Issuer, validity dates, and SANs.`,
	Args:  cobra.ExactArgs(1),
	RunE:  run,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
}

func run(cmd *cobra.Command, args []string) error {
	endpoint := args[0]

	if err := validateEndpoint(endpoint); err != nil {
		return err
	}

	certInfo, err := tlsquery.Query(endpoint)
	if err != nil {
		return err
	}

	if jsonOutput {
		return outputJSON(certInfo)
	}
	outputText(certInfo)
	return nil
}

func validateEndpoint(endpoint string) error {
	parts := strings.Split(endpoint, ":")
	if len(parts) != 2 {
		return fmt.Errorf("invalid endpoint format: expected FQDN:PORT, got %q", endpoint)
	}

	host, port := parts[0], parts[1]

	if host == "" {
		return fmt.Errorf("invalid hostname: hostname cannot be empty")
	}

	if port == "" {
		return fmt.Errorf("invalid port: port cannot be empty")
	}

	for _, c := range port {
		if c < '0' || c > '9' {
			return fmt.Errorf("invalid port: %q is not a valid port number", port)
		}
	}

	return nil
}

func outputJSON(chain *tlsquery.ChainInfo) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(chain)
}

func outputText(chain *tlsquery.ChainInfo) {
	for i, cert := range chain.Certificates {
		if i > 0 {
			fmt.Println()
		}
		fmt.Printf("[%s]\n", strings.ToUpper(cert.Type))
		fmt.Printf("Common Name:           %s\n", cert.CommonName)
		fmt.Printf("Issuer:                %s\n", cert.Issuer)
		fmt.Printf("Valid From:            %s\n", cert.NotBefore)
		fmt.Printf("Valid Until:           %s\n", cert.NotAfter)
		if len(cert.SubjectAltNames) > 0 {
			fmt.Printf("Subject Alt Names:     %s\n", strings.Join(cert.SubjectAltNames, ", "))
		}
	}
}
