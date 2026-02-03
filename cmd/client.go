package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"github.com/tlsctl/internal/tlsquery"
	"gopkg.in/yaml.v3"
)

var outputFormat string
var insecureMode bool

var clientCmd = &cobra.Command{
	Use:   "client FQDN[:PORT]",
	Short: "Query TLS certificate information for a given endpoint",
	Long:  `Connects to a TLS endpoint and displays certificate metadata.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runClient,
}

func init() {
	rootCmd.AddCommand(clientCmd)
	clientCmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: json, yaml, text (verbose), raw (PEM)")
	clientCmd.Flags().BoolVarP(&insecureMode, "insecure", "k", false, "Skip certificate verification (insecure)")
}

func runClient(cmd *cobra.Command, args []string) error {
	endpoint, err := normalizeEndpoint(args[0])
	if err != nil {
		return err
	}

	opts := tlsquery.QueryOptions{Insecure: insecureMode}
	certInfo, err := tlsquery.Query(endpoint, opts)
	if err != nil {
		return err
	}

	return outputChain(certInfo, outputFormat, insecureMode)
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

func outputChain(chain *tlsquery.ChainInfo, format string, insecure bool) error {
	// Strip PEM from output unless raw format
	outputData := chain
	if format != "raw" {
		outputData = &tlsquery.ChainInfo{
			Certificates: make([]tlsquery.CertInfo, len(chain.Certificates)),
		}
		for i, cert := range chain.Certificates {
			outputData.Certificates[i] = cert
			outputData.Certificates[i].PEM = ""
		}
	}

	switch format {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(outputData)
	case "yaml":
		encoder := yaml.NewEncoder(os.Stdout)
		encoder.SetIndent(2)
		return encoder.Encode(outputData)
	case "raw":
		for _, cert := range chain.Certificates {
			fmt.Print(cert.PEM)
		}
		return nil
	case "text":
		return outputVerboseText(outputData, insecure)
	case "":
		return outputHumanReadable(chain, insecure)
	default:
		return fmt.Errorf("invalid output format: %q (valid: json, yaml, text, raw)", format)
	}
}

func outputHumanReadable(chain *tlsquery.ChainInfo, insecure bool) error {
	if len(chain.Certificates) == 0 {
		return fmt.Errorf("no certificates in chain")
	}

	leaf := chain.Certificates[0]

	// Parse expiry and calculate status
	notAfter, err := time.Parse(time.RFC3339, leaf.NotAfter)
	if err != nil {
		return fmt.Errorf("failed to parse expiry date: %w", err)
	}
	notBefore, err := time.Parse(time.RFC3339, leaf.NotBefore)
	if err != nil {
		return fmt.Errorf("failed to parse start date: %w", err)
	}

	now := time.Now().UTC()
	daysUntilExpiry := int(notAfter.Sub(now).Hours() / 24)

	// Determine status indicator
	var status, statusMsg string
	switch {
	case now.After(notAfter):
		status = color.RedString("✗")
		statusMsg = "expired"
	case insecure:
		status = color.YellowString("⚠")
		statusMsg = fmt.Sprintf("insecure, expires in %d days", daysUntilExpiry)
	case daysUntilExpiry <= 30:
		status = color.YellowString("⚠")
		statusMsg = fmt.Sprintf("expires in %d days", daysUntilExpiry)
	default:
		status = color.GreenString("✓")
		statusMsg = fmt.Sprintf("expires in %d days", daysUntilExpiry)
	}

	// Display name: prefer CommonName, fall back to first SAN
	displayName := leaf.CommonName
	if displayName == "" && len(leaf.SubjectAltNames) > 0 {
		displayName = leaf.SubjectAltNames[0]
	}
	if displayName == "" {
		displayName = leaf.Subject
	}

	// Header line
	fmt.Printf("%s %s (%s)\n", status, displayName, statusMsg)

	// Subject and Issuer
	fmt.Printf("  Subject:  %s\n", leaf.Subject)
	fmt.Printf("  Issuer:   %s\n", leaf.Issuer)

	// Validity period (formatted nicely)
	fmt.Printf("  Validity: %s → %s\n",
		notBefore.Format("2006-01-02"),
		notAfter.Format("2006-01-02"))

	// SANs (truncate if too many)
	if len(leaf.SubjectAltNames) > 0 {
		sans := leaf.SubjectAltNames
		if len(sans) > 5 {
			fmt.Printf("  SANs:     %s (+%d more)\n",
				strings.Join(sans[:5], ", "), len(sans)-5)
		} else {
			fmt.Printf("  SANs:     %s\n", strings.Join(sans, ", "))
		}
	}

	// Chain summary
	if len(chain.Certificates) > 1 {
		fmt.Println()
		chainNames := make([]string, len(chain.Certificates))
		for i, cert := range chain.Certificates {
			name := cert.CommonName
			if name == "" {
				name = cert.Subject
			}
			chainNames[i] = name
		}
		fmt.Printf("  Chain: %s (%d certificates)\n",
			strings.Join(chainNames, " → "), len(chain.Certificates))
	}

	return nil
}

func outputVerboseText(chain *tlsquery.ChainInfo, insecure bool) error {
	if insecure {
		fmt.Printf("%s Certificate verification was skipped (insecure mode)\n\n", color.YellowString("⚠"))
	}
	for i, cert := range chain.Certificates {
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
	}
	return nil
}
