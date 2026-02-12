package cmd

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/catay/tlsctl/internal/cli"
	"github.com/catay/tlsctl/internal/output"
	"github.com/catay/tlsctl/internal/revocation"
	"github.com/catay/tlsctl/internal/tlsquery"
	"github.com/spf13/cobra"
)

type revocationFlags struct {
	mode     string
	timeout  time.Duration
	softFail bool
}

var validRevocationModes = map[string]bool{
	"off":  true,
	"crl":  true,
	"ocsp": true,
}

func addRevocationFlags(cmd *cobra.Command, rf *revocationFlags) {
	cmd.Flags().StringVar(&rf.mode, "revocation", "off", "Revocation check mode: off, crl, ocsp")
	cmd.Flags().DurationVar(&rf.timeout, "revocation-timeout", 5*time.Second, "Timeout for revocation checks")
	cmd.Flags().BoolVar(&rf.softFail, "revocation-soft-fail", true, "Treat revocation check errors as unknown (soft-fail)")
}

func validateRevocationMode(mode string) error {
	if !validRevocationModes[mode] {
		return fmt.Errorf("invalid revocation mode %q: must be one of off, crl, ocsp", mode)
	}
	return nil
}

func newClientCmd() *cobra.Command {
	var outputFormat string
	var caCertFile string
	var proxyURL string
	var rf revocationFlags

	cmd := &cobra.Command{
		Use:   "client FQDN[:PORT]",
		Short: "Query TLS certificate information for a given endpoint",
		Long:  `Connects to a TLS endpoint and displays certificate metadata.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRevocationMode(rf.mode); err != nil {
				return err
			}

			endpoint, err := cli.NormalizeEndpoint(args[0])
			if err != nil {
				return err
			}

			opts := tlsquery.QueryOptions{CACertFile: caCertFile, Proxy: proxyURL}
			certInfo, err := tlsquery.Query(endpoint, opts)
			if err != nil {
				return err
			}

			if rf.mode != "off" && rf.mode != "" {
				runRevocationCheck(certInfo, rf.mode, rf.timeout, rf.softFail)
			}

			renderer, err := output.New(output.Format(outputFormat))
			if err != nil {
				return err
			}

			renderOpts := output.Options{
				Now: time.Now,
			}
			return renderer.Render(os.Stdout, certInfo, renderOpts)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: json, yaml, text (verbose), raw (PEM)")
	cmd.Flags().StringVar(&caCertFile, "cacert", "", "Path to CA certificate file (PEM format)")
	cmd.Flags().StringVarP(&proxyURL, "proxy", "x", "", "Proxy URL (e.g. http://proxy:8080). Falls back to HTTPS_PROXY/HTTP_PROXY env vars if not set")
	addRevocationFlags(cmd, &rf)

	return cmd
}

func runRevocationCheck(chain *tlsquery.ChainInfo, mode string, timeout time.Duration, softFail bool) {
	if len(chain.Certificates) == 0 {
		return
	}

	leaf, err := tlsquery.ParseCertPEM(chain.Certificates[0].PEM)
	if err != nil {
		return
	}

	var issuer *x509.Certificate
	if len(chain.Certificates) > 1 {
		issuer, _ = tlsquery.ParseCertPEM(chain.Certificates[1].PEM)
	}

	var methods []revocation.Method
	switch mode {
	case "crl":
		methods = []revocation.Method{revocation.MethodCRL}
	case "ocsp":
		methods = []revocation.Method{revocation.MethodOCSP}
	}

	checker := revocation.NewChecker(&http.Client{Timeout: timeout}, nil)
	opts := revocation.Options{
		Methods:  methods,
		Timeout:  timeout,
		SoftFail: softFail,
	}

	result := checker.CheckCert(leaf, issuer, opts)
	chain.Certificates[0].Revocation = result
}

func init() {
	rootCmd.AddCommand(newClientCmd())
}
