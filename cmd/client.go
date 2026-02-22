package cmd

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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
	var inputFile string
	var tlsVersions bool
	var serverName string
	var startTLS string
	var insecure bool
	var rf revocationFlags

	cmd := &cobra.Command{
		Use:   "client FQDN[:PORT] [FQDN[:PORT]...]",
		Short: "Query TLS certificate information for a given endpoint",
		Long:  `Connects to a TLS endpoint and displays certificate metadata.`,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				return nil
			}
			if inputFile != "" {
				return nil
			}
			return fmt.Errorf("must provide at least one endpoint or --file")
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateRevocationMode(rf.mode); err != nil {
				return err
			}

			if startTLS != "" && !tlsquery.ValidStartTLSProtocol(startTLS) {
				return fmt.Errorf("invalid --starttls protocol %q: must be one of smtp, imap, pop3, ldap", startTLS)
			}

			targets, err := collectTargets(args, inputFile, startTLS)
			if err != nil {
				return err
			}

			opts := tlsquery.QueryOptions{
				CACertFile:  caCertFile,
				Proxy:       proxyURL,
				TLSVersions: tlsVersions,
				ServerName:  serverName,
				StartTLS:    startTLS,
				Insecure:    insecure,
			}

			now := time.Now().UTC()
			renderOpts := output.Options{
				Now:               func() time.Time { return now },
				ExpiryWarningDays: expiryWarningDays,
			}

			var chains []*tlsquery.ChainInfo
			var runtimeErrors []error
			for _, endpoint := range targets {
				certInfo, err := tlsquery.Query(endpoint, opts)
				if err != nil {
					runtimeErrors = append(runtimeErrors, fmt.Errorf("%s: %w", endpoint, err))
					continue
				}

				if rf.mode != "off" && rf.mode != "" {
					runRevocationCheck(certInfo, rf.mode, rf.timeout, rf.softFail)
				}

				updateExitCodeForChain(certInfo, now, expiryWarningDays)
				chains = append(chains, certInfo)
			}

			if err := renderChains(os.Stdout, output.Format(outputFormat), chains, renderOpts); err != nil {
				return err
			}

			if len(runtimeErrors) > 0 {
				for _, err := range runtimeErrors {
					fmt.Fprintln(os.Stderr, err)
				}
				setExitCode(ExitRuntimeError)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: json, yaml, text (verbose), raw (PEM)")
	cmd.Flags().StringVar(&caCertFile, "cacert", "", "Path to CA certificate file (PEM format)")
	cmd.Flags().StringVarP(&proxyURL, "proxy", "x", "", "Proxy URL (e.g. http://proxy:8080). Falls back to HTTPS_PROXY/HTTP_PROXY env vars if not set")
	cmd.Flags().StringVar(&inputFile, "file", "", "Read endpoints from file (one per line, '-' for stdin)")
	cmd.Flags().BoolVar(&tlsVersions, "tls-versions", false, "Probe and display supported TLS versions")
	cmd.Flags().StringVar(&serverName, "servername", "", "Override the SNI server name sent in the TLS handshake")
	cmd.Flags().StringVar(&startTLS, "starttls", "", "Use STARTTLS for the given protocol: smtp, imap, pop3, ldap")
	cmd.Flags().BoolVarP(&insecure, "insecure", "k", false, "Skip TLS certificate verification")
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

func collectTargets(args []string, inputFile string, startTLSProto ...string) ([]string, error) {
	var targets []string
	if inputFile != "" {
		fileTargets, err := readTargetsFromFile(inputFile)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fileTargets...)
	}

	targets = append(targets, args...)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no endpoints provided")
	}

	proto := ""
	if len(startTLSProto) > 0 {
		proto = startTLSProto[0]
	}

	normalized := make([]string, 0, len(targets))
	for _, raw := range targets {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		endpoint, err := cli.NormalizeEndpoint(value, proto)
		if err != nil {
			return nil, fmt.Errorf("invalid endpoint %q: %w", value, err)
		}
		normalized = append(normalized, endpoint)
	}

	if len(normalized) == 0 {
		return nil, fmt.Errorf("no valid endpoints found")
	}

	return normalized, nil
}

func readTargetsFromFile(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read endpoints file: %w", err)
		}
		defer file.Close()
		r = file
	}

	var targets []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read endpoints file: %w", err)
	}
	return targets, nil
}

func renderChains(w io.Writer, format output.Format, chains []*tlsquery.ChainInfo, opts output.Options) error {
	if len(chains) == 0 {
		return nil
	}

	renderer, err := output.New(format)
	if err != nil {
		return err
	}

	if len(chains) > 1 {
		if mr, ok := renderer.(output.MultiRenderer); ok {
			return mr.RenderAll(w, chains, opts)
		}
	}

	for i, chain := range chains {
		if i > 0 && format != output.FormatRaw {
			fmt.Fprintln(w)
		}
		if err := renderer.Render(w, chain, opts); err != nil {
			return err
		}
	}
	return nil
}

func init() {
	rootCmd.AddCommand(newClientCmd())
}
