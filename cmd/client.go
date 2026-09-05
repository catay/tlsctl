package cmd

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/catay/tlsctl/v2/internal/cli"
	"github.com/catay/tlsctl/v2/internal/output"
	"github.com/catay/tlsctl/v2/internal/revocation"
	"github.com/catay/tlsctl/v2/internal/tlsquery"
	"github.com/spf13/cobra"
)

type revocationFlags struct {
	mode     string
	timeout  time.Duration
	softFail bool
}
type connectionFlags struct {
	connectTimeout   time.Duration
	handshakeTimeout time.Duration
}

func addRevocationFlags(cmd *cobra.Command, rf *revocationFlags) {
	cmd.Flags().StringVar(&rf.mode, "revocation", "", "Check leaf revocation: crl, ocsp (disabled by default)")
	cmd.Flags().DurationVar(&rf.timeout, "revocation-timeout", 5*time.Second, "Timeout per revocation request")
	cmd.Flags().BoolVar(&rf.softFail, "revocation-soft-fail", true, "Report unavailable revocation checks without failing solely for uncertainty")
	registerChoices(cmd, "revocation", []string{"crl", "ocsp"})
}
func addConnectionFlags(cmd *cobra.Command, cf *connectionFlags) {
	cmd.Flags().DurationVar(&cf.connectTimeout, "connect-timeout", tlsquery.DefaultConnectTimeout, "Timeout for establishing each TCP connection")
	cmd.Flags().DurationVar(&cf.handshakeTimeout, "handshake-timeout", tlsquery.DefaultHandshakeTimeout, "Timeout for each proxy negotiation or STARTTLS/TLS handshake")
}
func validateRevocationMode(mode string) error {
	switch mode {
	case "", "crl", "ocsp":
		return nil
	}
	return fmt.Errorf("invalid revocation mode %q: must be one of crl, ocsp", mode)
}
func (rf revocationFlags) validate() error {
	if err := validateRevocationMode(rf.mode); err != nil {
		return err
	}
	if rf.timeout <= 0 {
		return fmt.Errorf("--revocation-timeout must be greater than 0")
	}
	return nil
}
func validateConnectionTimeouts(cf connectionFlags) error {
	if cf.connectTimeout <= 0 {
		return fmt.Errorf("--connect-timeout must be greater than 0")
	}
	if cf.handshakeTimeout <= 0 {
		return fmt.Errorf("--handshake-timeout must be greater than 0")
	}
	return nil
}
func newClientCmd(rt *Runtime) *cobra.Command {
	var flags certFlags
	var proxyURL, inputFile, alpnProtocols, serverName, startTLS string
	var tlsVersions bool
	var concurrency int
	var timeout time.Duration
	var rf revocationFlags
	var cf connectionFlags
	cmd := &cobra.Command{
		Use:     "client HOST[:PORT] [HOST[:PORT]...]",
		Short:   "Inspect TLS certificates from one or more endpoints",
		Long:    "Connect to TLS endpoints and inspect their certificates. The default port is 443, or the protocol port with --starttls.",
		Example: "  tlsctl client example.com\n  tlsctl client --file hosts.txt -o json\n  tlsctl client --starttls smtp mail.example.com\n  tlsctl client --servername example.com 192.0.2.1:443",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flags.validate(); err != nil {
				return err
			}
			if err := rf.validate(); err != nil {
				return err
			}
			if err := validateConnectionTimeouts(cf); err != nil {
				return err
			}
			if concurrency < 1 || concurrency > 256 {
				return fmt.Errorf("--concurrency must be between 1 and 256")
			}
			if timeout <= 0 {
				return fmt.Errorf("--timeout must be greater than 0")
			}
			if len(args) == 0 && inputFile == "" {
				return fmt.Errorf("must provide at least one endpoint or --file")
			}
			if startTLS != "" && !tlsquery.ValidStartTLSProtocol(startTLS) {
				return fmt.Errorf("invalid --starttls protocol %q: must be one of %s", startTLS, tlsquery.StartTLSProtocolList())
			}
			alpn, err := tlsquery.ParseALPNProtocols(alpnProtocols)
			if err != nil {
				return fmt.Errorf("invalid --alpn value: %w", err)
			}
			if err := tlsquery.ValidateProxy(proxyURL); err != nil {
				return err
			}
			targets, err := collectTargets(args, inputFile, startTLS, cmd.InOrStdin())
			if err != nil {
				return err
			}
			cmd.SilenceUsage = true
			roots, err := tlsquery.LoadRootCAs(flags.caCertFile)
			if err != nil {
				return err
			}
			opts := tlsquery.QueryOptions{RootCAs: roots, Proxy: proxyURL, TLSVersions: tlsVersions, ALPNProtocols: alpn,
				ServerName: serverName, StartTLS: startTLS, ConnectTimeout: cf.connectTimeout, HandshakeTimeout: cf.handshakeTimeout}
			results := queryTargets(cmd.Context(), targets, opts, concurrency, timeout, func(ctx context.Context, chain *tlsquery.ChainInfo) {
				runRevocationCheck(ctx, chain, rf)
			})
			return finishResults(rt, flags, results)
		},
	}
	cmd.Flags().StringVarP(&proxyURL, "proxy", "x", "", "HTTP(S) proxy URL; defaults to HTTPS_PROXY with NO_PROXY exclusions")
	cmd.Flags().StringVar(&inputFile, "file", "", "Read endpoints from a file (one per line, '-' for stdin)")
	cmd.Flags().BoolVar(&tlsVersions, "tls-versions", false, "Probe TLS versions and cipher suites implemented by Go")
	cmd.Flags().StringVar(&alpnProtocols, "alpn", "", "Comma-separated ALPN protocols to advertise (e.g. h2,http/1.1)")
	cmd.Flags().StringVar(&serverName, "servername", "", "Override the SNI and certificate verification hostname")
	cmd.Flags().StringVar(&startTLS, "starttls", "", "Upgrade to TLS using: "+tlsquery.StartTLSProtocolList())
	cmd.Flags().IntVar(&concurrency, "concurrency", 8, "Maximum number of targets queried concurrently (1-256)")
	cmd.Flags().DurationVar(&timeout, "timeout", time.Minute, "Overall timeout per target, including probes and revocation")
	registerChoices(cmd, "starttls", tlsquery.StartTLSProtocols())
	addRevocationFlags(cmd, &rf)
	addConnectionFlags(cmd, &cf)
	addCertFlags(cmd, &flags)
	return cmd
}

func runRevocationCheck(ctx context.Context, chain *tlsquery.ChainInfo, flags revocationFlags) {
	if flags.mode == "" || len(chain.Certificates) == 0 {
		return
	}
	leaf, issuer := chain.RevocationCertificates()
	checker := revocation.NewChecker(&http.Client{Timeout: flags.timeout}, nil)
	chain.Certificates[0].Revocation = checker.CheckCert(leaf, issuer, revocation.Options{
		Context: ctx, Methods: []revocation.Method{revocation.Method(flags.mode)}, Timeout: flags.timeout, SoftFail: flags.softFail,
	})
}

type targetJob struct {
	index    int
	endpoint string
}
type targetResult struct {
	endpoint string
	chain    *tlsquery.ChainInfo
	err      error
}

// Each worker owns a distinct result slot. Results retain input order.
func queryTargets(ctx context.Context, targets []string, opts tlsquery.QueryOptions, concurrency int, timeout time.Duration, revoke func(context.Context, *tlsquery.ChainInfo)) []targetResult {
	results := make([]targetResult, len(targets))
	jobs := make(chan targetJob)
	var wg sync.WaitGroup
	for i := 0; i < min(concurrency, len(targets)); i++ {
		wg.Go(func() {
			for job := range jobs {
				targetCtx, cancel := context.WithTimeout(ctx, timeout)
				chain, err := tlsquery.QueryContext(targetCtx, job.endpoint, opts)
				if err == nil && revoke != nil {
					revoke(targetCtx, chain)
				}
				if err == nil && targetCtx.Err() != nil {
					err = targetCtx.Err()
				}
				cancel()
				results[job.index] = targetResult{endpoint: job.endpoint, chain: chain, err: err}
			}
		})
	}
	for index, endpoint := range targets {
		jobs <- targetJob{index, endpoint}
	}
	close(jobs)
	wg.Wait()
	return results
}

func collectTargets(args []string, inputFile, startTLSProto string, stdin ...io.Reader) ([]string, error) {
	var targets []string
	if inputFile != "" {
		fileTargets, err := readTargetsFromFile(inputFile, stdin...)
		if err != nil {
			return nil, err
		}
		targets = append(targets, fileTargets...)
	}

	targets = append(targets, args...)
	if len(targets) == 0 {
		return nil, fmt.Errorf("no endpoints provided")
	}

	normalized := make([]string, 0, len(targets))
	for _, raw := range targets {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		endpoint, err := cli.NormalizeEndpoint(value, startTLSProto)
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

func readTargetsFromFile(path string, stdin ...io.Reader) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
		if len(stdin) > 0 && stdin[0] != nil {
			r = stdin[0]
		}
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
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
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

func finishResults(rt *Runtime, flags certFlags, results []targetResult) error {
	now := rt.NowFunc()
	for _, result := range results {
		if result.err != nil {
			rt.ExitTracker.Set(ExitRuntimeError)
		} else {
			updateExitCodeForChain(rt.ExitTracker, result.chain, now, flags.expiryWarningDays)
		}
	}
	renderedErrors := false
	if !flags.quiet {
		var err error
		renderedErrors, err = renderTargetResults(rt.Stdout, output.Format(flags.outputFormat), results,
			output.Options{Now: func() time.Time { return now }, ExpiryWarningDays: flags.expiryWarningDays})
		if err != nil {
			return fmt.Errorf("write output: %w", err)
		}
	}
	if !renderedErrors {
		for _, result := range results {
			if result.err != nil {
				if _, err := fmt.Fprintf(rt.Stderr, "%s: %v\n", result.endpoint, result.err); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
func renderChains(w io.Writer, format output.Format, chains []*tlsquery.ChainInfo, opts output.Options) error {
	renderer, err := output.New(format)
	if err != nil {
		return err
	}
	if len(chains) == 0 {
		return nil
	}
	if mr, ok := renderer.(output.MultiRenderer); ok {
		return mr.RenderAll(w, chains, opts)
	}
	for i, chain := range chains {
		if i > 0 && format != output.FormatRaw {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
		}
		if err := renderer.Render(w, chain, opts); err != nil {
			return err
		}
	}
	return nil
}
func renderTargetResults(w io.Writer, format output.Format, results []targetResult, opts output.Options) (bool, error) {
	renderer, err := output.New(format)
	if err != nil {
		return false, err
	}
	if batch, ok := renderer.(output.BatchRenderer); ok {
		return true, batch.RenderBatch(w, toOutputTargetResults(results), opts)
	}
	var chains []*tlsquery.ChainInfo
	for _, result := range results {
		if result.err == nil {
			chains = append(chains, result.chain)
		}
	}
	return false, renderChains(w, format, chains, opts)
}
func toOutputTargetResults(results []targetResult) []output.TargetResult {
	batch := make([]output.TargetResult, len(results))
	for i, result := range results {
		batch[i].Target = result.endpoint
		if result.err != nil {
			batch[i].Error = result.err.Error()
		} else {
			batch[i].Result = result.chain
		}
	}
	return batch
}
