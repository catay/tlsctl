package cmd

import (
	"bufio"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
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

func addRevocationFlags(cmd *cobra.Command, rf *revocationFlags) {
	cmd.Flags().StringVar(&rf.mode, "revocation", "", "Revocation check mode: crl, ocsp")
	cmd.Flags().DurationVar(&rf.timeout, "revocation-timeout", 5*time.Second, "Timeout for revocation checks")
	cmd.Flags().BoolVar(&rf.softFail, "revocation-soft-fail", true, "Treat revocation check errors as unknown (soft-fail)")
}

func validateRevocationMode(mode string) error {
	if mode == "" {
		return nil
	}
	switch mode {
	case "crl", "ocsp":
		return nil
	default:
		return fmt.Errorf("invalid revocation mode %q: must be one of crl, ocsp", mode)
	}
}

func newClientCmd(rt *Runtime) *cobra.Command {
	var outputFormat string
	var formatVersion int
	var caCertFile string
	var proxyURL string
	var inputFile string
	var tlsVersions bool
	var serverName string
	var startTLS string
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
			if err := validateCertFlags(); err != nil {
				return err
			}
			if err := validateRevocationMode(rf.mode); err != nil {
				return err
			}
			if err := validateOutputFormatVersion(output.Format(outputFormat), formatVersion); err != nil {
				return err
			}

			if startTLS != "" && !tlsquery.ValidStartTLSProtocol(startTLS) {
				return fmt.Errorf("invalid --starttls protocol %q: must be one of %s", startTLS, tlsquery.StartTLSProtocolList())
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
			}

			now := rt.NowFunc()
			renderOpts := output.Options{
				Now:               func() time.Time { return now },
				ExpiryWarningDays: expiryWarningDays,
				FormatVersion:     formatVersion,
			}

			var revocationFn func(*tlsquery.ChainInfo)
			if rf.mode != "" {
				revocationFn = func(chain *tlsquery.ChainInfo) {
					runRevocationCheck(chain, rf.mode, rf.timeout, rf.softFail)
				}
			}

			results := queryTargets(targets, opts, revocationFn)
			var runtimeErrors []error
			for _, result := range results {
				if result.err != nil {
					runtimeErrors = append(runtimeErrors, fmt.Errorf("%s: %w", result.endpoint, result.err))
					continue
				}
				updateExitCodeForChain(rt.ExitTracker, result.chain, now, expiryWarningDays)
			}

			renderedRuntimeErrors := false
			if !quiet {
				var err error
				renderedRuntimeErrors, err = renderTargetResults(rt.Stdout, output.Format(outputFormat), results, renderOpts)
				if err != nil {
					return err
				}
			}

			if len(runtimeErrors) > 0 {
				if quiet || !renderedRuntimeErrors {
					for _, err := range runtimeErrors {
						fmt.Fprintln(rt.Stderr, err)
					}
				}
				rt.ExitTracker.Set(ExitRuntimeError)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: human (default), json, yaml, csv, csv-full, text (verbose), raw (PEM)")
	cmd.Flags().IntVar(&formatVersion, "format-version", 1, "Structured output format version for client json, yaml, csv, or csv-full output")
	cmd.Flags().StringVar(&caCertFile, "cacert", "", "Path to CA certificate file (PEM format)")
	cmd.Flags().StringVarP(&proxyURL, "proxy", "x", "", "Proxy URL (e.g. http://proxy:8080). Falls back to HTTPS_PROXY/HTTP_PROXY env vars if not set")
	cmd.Flags().StringVar(&inputFile, "file", "", "Read endpoints from file (one per line, '-' for stdin)")
	cmd.Flags().BoolVar(&tlsVersions, "tls-versions", false, "Probe and display supported TLS versions")
	cmd.Flags().StringVar(&serverName, "servername", "", "Override the SNI server name sent in the TLS handshake")
	cmd.Flags().StringVar(&startTLS, "starttls", "", "Use STARTTLS for the given protocol: "+tlsquery.StartTLSProtocolList())
	addRevocationFlags(cmd, &rf)
	addCertFlags(cmd)

	return cmd
}

func validateOutputFormatVersion(format output.Format, version int) error {
	if version < 1 || version > 2 {
		return fmt.Errorf("--format-version must be 1 or 2")
	}
	if version == 1 {
		return nil
	}
	switch format {
	case output.FormatJSON, output.FormatYAML, output.FormatCSV, output.FormatCSVFull:
		return nil
	default:
		return fmt.Errorf("--format-version 2 is only supported with --output json, yaml, csv, or csv-full")
	}
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

type targetJob struct {
	index    int
	endpoint string
}

type targetResult struct {
	index    int
	endpoint string
	chain    *tlsquery.ChainInfo
	err      error
}

func queryTargets(targets []string, opts tlsquery.QueryOptions, revocationFn func(*tlsquery.ChainInfo)) []targetResult {
	results := make([]targetResult, len(targets))
	if len(targets) == 0 {
		return results
	}

	workerCount := runtime.GOMAXPROCS(0)
	if workerCount < 1 {
		workerCount = 1
	}
	if workerCount > len(targets) {
		workerCount = len(targets)
	}

	jobs := make(chan targetJob)
	resultCh := make(chan targetResult, workerCount)
	var wg sync.WaitGroup

	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				chain, err := tlsquery.Query(job.endpoint, opts)
				if err == nil && revocationFn != nil {
					revocationFn(chain)
				}
				resultCh <- targetResult{
					index:    job.index,
					endpoint: job.endpoint,
					chain:    chain,
					err:      err,
				}
			}
		}()
	}

	go func() {
		for index, endpoint := range targets {
			jobs <- targetJob{index: index, endpoint: endpoint}
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	for result := range resultCh {
		results[result.index] = result
	}

	return results
}

func collectTargets(args []string, inputFile, startTLSProto string) ([]string, error) {
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

func renderTargetResults(w io.Writer, format output.Format, results []targetResult, opts output.Options) (bool, error) {
	if len(results) == 0 {
		return false, nil
	}

	renderer, err := output.New(format)
	if err != nil {
		return false, err
	}

	if opts.FormatVersionOrDefault() >= 2 {
		if batchRenderer, ok := renderer.(output.BatchRenderer); ok {
			return true, batchRenderer.RenderBatch(w, toOutputTargetResults(results), opts)
		}
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
		batch[i] = output.TargetResult{
			Target: result.endpoint,
		}
		if result.err != nil {
			batch[i].Error = result.err.Error()
			continue
		}
		batch[i].Result = result.chain
	}
	return batch
}

func init() {
	rootCmd.AddCommand(newClientCmd(defaultRuntime))
}
