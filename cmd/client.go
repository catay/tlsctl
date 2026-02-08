package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/catay/tlsctl/internal/cli"
	"github.com/catay/tlsctl/internal/output"
	"github.com/catay/tlsctl/internal/tlsquery"
)

func newClientCmd() *cobra.Command {
	var outputFormat string
	var insecureMode bool
	var caCertFile string
	var proxyURL string

	cmd := &cobra.Command{
		Use:   "client FQDN[:PORT]",
		Short: "Query TLS certificate information for a given endpoint",
		Long:  `Connects to a TLS endpoint and displays certificate metadata.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			endpoint, err := cli.NormalizeEndpoint(args[0])
			if err != nil {
				return err
			}

			opts := tlsquery.QueryOptions{Insecure: insecureMode, CACertFile: caCertFile, Proxy: proxyURL}
			certInfo, err := tlsquery.Query(endpoint, opts)
			if err != nil {
				return err
			}

			renderer, err := output.New(output.Format(outputFormat))
			if err != nil {
				return err
			}

			renderOpts := output.Options{
				Insecure: insecureMode,
				Now:      time.Now,
			}
			return renderer.Render(os.Stdout, certInfo, renderOpts)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: json, yaml, text (verbose), raw (PEM)")
	cmd.Flags().BoolVarP(&insecureMode, "insecure", "k", false, "Skip certificate verification (insecure)")
	cmd.Flags().StringVar(&caCertFile, "cacert", "", "Path to CA certificate file (PEM format)")
	cmd.Flags().StringVarP(&proxyURL, "proxy", "x", "", "Proxy URL (e.g. http://proxy:8080). Falls back to HTTPS_PROXY/HTTP_PROXY env vars if not set")

	return cmd
}

func init() {
	rootCmd.AddCommand(newClientCmd())
}
