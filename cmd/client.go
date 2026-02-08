package cmd

import (
	"os"
	"time"

	"github.com/catay/tlsctl/internal/cli"
	"github.com/catay/tlsctl/internal/output"
	"github.com/catay/tlsctl/internal/tlsquery"
	"github.com/spf13/cobra"
)

func newClientCmd() *cobra.Command {
	var outputFormat string
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

			opts := tlsquery.QueryOptions{CACertFile: caCertFile, Proxy: proxyURL}
			certInfo, err := tlsquery.Query(endpoint, opts)
			if err != nil {
				return err
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

	return cmd
}

func init() {
	rootCmd.AddCommand(newClientCmd())
}
