package cmd

import (
	"os"
	"time"

	"github.com/catay/tlsctl/internal/output"
	"github.com/catay/tlsctl/internal/tlsquery"
	"github.com/spf13/cobra"
)

func newPemCmd() *cobra.Command {
	var outputFormat string
	var caCertFile string
	var rf revocationFlags

	cmd := &cobra.Command{
		Use:   "pem FILE",
		Short: "Parse and display certificates from a PEM file",
		Long:  `Reads a PEM file and displays certificate metadata for all certificates found.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := tlsquery.PEMOptions{CACertFile: caCertFile}
			chainInfo, err := tlsquery.ParsePEMFile(args[0], opts)
			if err != nil {
				return err
			}

			if rf.mode != "off" && rf.mode != "" {
				runRevocationCheck(chainInfo, rf.mode, rf.timeout, rf.softFail)
			}

			renderer, err := output.New(output.Format(outputFormat))
			if err != nil {
				return err
			}

			renderOpts := output.Options{
				Now: time.Now,
			}
			return renderer.Render(os.Stdout, chainInfo, renderOpts)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: json, yaml, text (verbose), raw (PEM)")
	cmd.Flags().StringVar(&caCertFile, "cacert", "", "Path to CA certificate file (PEM format)")
	addRevocationFlags(cmd, &rf)

	return cmd
}

func init() {
	rootCmd.AddCommand(newPemCmd())
}
