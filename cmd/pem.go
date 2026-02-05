package cmd

import (
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/tlsctl/internal/output"
	"github.com/tlsctl/internal/tlsquery"
)

func newPemCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "pem FILE",
		Short: "Parse and display certificates from a PEM file",
		Long:  `Reads a PEM file and displays certificate metadata for all certificates found.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			chainInfo, err := tlsquery.ParsePEMFile(args[0])
			if err != nil {
				return err
			}

			renderer, err := output.New(output.Format(outputFormat))
			if err != nil {
				return err
			}

			renderOpts := output.Options{
				Insecure: false,
				Now:      time.Now,
			}
			return renderer.Render(os.Stdout, chainInfo, renderOpts)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: json, yaml, text (verbose), raw (PEM)")

	return cmd
}

func init() {
	rootCmd.AddCommand(newPemCmd())
}
