package cmd

import (
	"github.com/spf13/cobra"
	"github.com/tlsctl/internal/tlsquery"
)

var pemOutputFormat string
var pemShowPEM bool

var pemCmd = &cobra.Command{
	Use:   "pem FILE",
	Short: "Parse and display certificates from a PEM file",
	Long:  `Reads a PEM file and displays certificate metadata for all certificates found.`,
	Args:  cobra.ExactArgs(1),
	RunE:  runPem,
}

func init() {
	rootCmd.AddCommand(pemCmd)
	pemCmd.Flags().StringVarP(&pemOutputFormat, "output", "o", "text", "Output format (text, json, yaml)")
	pemCmd.Flags().BoolVar(&pemShowPEM, "show-pem", false, "Include PEM-encoded certificate in output")
}

func runPem(cmd *cobra.Command, args []string) error {
	chainInfo, err := tlsquery.ParsePEMFile(args[0])
	if err != nil {
		return err
	}

	return outputChain(chainInfo, pemOutputFormat, pemShowPEM)
}
