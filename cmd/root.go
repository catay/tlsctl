package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tlsctl",
	Short: "A CLI tool for TLS certificate operations",
	Long:  `tlsctl provides commands for querying and inspecting TLS certificates.`,
}

var exitCode int

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
