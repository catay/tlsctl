package cmd

import (
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tlsctl",
	Short: "A CLI tool for TLS certificate operations",
	Long:  `tlsctl provides commands for querying and inspecting TLS certificates.`,
}

var exitCode int
var noColor bool

func init() {
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if noColor {
			color.NoColor = true
		}
	}
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	if exitCode != 0 {
		os.Exit(exitCode)
	}
}
