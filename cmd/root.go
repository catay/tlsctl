package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	minExpiryWarningDays = 1
	maxExpiryWarningDays = 10000
)

var rootCmd = &cobra.Command{
	Use:   "tlsctl",
	Short: "A CLI tool for TLS certificate operations",
	Long:  `tlsctl provides commands for querying and inspecting TLS certificates.`,
}

var exitCode int
var noColor bool
var quiet bool
var expiryWarningDays int

func init() {
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Suppress informational and warning output")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentFlags().IntVar(&expiryWarningDays, "expiry-warning", 30,
		fmt.Sprintf("Number of days before expiry to trigger a warning (%d-%d)", minExpiryWarningDays, maxExpiryWarningDays))
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if noColor {
			color.NoColor = true
		}
		if expiryWarningDays < minExpiryWarningDays || expiryWarningDays > maxExpiryWarningDays {
			return fmt.Errorf("--expiry-warning must be between %d and %d", minExpiryWarningDays, maxExpiryWarningDays)
		}
		return nil
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
