package cmd

import (
	"fmt"
	"os"

	"github.com/catay/tlsctl/v2/internal/config"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	minExpiryWarningDays = 1
	maxExpiryWarningDays = 10000
)

var defaultRuntime = NewRuntime()

var rootCmd = newRootCmd()
var configPath string
var noColor bool
var quiet bool
var expiryWarningDays int

func addCertFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "Suppress informational and warning output")
	cmd.Flags().IntVar(&expiryWarningDays, "expiry-warning", 30,
		fmt.Sprintf("Number of days before expiry to trigger a warning (%d-%d)", minExpiryWarningDays, maxExpiryWarningDays))
}

func validateCertFlags() error {
	if expiryWarningDays < minExpiryWarningDays || expiryWarningDays > maxExpiryWarningDays {
		return fmt.Errorf("--expiry-warning must be between %d and %d", minExpiryWarningDays, maxExpiryWarningDays)
	}
	return nil
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "Path to configuration file (default: OS-specific config dir)")
	rootCmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	rootCmd.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		if err := loadAndApplyConfig(cmd); err != nil {
			return err
		}
		if noColor {
			color.NoColor = true
		}
		return nil
	}
}

func loadAndApplyConfig(cmd *cobra.Command) error {
	path := configPath
	explicit := path != ""
	if !explicit {
		var err error
		path, err = config.DefaultPath()
		if err != nil {
			return err
		}
	}

	settings, err := config.Load(path, explicit)
	if err != nil {
		return err
	}

	subcmd := cmd.Name()
	vals := settings.FlagValues(subcmd)
	for name, value := range vals {
		f := cmd.Flag(name)
		if f == nil {
			continue
		}
		if !f.Changed {
			if err := f.Value.Set(value); err != nil {
				return fmt.Errorf("config: invalid value for %s: %w", name, err)
			}
		}
	}
	return nil
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	if code := defaultRuntime.ExitTracker.Code(); code != 0 {
		os.Exit(code)
	}
}

func newRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tlsctl",
		Short: "A CLI tool for TLS certificate operations",
		Long:  `tlsctl provides commands for querying and inspecting TLS certificates.`,
	}
}
