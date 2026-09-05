package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	"github.com/catay/tlsctl/v2/internal/config"
	"github.com/catay/tlsctl/v2/internal/output"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

const (
	minExpiryWarningDays = 1
	maxExpiryWarningDays = 10000
)

var defaultNoColor = color.NoColor

type certFlags struct {
	quiet             bool
	expiryWarningDays int
	outputFormat      string
	caCertFile        string
}

func addCertFlags(cmd *cobra.Command, flags *certFlags) {
	cmd.Flags().BoolVarP(&flags.quiet, "quiet", "q", false, "Suppress stdout; preserve errors and exit codes")
	cmd.Flags().IntVar(&flags.expiryWarningDays, "expiry-warning", 30, "Warn when expiry is within this many days (1-10000)")
	cmd.Flags().StringVarP(&flags.outputFormat, "output", "o", "human", "Output format: human, json, yaml, csv, csv-full, text, raw")
	cmd.Flags().StringVar(&flags.caCertFile, "cacert", "", "Add trusted CA certificates from a PEM file")
	registerChoices(cmd, "output", []string{"human", "json", "yaml", "csv", "csv-full", "text", "raw"})
}
func (f certFlags) validate() error {
	if f.expiryWarningDays < minExpiryWarningDays || f.expiryWarningDays > maxExpiryWarningDays {
		return fmt.Errorf("--expiry-warning must be between %d and %d", minExpiryWarningDays, maxExpiryWarningDays)
	}
	_, err := output.New(output.Format(f.outputFormat))
	return err
}
func registerChoices(cmd *cobra.Command, flag string, choices []string) {
	// Each flag is registered once by its owning command constructor.
	_ = cmd.RegisterFlagCompletionFunc(flag, func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return choices, cobra.ShellCompDirectiveNoFileComp
	})
}
func loadAndApplyConfig(cmd *cobra.Command, path string) error {
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
	for name, value := range settings.FlagValues(cmd.Name()) {
		if f := cmd.Flag(name); f != nil && !f.Changed {
			if err := f.Value.Set(value); err != nil {
				return fmt.Errorf("config: invalid value for %s: %w", name, err)
			}
		}
	}
	return nil
}
func Execute() {
	rt := NewRuntime()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	stopRead := context.AfterFunc(ctx, func() { _ = os.Stdin.Close() })
	err := newRootCmd(rt).ExecuteContext(ctx)
	stopRead()
	stop()
	if err != nil {
		os.Exit(ExitRuntimeError)
	}
	if code := rt.ExitTracker.Code(); code != 0 {
		os.Exit(code)
	}
}
func newRootCmd(rt *Runtime) *cobra.Command {
	var configPath string
	var noColor bool
	root := &cobra.Command{
		Use:     "tlsctl",
		Short:   "Inspect TLS certificates from endpoints, PEM files, or stdin",
		Example: "  tlsctl client example.com\n  tlsctl client -o json example.com mail.example.com:443\n  tlsctl pem chain.pem",
	}
	// Cobra writes usage after execution errors through the root output stream.
	// Keep diagnostics on stderr; help and completion explicitly use stdout.
	root.SetOut(rt.Stderr)
	root.SetErr(rt.Stderr)
	root.SetIn(rt.Stdin)
	help := root.HelpFunc()
	root.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		cmd.SetOut(rt.Stdout)
		help(cmd, args)
	})
	root.PersistentFlags().StringVar(&configPath, "config", "", "Configuration file (default: OS-specific tlsctl/settings.json)")
	root.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")
	root.PersistentPreRunE = func(cmd *cobra.Command, args []string) error {
		cmd.SetOut(rt.Stdout)
		if cmd.Name() == cobra.ShellCompRequestCmd {
			// Dynamic completions write through the command being completed.
			root.SetOut(rt.Stdout)
		}
		rt.ExitTracker.Reset()
		if cmd.Name() == "client" || cmd.Name() == "pem" {
			if err := loadAndApplyConfig(cmd, configPath); err != nil {
				cmd.SilenceUsage = true
				return err
			}
		}
		color.NoColor = defaultNoColor || noColor
		return nil
	}
	root.AddCommand(newClientCmd(rt), newPemCmd(rt), newVersionCmd(rt))
	// Cobra captures this writer when constructing completion generators.
	root.SetOut(rt.Stdout)
	root.InitDefaultCompletionCmd()
	root.SetOut(rt.Stderr)
	return root
}
