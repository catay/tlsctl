package cmd

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/catay/tlsctl/v2/internal/output"
	"github.com/catay/tlsctl/v2/internal/tlsquery"
	"github.com/spf13/cobra"
)

func newPemCmd(rt *Runtime) *cobra.Command {
	var outputFormat string
	var caCertFile string
	var rf revocationFlags

	cmd := &cobra.Command{
		Use:   "pem [FILE | -]",
		Short: "Parse and display certificates from a PEM file or stdin",
		Long:  `Reads a PEM file (or stdin when '-' is given) and displays certificate metadata for all certificates found.`,
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := validateCertFlags(); err != nil {
				return err
			}
			if err := validateRevocationMode(rf.mode); err != nil {
				return err
			}

			opts := tlsquery.PEMOptions{CACertFile: caCertFile}

			var chainInfo *tlsquery.ChainInfo
			var err error

			if len(args) == 0 || args[0] == "-" {
				if len(args) == 0 {
					// No args: require piped stdin
					stat, sErr := os.Stdin.Stat()
					if sErr != nil || stat.Mode()&os.ModeCharDevice != 0 {
						return fmt.Errorf("no input: provide a FILE argument or pipe PEM data to stdin")
					}
				}
				data, rErr := io.ReadAll(os.Stdin)
				if rErr != nil {
					return fmt.Errorf("failed to read stdin: %w", rErr)
				}
				chainInfo, err = tlsquery.ParsePEM(data, opts)
				if err == nil {
					chainInfo.InputName = "stdin"
					chainInfo.InputLabel = "source"
				}
			} else {
				chainInfo, err = tlsquery.ParsePEMFile(args[0], opts)
			}
			if err != nil {
				return err
			}

			if rf.mode != "" {
				runRevocationCheck(chainInfo, rf.mode, rf.timeout, rf.softFail)
			}

			now := rt.NowFunc()
			updateExitCodeForChain(rt.ExitTracker, chainInfo, now, expiryWarningDays)

			renderOpts := output.Options{
				Now:               func() time.Time { return now },
				ExpiryWarningDays: expiryWarningDays,
			}
			if quiet {
				return nil
			}
			return renderChains(rt.Stdout, output.Format(outputFormat), []*tlsquery.ChainInfo{chainInfo}, renderOpts)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: human (default), json, yaml, csv, csv-full, text (verbose), raw (PEM)")
	cmd.Flags().StringVar(&caCertFile, "cacert", "", "Path to CA certificate file (PEM format)")
	addRevocationFlags(cmd, &rf)
	addCertFlags(cmd)

	return cmd
}

func init() {
	rootCmd.AddCommand(newPemCmd(defaultRuntime))
}
