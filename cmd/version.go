package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func newVersionCmd(rt *Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			out := io.Writer(os.Stdout)
			if rt != nil && rt.Stdout != nil {
				out = rt.Stdout
			}
			_, err := fmt.Fprintf(out, "tlsctl version %s (commit: %s, built: %s)\n", version, commit, date)
			return err
		},
	}
}
