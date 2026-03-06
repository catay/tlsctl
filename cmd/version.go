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
		Run: func(cmd *cobra.Command, args []string) {
			out := io.Writer(os.Stdout)
			if rt != nil && rt.Stdout != nil {
				out = rt.Stdout
			}
			fmt.Fprintf(out, "tlsctl version %s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}

func init() {
	rootCmd.AddCommand(newVersionCmd(defaultRuntime))
}
