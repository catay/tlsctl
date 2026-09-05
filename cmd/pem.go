package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
	"github.com/spf13/cobra"
)

func newPemCmd(rt *Runtime) *cobra.Command {
	var flags certFlags
	var rf revocationFlags
	cmd := &cobra.Command{
		Use:     "pem [FILE | -]",
		Short:   "Inspect certificates from a PEM file or stdin",
		Long:    "Read certificates in PEM order, with the leaf first. Omit FILE or use '-' to read stdin. Verification checks trust and validity without a hostname or server-auth requirement.",
		Example: "  tlsctl pem chain.pem\n  tlsctl pem -o json chain.pem\n  tlsctl pem - < chain.pem\n  tlsctl pem --cacert private-ca.pem chain.pem",
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := flags.validate(); err != nil {
				return err
			}
			if err := rf.validate(); err != nil {
				return err
			}
			source := "stdin"
			if len(args) > 0 && args[0] != "-" {
				source = args[0]
			}
			if len(args) == 0 {
				if file, ok := cmd.InOrStdin().(*os.File); ok {
					stat, err := file.Stat()
					if err != nil || stat.Mode()&os.ModeCharDevice != 0 {
						return fmt.Errorf("no input: provide a FILE argument or pipe PEM data to stdin")
					}
				}
			}
			cmd.SilenceUsage = true
			roots, err := tlsquery.LoadRootCAs(flags.caCertFile)
			if err != nil {
				return err
			}
			opts := tlsquery.PEMOptions{RootCAs: roots}
			var chain *tlsquery.ChainInfo
			if source == "stdin" && (len(args) == 0 || args[0] == "-") {
				var data []byte
				data, err = io.ReadAll(cmd.InOrStdin())
				if err == nil {
					chain, err = tlsquery.ParsePEM(data, opts)
				}
			} else {
				chain, err = tlsquery.ParsePEMFile(source, opts)
			}
			if err == nil {
				chain.InputName, chain.InputLabel = source, "source"
				runRevocationCheck(cmd.Context(), chain, rf)
				if cmd.Context().Err() != nil {
					err = cmd.Context().Err()
				}
			}
			return finishResults(rt, flags, []targetResult{{endpoint: source, chain: chain, err: err}})
		},
	}
	addCertFlags(cmd, &flags)
	addRevocationFlags(cmd, &rf)
	return cmd
}
