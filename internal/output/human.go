package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/catay/tlsctl/internal/tlsquery"
	"github.com/fatih/color"
)

type HumanRenderer struct{}

func (HumanRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	leaf, err := chain.Leaf()
	if err != nil {
		return err
	}

	notAfter, err := leaf.NotAfterTime()
	if err != nil {
		return fmt.Errorf("failed to parse expiry date: %w", err)
	}
	notBefore, err := leaf.NotBeforeTime()
	if err != nil {
		return fmt.Errorf("failed to parse start date: %w", err)
	}

	now := opts.NowFunc()
	daysUntilExpiry := int(notAfter.Sub(now).Hours() / 24)

	bold := color.New(color.Bold)
	var status, statusMsg string
	switch {
	case now.After(notAfter):
		status = bold.Add(color.FgRed).Sprint("✗")
		statusMsg = "expired"
	case opts.Insecure:
		status = bold.Add(color.FgYellow).Sprint("⚠")
		statusMsg = fmt.Sprintf("insecure, expires in %d days", daysUntilExpiry)
	case daysUntilExpiry <= 30:
		status = bold.Add(color.FgYellow).Sprint("⚠")
		statusMsg = fmt.Sprintf("expires in %d days", daysUntilExpiry)
	default:
		status = bold.Add(color.FgGreen).Sprint("✓")
		statusMsg = fmt.Sprintf("expires in %d days", daysUntilExpiry)
	}

	displayName := leaf.DisplayName()

	fmt.Fprintf(w, "%s (%s) %s\n", displayName, statusMsg, status)
	fmt.Fprintf(w, "  Subject:  %s\n", leaf.Subject)
	fmt.Fprintf(w, "  Issuer:   %s\n", leaf.Issuer)
	fmt.Fprintf(w, "  Validity: %s → %s\n",
		notBefore.Format("2006-01-02"),
		notAfter.Format("2006-01-02"))

	if len(leaf.SubjectAltNames) > 0 {
		sans := leaf.SubjectAltNames
		if len(sans) > 5 {
			fmt.Fprintf(w, "  SANs:     %s (+%d more)\n",
				strings.Join(sans[:5], ", "), len(sans)-5)
		} else {
			fmt.Fprintf(w, "  SANs:     %s\n", strings.Join(sans, ", "))
		}
	}

	if len(chain.Certificates) > 1 {
		fmt.Fprintln(w)
		chainNames := chain.ChainNames()
		fmt.Fprintf(w, "  Chain: %s (%d certificates)\n",
			strings.Join(chainNames, " → "), len(chain.Certificates))
	}

	return nil
}
