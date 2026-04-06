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

	expiryMsg := formatExpiryMsg(daysUntilExpiry, now.After(notAfter))

	switch {
	case !chain.Verified:
		status = bold.Add(color.FgRed).Sprint("✗")
		reason := chain.VerificationError
		if reason == "" {
			reason = "unverified"
		}
		label := color.New(color.Bold, color.FgRed).Sprint("insecure")
		statusMsg = fmt.Sprintf("%s, %s, %s", label, reason, expiryMsg)
	case now.After(notAfter):
		status = bold.Add(color.FgRed).Sprint("✗")
		statusMsg = expiryMsg
	case daysUntilExpiry <= opts.WarningDays():
		status = bold.Add(color.FgYellow).Sprint("⚠")
		label := color.New(color.Bold, color.FgYellow).Sprint("secure")
		statusMsg = fmt.Sprintf("%s, expires in %d days", label, daysUntilExpiry)
	default:
		status = bold.Add(color.FgGreen).Sprint("✓")
		label := color.New(color.Bold, color.FgGreen).Sprint("secure")
		statusMsg = fmt.Sprintf("%s, expires in %d days", label, daysUntilExpiry)
	}

	displayName := leaf.DisplayName()

	fmt.Fprintf(w, "%s (%s) %s\n", displayName, statusMsg, status)
	fmt.Fprintf(w, "  Subject:  %s\n", leaf.Subject)
	fmt.Fprintf(w, "  Issuer:   %s\n", leaf.Issuer)
	fmt.Fprintf(w, "  Validity: %s → %s\n",
		notBefore.UTC().Format("2006-01-02"),
		notAfter.UTC().Format("2006-01-02"))
	if chain.NegotiatedTLS != nil {
		fmt.Fprintf(w, "  Handshake: %s\n", formatHandshakeSummary(chain.NegotiatedTLS))
	}

	if len(leaf.SubjectAltNames) > 0 {
		sans := leaf.SubjectAltNames
		if len(sans) > 5 {
			fmt.Fprintf(w, "  SANs:     %s (+%d more)\n",
				strings.Join(sans[:5], ", "), len(sans)-5)
		} else {
			fmt.Fprintf(w, "  SANs:     %s\n", strings.Join(sans, ", "))
		}
	}

	if leaf.Revocation != nil {
		method := ""
		if len(leaf.Revocation.Results) > 0 {
			method = string(leaf.Revocation.Results[0].Method)
		}
		revLabel := formatRevocationLabel(string(leaf.Revocation.OverallStatus), method)
		fmt.Fprintf(w, "  Revocation: %s\n", revLabel)
	}

	if len(chain.TLSVersions) > 0 {
		versions := make([]string, len(chain.TLSVersions))
		for i, v := range chain.TLSVersions {
			versions[i] = v.Version
		}
		fmt.Fprintf(w, "  TLS:      %s\n", strings.Join(versions, ", "))
		for _, v := range chain.TLSVersions {
			secureCipherSuites, insecureCipherSuites := cipherSuitesBySecurity(v)
			cipherSuites := v.CipherSuites
			if len(cipherSuites) == 0 {
				cipherSuites = append(cipherSuites, secureCipherSuites...)
				cipherSuites = append(cipherSuites, insecureCipherSuites...)
			}

			if len(cipherSuites) > 0 {
				insecureSet := cipherSuiteSet(insecureCipherSuites)

				fmt.Fprintf(w, "  Ciphers (%s):\n", v.Version)
				for _, cs := range cipherSuites {
					if _, insecure := insecureSet[cs]; insecure {
						fmt.Fprintf(w, "    %s\n", color.RedString(cs+" (insecure)"))
						continue
					}
					fmt.Fprintf(w, "    %s\n", color.GreenString(cs))
				}
			}
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

func formatHandshakeSummary(info *tlsquery.HandshakeInfo) string {
	if info == nil {
		return ""
	}

	parts := make([]string, 0, 3)
	if info.TLSVersion != "" {
		parts = append(parts, info.TLSVersion)
	}
	if info.CipherSuite != "" {
		parts = append(parts, info.CipherSuite)
	}
	if info.ALPN != "" {
		parts = append(parts, info.ALPN)
	}
	return strings.Join(parts, " / ")
}

func formatExpiryMsg(days int, expired bool) string {
	if expired {
		daysAgo := -days
		if daysAgo == 1 {
			return "expired 1 day ago"
		}
		return fmt.Sprintf("expired %d days ago", daysAgo)
	}
	if days == 1 {
		return "expires in 1 day"
	}
	return fmt.Sprintf("expires in %d days", days)
}

func formatRevocationLabel(status, method string) string {
	suffix := ""
	if method != "" {
		suffix = " (" + strings.ToUpper(method) + ")"
	}
	switch status {
	case "good":
		return color.GreenString("not revoked") + suffix
	case "revoked":
		return color.RedString("REVOKED") + suffix
	case "unknown":
		return color.YellowString("unknown") + suffix
	case "not_checked":
		return "not checked"
	case "not_supported":
		return color.YellowString("not supported") + suffix
	case "error":
		return color.RedString("error") + suffix
	default:
		return status
	}
}
