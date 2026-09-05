package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/catay/tlsctl/v2/internal/tlsquery"
	"github.com/fatih/color"
)

type HumanRenderer struct{}

func (HumanRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	out := &checkedWriter{writer: w}
	w = out
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

	health := chain.Health(now, opts.WarningDays())
	expiryMsg := formatExpiryMsg(daysUntilExpiry, now.After(notAfter))
	status, label := "✓", health.Status
	statusColor := color.FgGreen
	switch health.Status {
	case "insecure", "revocation_error":
		status, statusColor = "✗", color.FgRed
	case "expiring":
		status, statusColor = "⚠", color.FgYellow
	}
	if leaf.Revocation != nil && leaf.Revocation.OverallStatus != "good" && leaf.Revocation.OverallStatus != "revoked" && leaf.Revocation.OverallStatus != "error" {
		if health.Status == "secure" {
			status, statusColor = "⚠", color.FgYellow
		}
	}
	statusMsg := color.New(color.Bold, statusColor).Sprint(label)
	if health.Reason != "" && health.Status != "expiring" {
		statusMsg += ", " + health.Reason
	}
	statusMsg += ", " + expiryMsg
	status = color.New(color.Bold, statusColor).Sprint(status)
	if chain.InputName != "" {
		fmt.Fprintf(w, "%s: %s\n", inputLabel(chain), chain.InputName)
	}

	displayName := leaf.DisplayName()

	fmt.Fprintf(w, "%s (%s) %s\n", displayName, statusMsg, status)
	fmt.Fprintf(w, "  Subject:    %s\n", leaf.Subject)
	fmt.Fprintf(w, "  Issuer:     %s\n", leaf.Issuer)
	fmt.Fprintf(w, "  Validity:   %s → %s\n",
		notBefore.UTC().Format("2006-01-02"),
		notAfter.UTC().Format("2006-01-02"))
	if chain.NegotiatedTLS != nil {
		fmt.Fprintf(w, "  Handshake:  %s\n", formatHandshakeSummary(chain.NegotiatedTLS))
	}

	if len(leaf.SubjectAltNames) > 0 {
		sans := leaf.SubjectAltNames
		if len(sans) > 5 {
			fmt.Fprintf(w, "  SANs:       %s (+%d more)\n",
				strings.Join(sans[:5], ", "), len(sans)-5)
		} else {
			fmt.Fprintf(w, "  SANs:       %s\n", strings.Join(sans, ", "))
		}
	}

	if len(leaf.IPAddresses) > 0 {
		fmt.Fprintf(w, "  IPs:        %s\n", strings.Join(leaf.IPAddresses, ", "))
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
		fmt.Fprintf(w, "  TLS:        %s\n", strings.Join(versions, ", "))
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

	return out.err
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

func inputLabel(chain *tlsquery.ChainInfo) string {
	if chain.InputLabel == "source" {
		return "Source"
	}
	return "Target"
}
