package output

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/catay/tlsctl/internal/revocation"
	"github.com/catay/tlsctl/internal/tlsquery"
	"github.com/fatih/color"
)

type VerboseTextRenderer struct{}

func (VerboseTextRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	if !chain.Verified {
		reason := chain.VerificationError
		if reason == "" {
			reason = "unverified"
		}
		fmt.Fprintf(w, "%s Certificate verification failed: %s\n\n", color.YellowString("⚠"), reason)
	}
	if len(chain.TLSVersions) > 0 {
		versions := make([]string, len(chain.TLSVersions))
		for i, v := range chain.TLSVersions {
			versions[i] = v.Version
		}
		fmt.Fprintf(w, "TLS Versions:          %s\n", strings.Join(versions, ", "))
		for _, v := range chain.TLSVersions {
			secureCipherSuites, insecureCipherSuites := cipherSuitesBySecurity(v)

			if len(secureCipherSuites) > 0 {
				fmt.Fprintf(w, "Secure Cipher Suites (%s):\n", v.Version)
				for _, cs := range secureCipherSuites {
					fmt.Fprintf(w, "  %s\n", cs)
				}
			}
			if len(insecureCipherSuites) > 0 {
				fmt.Fprintf(w, "Insecure Cipher Suites (%s):\n", v.Version)
				for _, cs := range insecureCipherSuites {
					fmt.Fprintf(w, "  %s\n", cs)
				}
			}
		}
		fmt.Fprintln(w)
	}

	for i, cert := range chain.Certificates {
		if i > 0 {
			fmt.Fprintln(w)
		}
		renderCertFields(w, &cert)
		if cert.Revocation != nil {
			renderRevocation(w, cert.Revocation)
		}
	}
	return nil
}

func renderCertFields(w io.Writer, cert *tlsquery.CertInfo) {
	fmt.Fprintf(w, "[%s]\n", strings.ToUpper(cert.Type))
	fmt.Fprintf(w, "Version:               %d\n", cert.Version)
	fmt.Fprintf(w, "Serial Number:         %s\n", cert.SerialNumber)
	fmt.Fprintf(w, "Signature Algorithm:   %s\n", cert.SignatureAlgorithm)
	fmt.Fprintf(w, "Issuer:                %s\n", cert.Issuer)
	fmt.Fprintf(w, "Subject:               %s\n", cert.Subject)
	fmt.Fprintf(w, "Not Before:            %s\n", cert.NotBefore)
	fmt.Fprintf(w, "Not After:             %s\n", cert.NotAfter)
	fmt.Fprintf(w, "Public Key Algorithm:  %s\n", cert.PublicKeyAlgorithm)
	if cert.KeyLength > 0 {
		fmt.Fprintf(w, "Key Length:            %d bits\n", cert.KeyLength)
	}
	if len(cert.KeyUsage) > 0 {
		fmt.Fprintf(w, "Key Usage:             %s\n", strings.Join(cert.KeyUsage, ", "))
	}
	if len(cert.ExtKeyUsage) > 0 {
		fmt.Fprintf(w, "Extended Key Usage:    %s\n", strings.Join(cert.ExtKeyUsage, ", "))
	}
	if cert.BasicConstraints != nil {
		if cert.BasicConstraints.IsCA {
			fmt.Fprintf(w, "Basic Constraints:     CA:TRUE, pathlen:%d\n", cert.BasicConstraints.MaxPathLen)
		} else {
			fmt.Fprintf(w, "Basic Constraints:     CA:FALSE\n")
		}
	}
	if cert.SubjectKeyID != "" {
		fmt.Fprintf(w, "Subject Key ID:        %s\n", cert.SubjectKeyID)
	}
	if cert.AuthorityKeyID != "" {
		fmt.Fprintf(w, "Authority Key ID:      %s\n", cert.AuthorityKeyID)
	}
	if len(cert.SubjectAltNames) > 0 {
		fmt.Fprintf(w, "Subject Alt Names:     %s\n", strings.Join(cert.SubjectAltNames, ", "))
	}
	if len(cert.EmailAddresses) > 0 {
		fmt.Fprintf(w, "Email Addresses:       %s\n", strings.Join(cert.EmailAddresses, ", "))
	}
	if len(cert.IPAddresses) > 0 {
		fmt.Fprintf(w, "IP Addresses:          %s\n", strings.Join(cert.IPAddresses, ", "))
	}
	if len(cert.OCSPServers) > 0 {
		fmt.Fprintf(w, "OCSP Servers:          %s\n", strings.Join(cert.OCSPServers, ", "))
	}
	if len(cert.IssuingCertURL) > 0 {
		fmt.Fprintf(w, "CA Issuers:            %s\n", strings.Join(cert.IssuingCertURL, ", "))
	}
	if len(cert.CRLDistPoints) > 0 {
		fmt.Fprintf(w, "CRL Distribution:      %s\n", strings.Join(cert.CRLDistPoints, ", "))
	}
}

func renderRevocation(w io.Writer, rev *revocation.Info) {
	fmt.Fprintf(w, "Revocation Status:     %s\n", strings.ToUpper(string(rev.OverallStatus)))
	if rev.CheckedAt != "" {
		fmt.Fprintf(w, "Revocation Checked:    %s\n", rev.CheckedAt)
	}
	for _, r := range rev.Results {
		fmt.Fprintf(w, "  Method:              %s\n", string(r.Method))
		fmt.Fprintf(w, "  Status:              %s\n", string(r.Status))
		if r.ResponderURL != "" {
			fmt.Fprintf(w, "  Responder URL:       %s\n", r.ResponderURL)
		}
		if r.RevokedAt != nil {
			fmt.Fprintf(w, "  Revoked At:          %s\n", r.RevokedAt.UTC().Format(time.RFC3339))
		}
		if r.Reason != "" {
			fmt.Fprintf(w, "  Reason:              %s\n", r.Reason)
		}
		if r.Error != "" {
			fmt.Fprintf(w, "  Error:               %s\n", r.Error)
		}
	}
}
