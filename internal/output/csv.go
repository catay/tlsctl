package output

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/catay/tlsctl/internal/tlsquery"
)

type CSVRenderer struct{}

type CSVFullRenderer struct{}

func (CSVRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	return renderCSVSummary(w, []*tlsquery.ChainInfo{chain}, opts)
}

func (CSVRenderer) RenderAll(w io.Writer, chains []*tlsquery.ChainInfo, opts Options) error {
	return renderCSVSummary(w, chains, opts)
}

func (CSVRenderer) RenderBatch(w io.Writer, results []TargetResult, opts Options) error {
	return renderCSVSummaryBatch(w, results, opts)
}

func (CSVFullRenderer) Render(w io.Writer, chain *tlsquery.ChainInfo, opts Options) error {
	return renderCSVFull(w, []*tlsquery.ChainInfo{chain})
}

func (CSVFullRenderer) RenderAll(w io.Writer, chains []*tlsquery.ChainInfo, opts Options) error {
	return renderCSVFull(w, chains)
}

func (CSVFullRenderer) RenderBatch(w io.Writer, results []TargetResult, opts Options) error {
	return renderCSVFullBatch(w, results, opts)
}

func renderCSVSummary(w io.Writer, chains []*tlsquery.ChainInfo, opts Options) error {
	headers := []string{
		csvInputHeader(chains),
		"common_name",
		"issuer",
		"not_before",
		"not_after",
		"days_remaining",
		"sha256",
		"subject_alternative_names",
	}

	writer := csv.NewWriter(w)
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, chain := range chains {
		if chain == nil {
			continue
		}
		leaf, err := chain.Leaf()
		if err != nil {
			return err
		}
		record, err := csvSummaryRow(chain, leaf, opts)
		if err != nil {
			return err
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}

func renderCSVSummaryBatch(w io.Writer, results []TargetResult, opts Options) error {
	headers := csvSummaryBatchHeaders(opts)

	writer := csv.NewWriter(w)
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, result := range results {
		record, err := csvSummaryBatchRow(result, opts)
		if err != nil {
			return err
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	writer.Flush()
	return writer.Error()
}

func csvSummaryRow(chain *tlsquery.ChainInfo, leaf *tlsquery.CertInfo, opts Options) ([]string, error) {
	notAfter, err := leaf.NotAfterTime()
	if err != nil {
		return nil, fmt.Errorf("failed to parse expiry date: %w", err)
	}

	daysRemaining := int(notAfter.Sub(opts.NowFunc()).Hours() / 24)

	return []string{
		csvInputValue(chain),
		leaf.CommonName,
		leaf.Issuer,
		leaf.NotBefore,
		leaf.NotAfter,
		strconv.Itoa(daysRemaining),
		leaf.Fingerprint.SHA256,
		csvJoin(leaf.SubjectAltNames),
	}, nil
}

func csvSummaryBatchRow(result TargetResult, opts Options) ([]string, error) {
	record := csvSummaryBatchPrefix(result, opts)

	if result.Result == nil {
		return append(record, "", "", "", "", "", "", ""), nil
	}

	leaf, err := result.Result.Leaf()
	if err != nil {
		return nil, err
	}

	summary, err := csvSummaryRow(result.Result, leaf, opts)
	if err != nil {
		return nil, err
	}

	return append(record, summary[1:]...), nil
}

func renderCSVFull(w io.Writer, chains []*tlsquery.ChainInfo) error {
	headers := csvFullHeaders(csvInputHeader(chains))

	writer := csv.NewWriter(w)
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, chain := range chains {
		if chain == nil {
			continue
		}
		for certIndex := range chain.Certificates {
			if err := writer.Write(csvFullRow(certIndex, chain, &chain.Certificates[certIndex])); err != nil {
				return err
			}
		}
	}

	writer.Flush()
	return writer.Error()
}

func renderCSVFullBatch(w io.Writer, results []TargetResult, opts Options) error {
	headers := append(csvBatchPrefixHeaders(opts), csvFullHeaders("target")[1:]...)

	writer := csv.NewWriter(w)
	if err := writer.Write(headers); err != nil {
		return err
	}

	for _, result := range results {
		if result.Result == nil {
			record := csvSummaryBatchPrefix(result, opts)
			record = append(record, make([]string, len(headers)-len(record))...)
			if err := writer.Write(record); err != nil {
				return err
			}
			continue
		}

		for certIndex := range result.Result.Certificates {
			record := csvSummaryBatchPrefix(result, opts)
			record = append(record, csvFullFieldsRow(certIndex, result.Result, &result.Result.Certificates[certIndex])...)
			if err := writer.Write(record); err != nil {
				return err
			}
		}
	}

	writer.Flush()
	return writer.Error()
}

func csvSummaryBatchHeaders(opts Options) []string {
	return append(csvBatchPrefixHeaders(opts),
		"common_name",
		"issuer",
		"not_before",
		"not_after",
		"days_remaining",
		"sha256",
		"subject_alternative_names",
	)
}

func csvBatchPrefixHeaders(opts Options) []string {
	if opts.FormatVersionOrDefault() >= 2 {
		return []string{"target", "status", "tls_status", "error"}
	}
	return []string{"target", "ok", "error"}
}

func csvSummaryBatchPrefix(result TargetResult, opts Options) []string {
	if opts.FormatVersionOrDefault() >= 2 {
		return []string{
			result.Target,
			string(result.Status()),
			string(result.TLSStatus(opts)),
			result.Error,
		}
	}
	return []string{
		result.Target,
		strconv.FormatBool(result.OK()),
		result.Error,
	}
}

func csvFullHeaders(inputHeader string) []string {
	return []string{
		inputHeader,
		"certificate_index",
		"certificate_type",
		"chain",
		"verified",
		"verification_error",
		"version",
		"serial_number",
		"signature_algorithm",
		"issuer",
		"subject",
		"common_name",
		"not_before",
		"not_after",
		"public_key_algorithm",
		"key_length",
		"key_usage",
		"extended_key_usage",
		"basic_constraints_is_ca",
		"basic_constraints_max_path_len",
		"subject_key_id",
		"authority_key_id",
		"subject_alternative_names",
		"email_addresses",
		"ip_addresses",
		"ocsp_servers",
		"issuing_cert_url",
		"crl_distribution_points",
		"fingerprint_sha1",
		"fingerprint_sha256",
		"tls_versions",
		"secure_cipher_suites",
		"insecure_cipher_suites",
		"revocation_status",
		"revocation_checked_at",
	}
}

func csvFullRow(certIndex int, chain *tlsquery.ChainInfo, cert *tlsquery.CertInfo) []string {
	return append([]string{csvInputValue(chain)}, csvFullFieldsRow(certIndex, chain, cert)...)
}

func csvFullFieldsRow(certIndex int, chain *tlsquery.ChainInfo, cert *tlsquery.CertInfo) []string {
	basicConstraintsIsCA := ""
	basicConstraintsMaxPathLen := ""
	if cert.BasicConstraints != nil {
		basicConstraintsIsCA = strconv.FormatBool(cert.BasicConstraints.IsCA)
		basicConstraintsMaxPathLen = strconv.Itoa(cert.BasicConstraints.MaxPathLen)
	}

	revocationStatus := ""
	revocationCheckedAt := ""
	if cert.Revocation != nil {
		revocationStatus = string(cert.Revocation.OverallStatus)
		revocationCheckedAt = cert.Revocation.CheckedAt
	}

	return []string{
		strconv.Itoa(certIndex),
		cert.Type,
		strings.Join(chain.ChainNames(), " -> "),
		strconv.FormatBool(chain.Verified),
		chain.VerificationError,
		strconv.Itoa(cert.Version),
		cert.SerialNumber,
		cert.SignatureAlgorithm,
		cert.Issuer,
		cert.Subject,
		cert.CommonName,
		cert.NotBefore,
		cert.NotAfter,
		cert.PublicKeyAlgorithm,
		strconv.Itoa(cert.KeyLength),
		csvJoin(cert.KeyUsage),
		csvJoin(cert.ExtKeyUsage),
		basicConstraintsIsCA,
		basicConstraintsMaxPathLen,
		cert.SubjectKeyID,
		cert.AuthorityKeyID,
		csvJoin(cert.SubjectAltNames),
		csvJoin(cert.EmailAddresses),
		csvJoin(cert.IPAddresses),
		csvJoin(cert.OCSPServers),
		csvJoin(cert.IssuingCertURL),
		csvJoin(cert.CRLDistPoints),
		cert.Fingerprint.SHA1,
		cert.Fingerprint.SHA256,
		csvTLSVersions(chain.TLSVersions),
		csvCipherSuites(chain.TLSVersions, func(version tlsquery.TLSVersionInfo) []string {
			return version.SecureCipherSuites
		}),
		csvCipherSuites(chain.TLSVersions, func(version tlsquery.TLSVersionInfo) []string {
			return version.InsecureCipherSuites
		}),
		revocationStatus,
		revocationCheckedAt,
	}
}

func csvInputHeader(chains []*tlsquery.ChainInfo) string {
	if len(chains) == 0 {
		return "input"
	}

	header := ""
	for _, chain := range chains {
		if chain == nil || chain.InputLabel == "" {
			return "input"
		}
		if header == "" {
			header = chain.InputLabel
			continue
		}
		if chain.InputLabel != header {
			return "input"
		}
	}

	if header == "" {
		return "input"
	}
	return header
}

func csvInputValue(chain *tlsquery.ChainInfo) string {
	if chain == nil {
		return ""
	}
	return chain.InputName
}

func csvJoin(values []string) string {
	return strings.Join(values, "; ")
}

func csvTLSVersions(versions []tlsquery.TLSVersionInfo) string {
	names := make([]string, 0, len(versions))
	for _, version := range versions {
		if version.Version == "" {
			continue
		}
		names = append(names, version.Version)
	}
	return csvJoin(names)
}

func csvCipherSuites(versions []tlsquery.TLSVersionInfo, suites func(tlsquery.TLSVersionInfo) []string) string {
	var flattened []string
	for _, version := range versions {
		for _, suite := range suites(version) {
			flattened = append(flattened, version.Version+": "+suite)
		}
	}
	return csvJoin(flattened)
}
