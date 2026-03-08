package output

import "github.com/catay/tlsctl/internal/tlsquery"

func cipherSuitesBySecurity(version tlsquery.TLSVersionInfo) (secure []string, insecure []string) {
	if len(version.SecureCipherSuites) > 0 || len(version.InsecureCipherSuites) > 0 {
		return version.SecureCipherSuites, version.InsecureCipherSuites
	}
	return tlsquery.SplitCipherSuitesBySecurity(version.CipherSuites)
}

func cipherSuiteSet(cipherSuites []string) map[string]struct{} {
	set := make(map[string]struct{}, len(cipherSuites))
	for _, cs := range cipherSuites {
		set[cs] = struct{}{}
	}
	return set
}
