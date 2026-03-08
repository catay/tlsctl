package tlsquery

import "crypto/tls"

var secureCipherSuiteNames = cipherSuiteNameSet(tls.CipherSuites())
var insecureCipherSuiteNames = cipherSuiteNameSet(tls.InsecureCipherSuites())

func cipherSuiteNameSet(suites []*tls.CipherSuite) map[string]struct{} {
	names := make(map[string]struct{}, len(suites))
	for _, cs := range suites {
		names[cs.Name] = struct{}{}
	}
	return names
}

// IsCipherSuiteSecure reports whether a cipher suite name is currently
// considered secure by Go's crypto/tls package.
func IsCipherSuiteSecure(name string) bool {
	if _, ok := secureCipherSuiteNames[name]; ok {
		return true
	}
	if _, ok := insecureCipherSuiteNames[name]; ok {
		return false
	}
	return false
}

// SplitCipherSuitesBySecurity splits cipher suites into secure and insecure
// slices while preserving the input order within each slice.
func SplitCipherSuitesBySecurity(cipherSuites []string) (secure []string, insecure []string) {
	secure = make([]string, 0, len(cipherSuites))
	insecure = make([]string, 0, len(cipherSuites))
	for _, cs := range cipherSuites {
		if IsCipherSuiteSecure(cs) {
			secure = append(secure, cs)
			continue
		}
		insecure = append(insecure, cs)
	}
	return secure, insecure
}
