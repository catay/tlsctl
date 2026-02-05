package tlsquery

import "time"

func (ci *CertInfo) NotAfterTime() (time.Time, error) {
	return time.Parse(time.RFC3339, ci.NotAfter)
}

func (ci *CertInfo) NotBeforeTime() (time.Time, error) {
	return time.Parse(time.RFC3339, ci.NotBefore)
}

func (ci *CertInfo) DisplayName() string {
	if ci.CommonName != "" {
		return ci.CommonName
	}
	if len(ci.SubjectAltNames) > 0 {
		return ci.SubjectAltNames[0]
	}
	if ci.Subject != "" {
		return ci.Subject
	}
	return "(unknown)"
}
