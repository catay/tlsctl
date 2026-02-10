package revocation

import (
	"net/http"
	"net/url"
	"time"
)

type Method string

const (
	MethodCRL        Method = "crl"
	MethodOCSPStaple Method = "ocsp_staple"
	MethodOCSP       Method = "ocsp"
)

type Status string

const (
	StatusGood       Status = "good"
	StatusRevoked    Status = "revoked"
	StatusUnknown    Status = "unknown"
	StatusNotChecked Status = "not_checked"
	StatusError      Status = "error"
)

type Result struct {
	Method       Method
	Status       Status
	ResponderURL string
	RevokedAt    *time.Time
	Reason       string
	Error        string
}

type Options struct {
	Methods  []Method
	Timeout  time.Duration
	SoftFail bool
	Now      func() time.Time
	Proxy    *url.URL
}

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type RevocationInfo struct {
	OverallStatus string             `json:"overall_status" yaml:"overall_status"`
	CheckedAt     string             `json:"checked_at,omitempty" yaml:"checked_at,omitempty"`
	Results       []RevocationResult `json:"results,omitempty" yaml:"results,omitempty"`
}

type RevocationResult struct {
	Method       string `json:"method" yaml:"method"`
	Status       string `json:"status" yaml:"status"`
	ResponderURL string `json:"responder_url,omitempty" yaml:"responder_url,omitempty"`
	RevokedAt    string `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
	Reason       string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Error        string `json:"error,omitempty" yaml:"error,omitempty"`
}
