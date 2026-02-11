package revocation

import (
	"net/http"
	"net/url"
	"time"
)

type Method string

const (
	MethodCRL  Method = "crl"
	MethodOCSP Method = "ocsp"
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
	Method       Method     `json:"method" yaml:"method"`
	Status       Status     `json:"status" yaml:"status"`
	ResponderURL string     `json:"responder_url,omitempty" yaml:"responder_url,omitempty"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty" yaml:"revoked_at,omitempty"`
	Reason       string     `json:"reason,omitempty" yaml:"reason,omitempty"`
	Error        string     `json:"error,omitempty" yaml:"error,omitempty"`
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

type Info struct {
	OverallStatus Status   `json:"overall_status" yaml:"overall_status"`
	CheckedAt     string   `json:"checked_at,omitempty" yaml:"checked_at,omitempty"`
	Results       []Result `json:"results,omitempty" yaml:"results,omitempty"`
}
