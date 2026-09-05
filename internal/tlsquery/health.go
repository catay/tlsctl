package tlsquery

import (
	"time"

	"github.com/catay/tlsctl/v2/internal/revocation"
)

// Health is the shared certificate assessment used by output and exit codes.
// Secure describes certificate validation, not a complete TLS security audit.
type Health struct {
	Status string
	Reason string
}

func (c *ChainInfo) Health(now time.Time, warningDays int) Health {
	leaf, err := c.Leaf()
	if err != nil {
		return Health{"insecure", err.Error()}
	}
	if leaf.Revocation != nil {
		switch leaf.Revocation.OverallStatus {
		case revocation.StatusRevoked:
			return Health{"insecure", "certificate revoked"}
		case revocation.StatusError:
			return Health{"revocation_error", "revocation check failed"}
		}
	}
	if !c.Verified {
		reason := c.VerificationError
		if reason == "" {
			reason = "unverified"
		}
		return Health{"insecure", reason}
	}
	before, err := leaf.NotBeforeTime()
	if err != nil {
		return Health{"insecure", "invalid certificate start date"}
	}
	if now.Before(before) {
		return Health{"insecure", "certificate not yet valid"}
	}
	after, err := leaf.NotAfterTime()
	if err != nil {
		return Health{"insecure", "invalid certificate expiry date"}
	}
	if now.After(after) {
		return Health{"insecure", "certificate expired"}
	}
	if warningDays <= 0 {
		warningDays = 30
	}
	if after.Sub(now) <= time.Duration(warningDays)*24*time.Hour {
		return Health{"expiring", "certificate expires soon"}
	}
	return Health{"secure", ""}
}
