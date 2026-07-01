package finding

import "fmt"

const ModuleAuth = "auth"

func FromAuth(result *AuthSnapshot) []Finding {
	if result == nil {
		return nil
	}

	var findings []Finding
	for i, signal := range result.Signals {
		if signal.Status == "PASS" || signal.Status == "INFO" {
			continue
		}
		meta := authMappings[signal.Category]
		findings = append(findings, New(Options{
			Module:         ModuleAuth,
			ID:             slug(signal.Category) + "-" + slug(signal.Status) + "-" + fmt.Sprintf("%d", i),
			Severity:       authSeverity(signal.Status),
			Title:          signal.Category + " issue",
			Description:    signal.Detail,
			Evidence:       signal.Detail,
			Recommendation: meta.Rec,
			CWE:            meta.CWE,
			OWASP:          meta.OWASP,
			CVSS:           meta.CVSS,
		}))
	}
	return findings
}

type AuthSnapshot struct {
	Signals []AuthSignal
}

type AuthSignal struct {
	Category string
	Status   string
	Detail   string
}

var authMappings = map[string]struct {
	CWE   string
	OWASP string
	CVSS  float64
	Rec   string
}{
	"Cookies": {
		CWE: "CWE-614", OWASP: "A05:2021", CVSS: 5.9,
		Rec: "Harden session cookies with Secure, HttpOnly, and SameSite.",
	},
	"JWT": {
		CWE: "CWE-922", OWASP: "A02:2021", CVSS: 5.4,
		Rec: "Store tokens in HttpOnly cookies; avoid localStorage for JWT.",
	},
	"CSRF": {
		CWE: "CWE-352", OWASP: "A01:2021", CVSS: 6.5,
		Rec: "Implement CSRF tokens on state-changing requests.",
	},
	"Roles": {
		CWE: "CWE-602", OWASP: "A01:2021", CVSS: 5.4,
		Rec: "Enforce authorization on the server; never trust client-side roles.",
	},
	"Session": {
		CWE: "CWE-384", OWASP: "A07:2021", CVSS: 4.3,
		Rec: "Regenerate session IDs after login and use Cache-Control: no-store.",
	},
	"Refresh": {
		CWE: "CWE-287", OWASP: "A07:2021", CVSS: 6.1,
		Rec: "Protect token refresh endpoints; require POST with authentication.",
	},
}

func authSeverity(status string) string {
	switch status {
	case "FAIL":
		return SeverityHigh
	case "WARNING":
		return SeverityMedium
	default:
		return SeverityInfo
	}
}
