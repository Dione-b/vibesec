package finding

var headerMappings = map[string]struct {
	CWE    string
	OWASP  string
	CVSS   float64
	Rec    string
}{
	"hsts": {
		CWE: "CWE-319", OWASP: "A02:2021", CVSS: 5.3,
		Rec: "Add Strict-Transport-Security with a long max-age and includeSubDomains.",
	},
	"csp": {
		CWE: "CWE-1021", OWASP: "A05:2021", CVSS: 6.1,
		Rec: "Define a Content-Security-Policy that restricts script and object sources.",
	},
	"xfo": {
		CWE: "CWE-1021", OWASP: "A05:2021", CVSS: 4.3,
		Rec: "Set X-Frame-Options to DENY or SAMEORIGIN, or use CSP frame-ancestors.",
	},
	"referrer-policy": {
		CWE: "CWE-200", OWASP: "A01:2021", CVSS: 3.7,
		Rec: "Set Referrer-Policy to strict-origin-when-cross-origin or stricter.",
	},
	"permissions-policy": {
		CWE: "CWE-200", OWASP: "A05:2021", CVSS: 3.1,
		Rec: "Restrict browser features with Permissions-Policy.",
	},
	"cors": {
		CWE: "CWE-942", OWASP: "A01:2021", CVSS: 6.5,
		Rec: "Avoid wildcard origins with credentials; restrict allowed methods and origins.",
	},
	"cookies-secure": {
		CWE: "CWE-614", OWASP: "A05:2021", CVSS: 5.9,
		Rec: "Set the Secure flag on cookies served over HTTPS.",
	},
	"cookies-httponly": {
		CWE: "CWE-1004", OWASP: "A05:2021", CVSS: 5.4,
		Rec: "Set HttpOnly on session cookies to reduce XSS impact.",
	},
	"cookies-samesite": {
		CWE: "CWE-1275", OWASP: "A05:2021", CVSS: 4.3,
		Rec: "Use SameSite=Lax or Strict; SameSite=None requires Secure.",
	},
}

func severityFromHeaderStatus(status string) string {
	switch status {
	case "FAIL":
		return SeverityHigh
	case "WARNING":
		return SeverityMedium
	default:
		return SeverityInfo
	}
}

type HeaderCheck struct {
	Name   string
	Status string
	Detail string
}

func FromHeaderChecks(checks []HeaderCheck) []Finding {
	var findings []Finding
	for _, check := range checks {
		if check.Status == "PASS" || check.Status == "INFO" {
			continue
		}
		key := slug(check.Name)
		meta := headerMappings[key]
		rec := meta.Rec
		if rec == "" {
			rec = "Review and harden the response header configuration."
		}
		findings = append(findings, New(Options{
			Module:         ModuleHeaders,
			ID:             key,
			Severity:       severityFromHeaderStatus(check.Status),
			Title:          check.Name,
			Description:    check.Detail,
			Evidence:       check.Detail,
			Recommendation: rec,
			CWE:            meta.CWE,
			OWASP:          meta.OWASP,
			CVSS:           meta.CVSS,
		}))
	}
	return findings
}
