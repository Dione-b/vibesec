package finding

import (
	"strings"
)

func FromCSP(policy string, missing bool) []Finding {
	if missing || strings.TrimSpace(policy) == "" {
		return []Finding{New(Options{
			Module:         ModuleCSP,
			ID:             "missing",
			Severity:       SeverityHigh,
			Title:          "Content-Security-Policy missing",
			Description:    "No Content-Security-Policy header was returned.",
			Recommendation: "Deploy a restrictive Content-Security-Policy.",
			CWE:            "CWE-1021",
			OWASP:          "A05:2021",
			CVSS:           6.1,
		})}
	}

	var findings []Finding
	lower := strings.ToLower(policy)
	if strings.Contains(lower, "unsafe-inline") {
		findings = append(findings, New(Options{
			Module:         ModuleCSP,
			ID:             "unsafe-inline",
			Severity:       SeverityMedium,
			Title:          "CSP allows unsafe-inline",
			Description:    "The policy permits inline scripts or styles.",
			Evidence:       truncatePolicy(policy),
			Recommendation: "Remove unsafe-inline and use nonces or hashes.",
			CWE:            "CWE-79",
			OWASP:          "A03:2021",
			CVSS:           5.4,
		}))
	}
	if strings.Contains(lower, "unsafe-eval") {
		findings = append(findings, New(Options{
			Module:         ModuleCSP,
			ID:             "unsafe-eval",
			Severity:       SeverityMedium,
			Title:          "CSP allows unsafe-eval",
			Description:    "The policy permits dynamic code evaluation.",
			Evidence:       truncatePolicy(policy),
			Recommendation: "Remove unsafe-eval from script-src.",
			CWE:            "CWE-95",
			OWASP:          "A03:2021",
			CVSS:           5.4,
		}))
	}
	if strings.Contains(lower, "default-src") && strings.Contains(lower, "*") {
		findings = append(findings, New(Options{
			Module:         ModuleCSP,
			ID:             "wildcard-default",
			Severity:       SeverityMedium,
			Title:          "CSP wildcard in default-src",
			Description:    "The default source list includes a wildcard.",
			Evidence:       truncatePolicy(policy),
			Recommendation: "Replace wildcards with explicit trusted origins.",
			CWE:            "CWE-1021",
			OWASP:          "A05:2021",
			CVSS:           5.0,
		}))
	}
	return findings
}

func truncatePolicy(policy string) string {
	policy = strings.Join(strings.Fields(policy), " ")
	if len(policy) <= 120 {
		return policy
	}
	return policy[:120] + "..."
}
