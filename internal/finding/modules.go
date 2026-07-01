package finding

import (
	"fmt"
	"strings"
)

type FingerprintSnapshot struct {
	Stack      []string
	Infra      []string
	TLSVersion string
}

func FromFingerprint(result *FingerprintSnapshot) []Finding {
	if result == nil {
		return nil
	}
	var findings []Finding
	if len(result.Stack) > 0 {
		findings = append(findings, New(Options{
			Module:      ModuleFingerprint,
			ID:          "stack",
			Severity:    SeverityInfo,
			Title:       "Technology stack identified",
			Description: "Probable technologies were inferred from headers, cookies, and page content.",
			Evidence:    strings.Join(result.Stack, ", "),
		}))
	}
	if isWeakTLS(result.TLSVersion) {
		findings = append(findings, New(Options{
			Module:         ModuleFingerprint,
			ID:             "weak-tls",
			Severity:       SeverityMedium,
			Title:          "Weak TLS version",
			Description:    "The server negotiates a deprecated TLS version.",
			Evidence:       result.TLSVersion,
			Recommendation: "Disable TLS 1.0 and TLS 1.1; prefer TLS 1.2+.",
			CWE:            "CWE-326",
			OWASP:          "A02:2021",
			CVSS:           5.9,
		}))
	}
	return findings
}

func isWeakTLS(version string) bool {
	v := strings.ToUpper(version)
	return strings.Contains(v, "TLS 1.0") || strings.Contains(v, "TLS 1.1")
}

type BundleSnapshot struct {
	Secrets    []string
	AdminPages []string
	Libraries  []string
}

func FromBundle(result *BundleSnapshot) []Finding {
	if result == nil {
		return nil
	}
	var findings []Finding
	for i, secret := range result.Secrets {
		findings = append(findings, New(Options{
			Module:         ModuleBundle,
			ID:             fmt.Sprintf("secret-%d", i+1),
			Severity:       SeverityHigh,
			Title:          "Possible secret in bundle",
			Description:    "A hardcoded secret-like value was found in JavaScript sources.",
			Evidence:       secret,
			Recommendation: "Move secrets to environment variables and rotate exposed values.",
			CWE:            "CWE-798",
			OWASP:          "A02:2021",
			CVSS:           7.5,
		}))
	}
	for _, admin := range result.AdminPages {
		findings = append(findings, New(Options{
			Module:         ModuleBundle,
			ID:             "admin-page-" + slug(admin),
			Severity:       SeverityLow,
			Title:          "Admin page referenced in bundle",
			Description:    "Client-side code references a potential administrative route.",
			Evidence:       admin,
			Recommendation: "Ensure admin routes enforce server-side authorization.",
			CWE:            "CWE-284",
			OWASP:          "A01:2021",
			CVSS:           4.3,
		}))
	}
	return findings
}

type EndpointProbe struct {
	Path   string
	Method string
	Status int
}

func FromEndpoints(probes []EndpointProbe) []Finding {
	var findings []Finding
	for _, probe := range probes {
		if probe.Method != "GET" || probe.Status >= 400 {
			continue
		}
		lower := strings.ToLower(probe.Path)
		switch {
		case strings.Contains(lower, "/admin"):
			findings = append(findings, New(Options{
				Module:         ModuleEndpoint,
				ID:             "exposed-" + slug(probe.Path),
				Severity:       SeverityMedium,
				Title:          "Admin endpoint reachable",
				Description:    "An administrative path responded successfully to a safe GET probe.",
				Evidence:       fmt.Sprintf("%s %d", probe.Path, probe.Status),
				Recommendation: "Verify authentication and authorization on admin routes.",
				CWE:            "CWE-284",
				OWASP:          "A01:2021",
				CVSS:           5.4,
			}))
		case strings.Contains(lower, "openapi") || strings.Contains(lower, "swagger"):
			findings = append(findings, New(Options{
				Module:         ModuleEndpoint,
				ID:             "api-doc-" + slug(probe.Path),
				Severity:       SeverityLow,
				Title:          "API documentation exposed",
				Description:    "An API documentation endpoint is reachable.",
				Evidence:       fmt.Sprintf("%s %d", probe.Path, probe.Status),
				Recommendation: "Restrict public access to API documentation in production.",
				CWE:            "CWE-200",
				OWASP:          "A05:2021",
				CVSS:           3.7,
			}))
		}
	}
	return findings
}
