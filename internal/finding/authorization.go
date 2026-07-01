package finding

import "fmt"

const ModuleAuthorization = "authorization"

type AuthorizationSnapshot struct {
	Signals []AuthSignal
}

func FromAuthorization(result *AuthorizationSnapshot) []Finding {
	if result == nil {
		return nil
	}
	var findings []Finding
	for i, signal := range result.Signals {
		if signal.Status == "PASS" || signal.Status == "INFO" {
			continue
		}
		meta := authorizationMappings[signal.Category]
		findings = append(findings, New(Options{
			Module:         ModuleAuthorization,
			ID:             slug(signal.Category) + "-" + fmt.Sprintf("%d", i),
			Severity:       authSeverity(signal.Status),
			Title:          signal.Category,
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

var authorizationMappings = map[string]struct {
	CWE   string
	OWASP string
	CVSS  float64
	Rec   string
}{
	"Admin pages": {
		CWE: "CWE-284", OWASP: "A01:2021", CVSS: 5.4,
		Rec: "Protect admin routes with server-side authentication and authorization.",
	},
	"IDOR": {
		CWE: "CWE-639", OWASP: "A01:2021", CVSS: 6.5,
		Rec: "Authorize access to every object by ID on the server.",
	},
	"Mass Assignment": {
		CWE: "CWE-915", OWASP: "A01:2021", CVSS: 5.4,
		Rec: "Use allowlists for writable fields; never bind raw request bodies to models.",
	},
	"Role bypass": {
		CWE: "CWE-602", OWASP: "A01:2021", CVSS: 7.1,
		Rec: "Never enforce authorization in client-side code.",
	},
	"Vertical escalation": {
		CWE: "CWE-269", OWASP: "A01:2021", CVSS: 6.5,
		Rec: "Require privileged roles for admin endpoints and verify on every request.",
	},
}
