package finding

import (
	"fmt"
	"strings"
)

const ModuleBurp = "burp"

type BurpIssue struct {
	Name        string
	Severity    string
	Location    string
	Detail      string
	Remediation string
}

func FromBurp(issues []BurpIssue) []Finding {
	var findings []Finding
	for i, issue := range issues {
		evidence := issue.Location
		if evidence == "" {
			evidence = issue.Detail
		}
		rec := issue.Remediation
		if rec == "" {
			rec = "Review and remediate the issue identified by Burp Suite."
		}
		findings = append(findings, New(Options{
			Module:         ModuleBurp,
			ID:             slug(issue.Name) + "-" + fmt.Sprintf("%d", i),
			Severity:       mapBurpSeverity(issue.Severity),
			Title:          issue.Name,
			Description:    issue.Detail,
			Evidence:       evidence,
			Recommendation: rec,
			OWASP:          "A05:2021",
		}))
	}
	return findings
}

func mapBurpSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "information", "info":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}
