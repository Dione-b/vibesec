package finding

import (
	"fmt"
	"strings"
)

const ModuleNuclei = "nuclei"

type NucleiItem struct {
	TemplateID string
	Name       string
	Severity   string
	Matched    string
}

func FromNuclei(items []NucleiItem) []Finding {
	var findings []Finding
	for i, item := range items {
		findings = append(findings, New(Options{
			Module:      ModuleNuclei,
			ID:          slug(item.TemplateID) + "-" + fmt.Sprintf("%d", i),
			Severity:    mapNucleiSeverity(item.Severity),
			Title:       item.Name,
			Description: "Nuclei template match",
			Evidence:    item.Matched,
			OWASP:       "A05:2021",
		}))
	}
	return findings
}

func mapNucleiSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "med":
		return SeverityMedium
	case "low":
		return SeverityLow
	default:
		return SeverityInfo
	}
}
