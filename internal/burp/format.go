package burp

import (
	"strings"

	"github.com/dionebastos/vibesec/internal/ui"
)

func FormatOutput(result *Result) []string {
	if result == nil {
		return nil
	}
	lines := []string{""}
	switch result.Status {
	case StatusOK:
		lines = append(lines, ui.CheckLine("Burp import", "PASS", result.Summary))
		for _, issue := range result.Issues {
			detail := issue.Location
			if detail == "" {
				detail = issue.Path
			}
			lines = append(lines, ui.CheckLine(issue.Name, displaySeverity(issue.Severity), detail))
		}
	case StatusSkipped:
		lines = append(lines, ui.CheckLine("Burp import", "WARNING", result.Summary))
	default:
		detail := result.Summary
		if result.Error != "" {
			detail = result.Error
		}
		lines = append(lines, ui.CheckLine("Burp import", "FAIL", detail))
	}
	return lines
}

func displaySeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return "FAIL"
	case "medium":
		return "WARNING"
	case "low", "information", "info":
		return "INFO"
	default:
		return strings.ToUpper(value)
	}
}
