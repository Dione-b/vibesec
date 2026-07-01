package nuclei

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
		lines = append(lines, ui.CheckLine("Nuclei", "PASS", result.Summary))
		for _, item := range result.Findings {
			lines = append(lines, ui.CheckLine(item.TemplateID, strings.ToUpper(item.Severity), item.Name))
		}
	case StatusSkipped:
		lines = append(lines, ui.CheckLine("Nuclei", "WARNING", result.Summary))
	default:
		detail := result.Summary
		if result.Error != "" {
			detail = result.Error
		}
		lines = append(lines, ui.CheckLine("Nuclei", "FAIL", detail))
	}
	return lines
}
