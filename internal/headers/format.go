package headers

import (
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/ui"
)

func FormatOutput(result *Result) []string {
	if result == nil || len(result.Checks) == 0 {
		return nil
	}

	lines := []string{""}
	for _, check := range result.Checks {
		lines = append(lines, ui.CheckLine(check.Name, check.Status, check.Detail))
	}
	return lines
}

func ToHeaderChecks(result *Result) []finding.HeaderCheck {
	if result == nil {
		return nil
	}
	checks := make([]finding.HeaderCheck, len(result.Checks))
	for i, check := range result.Checks {
		checks[i] = finding.HeaderCheck{
			Name:   check.Name,
			Status: check.Status,
			Detail: check.Detail,
		}
	}
	return checks
}
