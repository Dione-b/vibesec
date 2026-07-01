package ai

import "fmt"

func FormatOutput(result *Result) []string {
	if result == nil {
		return []string{"", "  no analysis generated"}
	}
	lines := []string{""}
	if result.ExecutiveSummary != "" {
		lines = append(lines, "  "+truncate(result.ExecutiveSummary, 120))
	}
	if len(result.Prioritization) > 0 {
		lines = append(lines, fmt.Sprintf("  %d prioritized issue(s), %d hypothesis/hypotheses",
			len(result.Prioritization), len(result.Hypotheses)))
	}
	return lines
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max-3] + "..."
}
