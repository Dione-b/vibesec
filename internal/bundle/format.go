package bundle

import (
	"fmt"
	"strings"

	"github.com/dionebastos/vibesec/internal/ui"
)

func FormatOutput(result *Result) []string {
	if result == nil {
		return nil
	}

	lines := []string{""}
	lines = append(lines, fmt.Sprintf("  %s", ui.Muted(fmt.Sprintf("%d routes", result.RouteCount()))))
	lines = append(lines, fmt.Sprintf("  %s", ui.Muted(fmt.Sprintf("%d endpoints", result.EndpointCount()))))
	if result.AdminCount() > 0 {
		lines = append(lines, fmt.Sprintf("  %s", ui.Muted(fmt.Sprintf("%d admin pages", result.AdminCount()))))
	}
	if len(result.Libraries) > 0 {
		lines = append(lines, "")
		for _, lib := range result.Libraries {
			lines = append(lines, "  "+lib)
		}
	}
	if len(result.Secrets) > 0 {
		lines = append(lines, "")
		lines = append(lines, ui.Subsection("Possible secrets"))
		for _, secret := range result.Secrets {
			lines = append(lines, "  "+secret)
		}
	}
	if len(result.Scripts) > 0 && len(result.Libraries) == 0 && result.RouteCount() == 0 {
		lines = append(lines, fmt.Sprintf("  %s", ui.Muted(fmt.Sprintf("%d scripts analyzed", len(result.Scripts)))))
	}
	return lines
}

func SummaryLine(result *Result) string {
	if result == nil {
		return ""
	}
	parts := []string{
		fmt.Sprintf("%d routes", result.RouteCount()),
		fmt.Sprintf("%d endpoints", result.EndpointCount()),
	}
	if result.AdminCount() > 0 {
		parts = append(parts, fmt.Sprintf("%d admin pages", result.AdminCount()))
	}
	if len(result.Libraries) > 0 {
		parts = append(parts, strings.Join(result.Libraries, ", "))
	}
	return strings.Join(parts, "\n")
}
