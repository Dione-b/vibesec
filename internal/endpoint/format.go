package endpoint

import (
	"fmt"

	"github.com/dionebastos/vibesec/internal/ui"
)

func FormatOutput(result *Result) []string {
	if result == nil || len(result.Matrix) == 0 {
		return []string{"", ui.Muted("  no endpoints discovered")}
	}

	lines := []string{"", ui.Subsection("Endpoint Matrix"), ""}
	lines = append(lines, fmt.Sprintf("  %-8s %-28s %s", "METHOD", "PATH", "STATUS"))
	for _, probe := range result.Matrix {
		line := fmt.Sprintf("  %-8s %-28s %d", probe.Method, probe.Path, probe.Status)
		if probe.AllowedMethods != "" {
			line += "  " + ui.Muted(probe.AllowedMethods)
		}
		lines = append(lines, line)
	}
	return lines
}
