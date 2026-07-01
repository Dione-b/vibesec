package auth

import "github.com/dionebastos/vibesec/internal/ui"

func FormatOutput(result *Result) []string {
	if result == nil {
		return nil
	}

	lines := []string{""}
	if len(result.Mechanisms) > 0 {
		lines = append(lines, ui.Subsection("Auth mechanisms"))
		for _, m := range result.Mechanisms {
			lines = append(lines, "  "+m)
		}
		lines = append(lines, "")
	}

	for _, signal := range result.Signals {
		lines = append(lines, ui.CheckLine(signal.Category, signal.Status, signal.Detail))
	}
	return lines
}
