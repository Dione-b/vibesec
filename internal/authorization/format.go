package authorization

import "github.com/dionebastos/vibesec/internal/ui"

func FormatOutput(result *Result) []string {
	if result == nil || len(result.Signals) == 0 {
		return nil
	}
	lines := []string{""}
	for _, signal := range result.Signals {
		lines = append(lines, ui.CheckLine(signal.Category, signal.Status, signal.Detail))
	}
	return lines
}
