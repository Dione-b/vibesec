package plugin

import "github.com/dionebastos/vibesec/internal/ui"

func FormatOutput(collection *Collection) []string {
	if collection == nil || len(collection.Results) == 0 {
		return nil
	}

	lines := []string{""}
	for _, result := range collection.Results {
		status := result.Status
		detail := result.Summary
		if result.Status == StatusError && result.Error != "" {
			detail = result.Error
		}
		switch status {
		case StatusOK:
			lines = append(lines, ui.CheckLine(result.Name, "PASS", detail))
		case StatusSkipped:
			lines = append(lines, ui.CheckLine(result.Name, "WARNING", detail))
		default:
			lines = append(lines, ui.CheckLine(result.Name, "FAIL", detail))
		}
	}
	return lines
}
