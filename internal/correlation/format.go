package correlation

import "fmt"

func FormatOutput(count int) []string {
	if count == 0 {
		return []string{"", "  no correlated findings"}
	}
	return []string{"", fmt.Sprintf("  %d high-confidence correlation(s)", count)}
}
