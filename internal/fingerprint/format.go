package fingerprint

import (
	"strings"

	"github.com/dionebastos/vibesec/internal/ui"
)

func FormatOutput(result *Result) []string {
	if result == nil || len(result.Stack) == 0 {
		return nil
	}

	lines := []string{"", ui.Subsection("Stack provável"), ""}
	for _, item := range result.Stack {
		lines = append(lines, "  "+item)
	}
	return lines
}

func FormatDetails(result *Result) string {
	if result == nil {
		return ""
	}

	var parts []string
	if result.TLS.Version != "" {
		parts = append(parts, "TLS "+result.TLS.Version)
	}
	if result.Server != "" {
		parts = append(parts, "Server: "+result.Server)
	}
	if result.PoweredBy != "" {
		parts = append(parts, "X-Powered-By: "+result.PoweredBy)
	}
	if len(result.Cookies) > 0 {
		names := make([]string, 0, len(result.Cookies))
		for _, c := range result.Cookies {
			names = append(names, c.Name)
		}
		parts = append(parts, "Cookies: "+strings.Join(names, ", "))
	}
	return strings.Join(parts, " | ")
}
