package finding

import "fmt"

const ModulePlugins = "plugins"

type PluginItem struct {
	Name      string
	Status    string
	Summary   string
	Error     string
	OpenPorts int
}

func FromPluginCollection(results []PluginItem) []Finding {
	var findings []Finding
	for _, result := range results {
		if result.Status == "error" && result.Error != "" {
			findings = append(findings, New(Options{
				Module:      ModulePlugins,
				ID:          result.Name + "-error",
				Severity:    SeverityLow,
				Title:       result.Name + " plugin failed",
				Description: result.Error,
				Evidence:    result.Error,
			}))
		}
		if result.OpenPorts > 10 {
			findings = append(findings, New(Options{
				Module:         ModulePlugins,
				ID:             result.Name + "-ports",
				Severity:       SeverityInfo,
				Title:          "Multiple open ports detected",
				Description:    fmt.Sprintf("%s reported %d open ports", result.Name, result.OpenPorts),
				Evidence:       result.Summary,
				Recommendation: "Review exposed services and close unnecessary ports.",
			}))
		}
	}
	return findings
}
