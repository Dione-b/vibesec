package nuclei

import (
	"encoding/json"
	"strings"
)

type Result struct {
	Status   string    `json:"status"`
	Summary  string    `json:"summary,omitempty"`
	Error    string    `json:"error,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

type Finding struct {
	TemplateID string `json:"template_id"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	Matched    string `json:"matched_at"`
	CURL       string `json:"curl,omitempty"`
}

const (
	StatusOK      = "ok"
	StatusSkipped   = "skipped"
	StatusError     = "error"
)

func ParseJSONL(raw []byte) []Finding {
	var findings []Finding
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var row struct {
			TemplateID string `json:"template-id"`
			Info       struct {
				Name     string `json:"name"`
				Severity string `json:"severity"`
			} `json:"info"`
			Matched string `json:"matched-at"`
			CURL    string `json:"curl-command"`
		}
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			continue
		}
		findings = append(findings, Finding{
			TemplateID: row.TemplateID,
			Name:       row.Info.Name,
			Severity:   row.Info.Severity,
			Matched:    row.Matched,
			CURL:       row.CURL,
		})
	}
	return findings
}
