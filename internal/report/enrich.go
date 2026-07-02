package report

import (
	"encoding/json"

	"github.com/dionebastos/vibesec/internal/finding"
)

// EnrichFindingsForExecutive populates layperson fields used by the executive UI.
func EnrichFindingsForExecutive(findings []finding.Finding) []finding.Finding {
	for i := range findings {
		findings[i].LaypersonImpact = finding.LaypersonExplanation(findings[i])
		findings[i].LaypersonRecommendation = finding.LaypersonRecommendation(findings[i])
	}
	return findings
}

// EnrichDocumentJSON unmarshals a scan document, enriches findings, and returns updated JSON.
func EnrichDocumentJSON(raw string) (string, error) {
	if raw == "" {
		return raw, nil
	}
	var doc Document
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return raw, err
	}
	doc.Findings = EnrichFindingsForExecutive(doc.Findings)
	out, err := json.Marshal(doc)
	if err != nil {
		return raw, err
	}
	return string(out), nil
}
