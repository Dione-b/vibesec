package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/dionebastos/vibesec/internal/finding"
)

func TestEnrichDocumentJSONPopulatesLaypersonFields(t *testing.T) {
	doc := Document{
		Findings: []finding.Finding{{
			ID:          "headers/hsts",
			Title:       "HSTS",
			Severity:    finding.SeverityHigh,
			Description: "Strict-Transport-Security header missing",
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}

	enriched, err := EnrichDocumentJSON(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if enriched == string(raw) {
		t.Fatal("expected enriched JSON to differ")
	}

	var out Document
	if err := json.Unmarshal([]byte(enriched), &out); err != nil {
		t.Fatal(err)
	}
	if out.Findings[0].LaypersonImpact == "" {
		t.Fatal("expected layperson_impact")
	}
	if out.Findings[0].LaypersonRecommendation == "" {
		t.Fatal("expected layperson_recommendation")
	}
	if strings.Contains(out.Findings[0].LaypersonImpact, "Strict-Transport-Security") {
		t.Fatalf("layperson_impact should not echo technical description: %s", out.Findings[0].LaypersonImpact)
	}
}

func TestEnrichFindingsForExecutive(t *testing.T) {
	findings := []finding.Finding{{ID: "headers/csp", Title: "CSP", Severity: finding.SeverityHigh}}
	out := EnrichFindingsForExecutive(findings)
	if out[0].LaypersonImpact == "" || out[0].LaypersonRecommendation == "" {
		t.Fatalf("expected enriched fields, got %+v", out[0])
	}
}
