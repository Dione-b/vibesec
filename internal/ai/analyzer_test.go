package ai

import (
	"testing"

	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/headers"
)

func TestAnalyzeProducesExecutiveSummary(t *testing.T) {
	result := Analyze(Input{
		Target: "https://example.com",
		Findings: []finding.Finding{
			finding.New(finding.Options{
				Module:   finding.ModuleHeaders,
				ID:       "hsts",
				Severity: finding.SeverityHigh,
				Title:    "Missing HSTS",
				CVSS:     6.5,
			}),
		},
		Headers: &headers.Result{
			Checks: []headers.Check{{Name: "HSTS", Status: headers.StatusFail}},
		},
	})
	if result.ExecutiveSummary == "" {
		t.Fatal("expected executive summary")
	}
	if len(result.Prioritization) != 1 {
		t.Fatalf("expected 1 priority item, got %d", len(result.Prioritization))
	}
}

func TestPrioritizeBoostsHighConfidence(t *testing.T) {
	items := []finding.Finding{
		finding.New(finding.Options{Module: "headers", ID: "a", Severity: finding.SeverityHigh, Title: "A", CVSS: 6.0}),
		finding.New(finding.Options{
			Module: finding.ModuleCorrelation, ID: "b", Severity: finding.SeverityHigh,
			Title: "B", CVSS: 6.0, Confidence: finding.ConfidenceHigh,
		}),
	}
	priorities := prioritizeFindings(items)
	if priorities[0].Title != "B" {
		t.Fatalf("expected correlated finding first, got %q", priorities[0].Title)
	}
}
