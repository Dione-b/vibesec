package report

import (
	"strings"
	"testing"
	"time"

	"github.com/dionebastos/vibesec/internal/ai"
	"github.com/dionebastos/vibesec/internal/finding"
)

func TestRenderHTMLIncludesDashboardSections(t *testing.T) {
	doc := &Document{
		Summary: Summary{
			Target:       "https://example.com",
			GeneratedAt:  time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			ModulesRun:   5,
			FindingCount: 2,
		},
		Stack:          []string{"PHP"},
		Infrastructure: []string{"Cloudflare"},
		Findings: []finding.Finding{
			{Title: "Missing CSP", Severity: finding.SeverityHigh, CWE: "CWE-1021", CVSS: 6.1},
		},
		AI: &ai.Result{ExecutiveSummary: "Elevated posture."},
	}
	doc.Risk = assessRisk(doc.Findings, nil)

	html := RenderHTML(doc)
	checks := []string{
		"<!DOCTYPE html>",
		"Security Assessment",
		"Severity distribution",
		"Scan timeline",
		"Missing CSP",
		"CWE-1021",
		"AI analysis",
		"Elevated posture.",
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Fatalf("html missing %q", want)
		}
	}
}
