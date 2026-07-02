package report

import (
	"strings"
	"testing"
	"time"

	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/finding"
)

func TestRenderExecutiveMarkdownContainsExpectedSections(t *testing.T) {
	doc := &Document{
		Summary: Summary{
			Target:       "https://example.com",
			GeneratedAt:  time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			ModulesRun:   5,
			FindingCount: 2,
		},
		Findings: []finding.Finding{
			{Title: "Missing CSP", Severity: finding.SeverityHigh, Description: "No Content-Security-Policy header found.", Recommendation: "Add CSP header"},
			{Title: "Weak Cookies", Severity: finding.SeverityMedium, Recommendation: "Set Secure flag"},
		},
		Risk: Risk{
			Level: "high",
			Score: 15,
			Counts: map[string]int{
				"critical": 0,
				"high":     1,
				"medium":   1,
				"low":      0,
				"info":     0,
			},
		},
		Recommendations: []string{"Add CSP header", "Set Secure flag"},
	}

	md := RenderExecutiveMarkdown(doc)

	checks := []string{
		"Relatório de Segurança",
		"Visão Executiva",
		"example.com",
		"Como isso afeta seu sistema",
		"Missing CSP",
		"Weak Cookies",
		"O que fazer",
		"Próximos Passos",
		"🟠",
		"Alto",
	}
	for _, want := range checks {
		if !strings.Contains(md, want) {
			t.Errorf("executive markdown missing %q", want)
		}
	}
}

func TestRenderExecutiveMarkdownNilDoc(t *testing.T) {
	if result := RenderExecutiveMarkdown(nil); result != "" {
		t.Errorf("expected empty string for nil doc, got %q", result)
	}
}

func TestRenderExecutiveHTMLContainsExpectedSections(t *testing.T) {
	doc := &Document{
		Summary: Summary{
			Target:       "https://example.com",
			GeneratedAt:  time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC),
			ModulesRun:   5,
			FindingCount: 1,
		},
		Findings: []finding.Finding{
			{Title: "Missing CSP", Severity: finding.SeverityHigh, Description: "No CSP header found.", Recommendation: "Add CSP"},
		},
		Risk: Risk{
			Level: "high",
			Score: 15,
			Counts: map[string]int{
				"critical": 0,
				"high":     1,
				"medium":   0,
				"low":      0,
				"info":     0,
			},
		},
		Recommendations: []string{"Add CSP"},
	}

	html := RenderExecutiveHTML(doc)

	checks := []string{
		"<!DOCTYPE html>",
		"Relatório Executivo",
		"Análise de Segurança",
		"example.com",
		"Como isso afeta seu sistema",
		"Missing CSP",
		"O que fazer",
		"Próximos Passos",
		"Alto",
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Errorf("executive html missing %q", want)
		}
	}
}

func TestRenderExecutiveHTMLNilDoc(t *testing.T) {
	if result := RenderExecutiveHTML(nil); result != "" {
		t.Errorf("expected empty string for nil doc, got %q", result)
	}
}

func TestWriteGeneratesExecutiveReports(t *testing.T) {
	dir := t.TempDir()
	oldNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = oldNow })

	cfg := defaultConfigAllFormats()
	doc := &Document{
		Summary: Summary{
			Target:       "https://example.com",
			GeneratedAt:  timeNow(),
			ModulesRun:   5,
			FindingCount: 1,
		},
		Findings: []finding.Finding{
			{ID: "1", Severity: "high", Title: "Test Finding", Recommendation: "Fix it"},
		},
	}
	doc.Risk = assessRisk(doc.Findings, nil)
	doc.Recommendations = buildRecommendations(doc)

	output, err := writeToDir(cfg, doc, dir)
	if err != nil {
		t.Fatal(err)
	}

	if output.ExecutiveMarkdown == "" {
		t.Fatal("expected executive markdown path")
	}
	if output.ExecutiveHTML == "" {
		t.Fatal("expected executive html path")
	}
	if !strings.Contains(output.ExecutiveMarkdown, "executive") {
		t.Errorf("executive markdown path should contain 'executive': %s", output.ExecutiveMarkdown)
	}
	if !strings.Contains(output.ExecutiveHTML, "executive") {
		t.Errorf("executive html path should contain 'executive': %s", output.ExecutiveHTML)
	}

	latest, err := LoadLatest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if latest.ExecutiveMarkdown == "" || latest.ExecutiveHTML == "" {
		t.Fatal("latest pointer should include executive report paths")
	}
}

func defaultConfigAllFormats() *config.Config {
	cfg := config.Default()
	cfg.Report.Format = []string{"markdown", "json", "html"}
	return cfg
}
