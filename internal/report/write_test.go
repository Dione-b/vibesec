package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/headers"
)

func TestWriteMarkdownAndJSON(t *testing.T) {
	dir := t.TempDir()
	oldNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = oldNow })

	cfg := config.Default()
	doc := &Document{
		Summary: Summary{
			Target:      "https://escritha.com",
			GeneratedAt: timeNow(),
			ModulesRun:  6,
		},
		Stack:          []string{"PHP", "Laravel"},
		Infrastructure: []string{"Cloudflare"},
		HeaderChecks: []headers.Check{
			{Name: "CSP", Status: headers.StatusFail, Detail: "missing"},
		},
		Findings: []finding.Finding{
			{ID: "1", Severity: "high", Title: "Missing CSP", Recommendation: "Add CSP"},
		},
	}
	doc.Risk = assessRisk(doc.Findings, doc.HeaderChecks)
	doc.Recommendations = buildRecommendations(doc)

	output, err := writeToDir(cfg, doc, dir)
	if err != nil {
		t.Fatal(err)
	}
	if output.Markdown == "" || output.JSON == "" {
		t.Fatalf("expected both outputs, got %#v", output)
	}

	md, err := os.ReadFile(output.Markdown)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "# VibeSec Report") {
		t.Fatalf("unexpected markdown: %s", md)
	}

	latest, err := LoadLatest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Target != doc.Summary.Target {
		t.Fatalf("latest target mismatch")
	}
}
