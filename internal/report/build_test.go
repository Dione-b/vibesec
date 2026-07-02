package report

import (
	"testing"

	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/fingerprint"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func TestBuildFromContext(t *testing.T) {
	ctx := &scanctx.Context{
		Target: "https://example.com",
		Config: config.Default(),
		Fingerprint: &fingerprint.Result{
			Stack: []string{"Node"},
			Infra: []string{"AWS"},
		},
	}
	doc := Build(ctx, 3)
	if len(doc.Stack) != 1 || doc.Stack[0] != "Node" {
		t.Fatalf("stack: %#v", doc.Stack)
	}
}

func TestBuildEnrichesLaypersonImpact(t *testing.T) {
	ctx := &scanctx.Context{
		Target: "https://example.com",
		Config: config.Default(),
		Findings: []finding.Finding{
			{
				ID:       "headers/hsts",
				Module:   "headers",
				Title:    "Missing HSTS",
				Severity: finding.SeverityHigh,
			},
		},
	}
	doc := Build(ctx, 1)
	if len(doc.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
	}
	if doc.Findings[0].LaypersonImpact == "" {
		t.Fatal("expected layperson_impact to be populated")
	}
	if doc.Findings[0].LaypersonRecommendation == "" {
		t.Fatal("expected layperson_recommendation to be populated")
	}
	if doc.Findings[0].LaypersonImpact != finding.LaypersonExplanation(doc.Findings[0]) {
		t.Fatal("layperson_impact should match LaypersonExplanation output")
	}
}
