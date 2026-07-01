package correlation

import (
	"testing"

	"github.com/dionebastos/vibesec/internal/auth"
	"github.com/dionebastos/vibesec/internal/bundle"
	"github.com/dionebastos/vibesec/internal/burp"
	"github.com/dionebastos/vibesec/internal/endpoint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/headers"
	"github.com/dionebastos/vibesec/internal/nuclei"
)

func TestAnalyzeAdminBundleAndEndpoint(t *testing.T) {
	findings := Analyze(Snapshot{
		Bundle: &bundle.Result{AdminPages: []string{"/admin"}},
		Endpoints: &endpoint.Result{
			Matrix: []endpoint.Probe{{Path: "/admin", Method: "GET", Status: 200}},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Confidence != finding.ConfidenceHigh {
		t.Fatalf("expected high confidence, got %q", findings[0].Confidence)
	}
	if findings[0].Module != finding.ModuleCorrelation {
		t.Fatalf("expected correlation module, got %q", findings[0].Module)
	}
}

func TestAnalyzeSecretNearLogin(t *testing.T) {
	findings := Analyze(Snapshot{
		Bundle: &bundle.Result{Secrets: []string{"api_key=abc"}},
		Endpoints: &endpoint.Result{
			Matrix: []endpoint.Probe{{Path: "/login", Method: "GET", Status: 200}},
		},
	})
	found := false
	for _, item := range findings {
		if item.ID == "correlation/secret-near-auth" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected secret-near-auth correlation")
	}
}

func TestAnalyzeNucleiConfirmedByEndpoint(t *testing.T) {
	findings := Analyze(Snapshot{
		Nuclei: &nuclei.Result{
			Findings: []nuclei.Finding{{
				TemplateID: "exposed-panel",
				Name:       "Admin Panel",
				Severity:   "medium",
				Matched:    "https://example.com/admin",
			}},
		},
		Endpoints: &endpoint.Result{
			Matrix: []endpoint.Probe{{Path: "/admin", Method: "GET", Status: 200}},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestAnalyzeBurpCorroborated(t *testing.T) {
	findings := Analyze(Snapshot{
		Burp: &burp.Result{
			Issues: []burp.Issue{{
				Name:     "Cookie without Secure",
				Severity: "Medium",
				Path:     "/login",
			}},
		},
		Endpoints: &endpoint.Result{
			Matrix: []endpoint.Probe{{Path: "/login", Method: "GET", Status: 200}},
		},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestAnalyzeWeakTransportLogin(t *testing.T) {
	findings := Analyze(Snapshot{
		Headers: &headers.Result{
			Checks: []headers.Check{{Name: "HSTS", Status: headers.StatusFail}},
		},
		Auth: &auth.Result{LoginPath: "/login"},
		Endpoints: &endpoint.Result{
			Matrix: []endpoint.Probe{{Path: "/login", Method: "GET", Status: 200}},
		},
	})
	found := false
	for _, item := range findings {
		if item.ID == "correlation/weak-transport-login" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected weak-transport-login correlation")
	}
}

func TestPathsRelated(t *testing.T) {
	if !pathsRelated("/admin", "/admin") {
		t.Fatal("expected exact match")
	}
	if !pathsRelated("admin", "/panel/admin") {
		t.Fatal("expected suffix match")
	}
}
