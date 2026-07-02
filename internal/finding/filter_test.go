package finding

import "testing"

func TestFilterLowConfidenceRemovesLow(t *testing.T) {
	findings := []Finding{
		{ID: "a", Confidence: ConfidenceLow},
		{ID: "b", Confidence: ConfidenceMedium},
		{ID: "c", Confidence: ConfidenceHigh},
	}
	filtered := FilterLowConfidence(findings)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(filtered))
	}
}

func TestScoreConfidenceSuppressesNucleiStandalone(t *testing.T) {
	f := Finding{Module: ModuleNuclei, Severity: SeverityHigh, Title: "Test"}
	scored := ScoreConfidence(f, FilterContext{})
	if scored.Confidence != ConfidenceLow {
		t.Fatalf("expected low confidence, got %q", scored.Confidence)
	}
}

func TestScoreConfidenceKeepsNucleiCritical(t *testing.T) {
	f := Finding{Module: ModuleNuclei, Severity: SeverityCritical, Title: "RCE"}
	scored := ScoreConfidence(f, FilterContext{})
	if scored.Confidence != ConfidenceMedium {
		t.Fatalf("expected medium confidence, got %q", scored.Confidence)
	}
}

func TestScoreConfidenceSuppressesBurpStandalone(t *testing.T) {
	f := Finding{Module: ModuleBurp, Severity: SeverityHigh, Title: "Issue"}
	scored := ScoreConfidence(f, FilterContext{})
	if scored.Confidence != ConfidenceLow {
		t.Fatalf("expected low confidence, got %q", scored.Confidence)
	}
}

func TestScoreConfidenceSuppressesEndpointOnSPA(t *testing.T) {
	f := Finding{
		Module:   ModuleEndpoint,
		Title:    "Admin endpoint reachable",
		Evidence: "/admin 200",
	}
	ctx := FilterContext{SPADetected: true}
	scored := ScoreConfidence(f, ctx)
	if scored.Confidence != ConfidenceLow {
		t.Fatalf("expected low confidence on SPA, got %q", scored.Confidence)
	}
}

func TestScoreConfidenceSuppressesHSTSOnHTTP(t *testing.T) {
	f := Finding{Module: ModuleHeaders, Title: "HSTS"}
	ctx := FilterContext{IsHTTPS: false}
	scored := ScoreConfidence(f, ctx)
	if scored.Confidence != ConfidenceLow {
		t.Fatalf("expected low confidence for HSTS on HTTP, got %q", scored.Confidence)
	}
}

func TestFromEndpointsSkipsSPA(t *testing.T) {
	probes := []EndpointProbe{{Path: "/admin", Method: "GET", Status: 200}}
	findings := FromEndpoints(probes, true)
	if len(findings) != 0 {
		t.Fatalf("expected no endpoint findings on SPA, got %d", len(findings))
	}
}
