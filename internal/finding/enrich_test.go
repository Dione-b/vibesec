package finding

import "testing"

func TestEnrichAddsASVSAndCAPEC(t *testing.T) {
	items := []Finding{{
		ID:       "headers/csp",
		Severity: SeverityHigh,
		CWE:      "CWE-1021",
	}}
	out := Enrich(items)
	if out[0].ASVS == "" || out[0].CAPEC == "" {
		t.Fatalf("expected enrichment, got %+v", out[0])
	}
	if out[0].CVSS == 0 {
		t.Fatal("expected cvss")
	}
}

func TestEnrichDefaultCVSSBySeverity(t *testing.T) {
	items := []Finding{{ID: "custom", Severity: SeverityHigh}}
	out := Enrich(items)
	if out[0].CVSS != 7.0 {
		t.Fatalf("cvss: %v", out[0].CVSS)
	}
}
