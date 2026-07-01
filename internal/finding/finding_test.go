package finding

import "testing"

func TestNewPrefixesModuleID(t *testing.T) {
	f := New(Options{
		Module:   ModuleHeaders,
		ID:       "hsts",
		Severity: SeverityHigh,
		Title:    "HSTS",
	})
	if f.ID != "headers/hsts" {
		t.Fatalf("id: %s", f.ID)
	}
	if f.Module != ModuleHeaders {
		t.Fatalf("module: %s", f.Module)
	}
}

func TestDedupByID(t *testing.T) {
	items := []Finding{
		{ID: "a", Severity: SeverityHigh, Title: "one"},
		{ID: "a", Severity: SeverityHigh, Title: "dup"},
		{ID: "b", Severity: SeverityLow, Title: "two"},
	}
	out := Dedup(items)
	if len(out) != 2 {
		t.Fatalf("expected 2, got %d", len(out))
	}
}

func TestFromHeaderChecksSkipsPass(t *testing.T) {
	findings := FromHeaderChecks([]HeaderCheck{
		{Name: "HSTS", Status: "PASS", Detail: "ok"},
		{Name: "CSP", Status: "FAIL", Detail: "missing"},
	})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].CWE == "" {
		t.Fatal("expected CWE mapping")
	}
}

func TestFromCSPMissing(t *testing.T) {
	findings := FromCSP("", true)
	if len(findings) != 1 || findings[0].Severity != SeverityHigh {
		t.Fatalf("unexpected: %+v", findings)
	}
}
