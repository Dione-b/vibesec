package finding

import (
	"strings"
	"testing"
)

func TestLaypersonRecommendationHSTS(t *testing.T) {
	f := Finding{ID: "headers/hsts", Title: "HSTS", Severity: SeverityHigh}
	rec := LaypersonRecommendation(f)
	if rec == "" {
		t.Fatal("expected recommendation")
	}
	if containsAny(rec, "Strict-Transport-Security", "max-age", "includeSubDomains") {
		t.Fatalf("recommendation should be layperson PT, got: %s", rec)
	}
}

func TestLaypersonRecommendationBundleSecret(t *testing.T) {
	f := Finding{ID: "bundle/secret-1", Title: "Possible secret in bundle", Severity: SeverityHigh}
	rec := LaypersonRecommendation(f)
	if rec == "" {
		t.Fatal("expected recommendation")
	}
	if containsAny(rec, "environment variables", "rotate") {
		t.Fatalf("recommendation should be layperson PT, got: %s", rec)
	}
}

func TestLaypersonRecommendationCookiesSecureTitle(t *testing.T) {
	f := Finding{ID: "headers/cookies-secure", Title: "Cookies Secure", Severity: SeverityHigh}
	impact := LaypersonExplanation(f)
	rec := LaypersonRecommendation(f)
	if impact == "" || rec == "" {
		t.Fatalf("expected impact and recommendation, got impact=%q rec=%q", impact, rec)
	}
}

func TestLaypersonExplanationHSTS(t *testing.T) {
	f := Finding{ID: "headers/hsts", Title: "HSTS", Severity: SeverityHigh}
	msg := LaypersonExplanation(f)
	if containsAny(msg, "Strict-Transport-Security", "header missing") {
		t.Fatalf("explanation should be layperson PT, got: %s", msg)
	}
}

func containsAny(s string, parts ...string) bool {
	lower := strings.ToLower(s)
	for _, p := range parts {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	return false
}
