package auth

import (
	"net/http"
	"testing"
)

func TestAnalyzeLaravelSessionCookie(t *testing.T) {
	result := Analyze(Input{
		Target: "https://escritha.com",
		Cookies: []Cookie{{
			Name:     "escritha_session",
			HttpOnly: true,
			Secure:   false,
			SameSite: "",
		}},
		EndpointProbes: []EndpointProbe{
			{Path: "/login", Method: http.MethodGet, Status: 200},
		},
	})

	if result.LoginPath != "/login" {
		t.Fatalf("login path: %s", result.LoginPath)
	}
	if !hasSignal(result, "Cookies", StatusFail) {
		t.Fatalf("expected cookie fail, got %+v", result.Signals)
	}
	if !hasSignal(result, "Cookies", StatusWarning) {
		t.Fatalf("expected samesite warning")
	}
}

func hasSignal(result *Result, category, status string) bool {
	for _, s := range result.Signals {
		if s.Category == category && s.Status == status {
			return true
		}
	}
	return false
}
