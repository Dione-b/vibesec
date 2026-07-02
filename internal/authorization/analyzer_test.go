package authorization

import "testing"

func TestAnalyzeVerticalSkipsSPA(t *testing.T) {
	result := Analyze(Input{
		AdminPages: []string{"/admin"},
		EndpointProbes: []EndpointProbe{
			{Path: "/admin", Method: "GET", Status: 200},
		},
		SPADetected: true,
	})

	for _, signal := range result.Signals {
		if signal.Category == "Vertical escalation" && signal.Status == StatusWarning {
			t.Fatalf("expected no vertical escalation warning on SPA, got %+v", signal)
		}
	}
}

func TestAnalyzeVerticalFlagsAdmin200(t *testing.T) {
	result := Analyze(Input{
		AdminPages: []string{"/admin"},
		EndpointProbes: []EndpointProbe{
			{Path: "/admin", Method: "GET", Status: 200},
		},
	})

	found := false
	for _, signal := range result.Signals {
		if signal.Category == "Vertical escalation" && signal.Status == StatusWarning {
			found = true
		}
	}
	if !found {
		t.Fatal("expected vertical escalation warning without SPA")
	}
}
