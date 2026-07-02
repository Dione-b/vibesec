package endpoint

import "testing"

func TestDetectSPAFallbackTrue(t *testing.T) {
	hash := "abc123"
	probes := []Probe{
		{Path: "/", Method: "GET", Status: 200, ContentHash: hash},
		{Path: "/admin", Method: "GET", Status: 200, ContentHash: hash},
		{Path: "/login", Method: "GET", Status: 200, ContentHash: hash},
		{Path: "/dashboard", Method: "GET", Status: 200, ContentHash: hash},
	}
	if !DetectSPAFallback(probes) {
		t.Fatal("expected SPA fallback detection")
	}
}

func TestDetectSPAFallbackFalse(t *testing.T) {
	probes := []Probe{
		{Path: "/", Method: "GET", Status: 200, ContentHash: "hash-a"},
		{Path: "/admin", Method: "GET", Status: 200, ContentHash: "hash-b"},
		{Path: "/login", Method: "GET", Status: 200, ContentHash: "hash-c"},
	}
	if DetectSPAFallback(probes) {
		t.Fatal("expected distinct responses to avoid SPA detection")
	}
}

func TestDetectSPAFallbackIgnoresNonGET(t *testing.T) {
	hash := "same"
	probes := []Probe{
		{Path: "/", Method: "HEAD", Status: 200, ContentHash: hash},
		{Path: "/admin", Method: "OPTIONS", Status: 200, ContentHash: hash},
	}
	if DetectSPAFallback(probes) {
		t.Fatal("expected non-GET probes to be ignored")
	}
}
