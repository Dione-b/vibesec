package report

import (
	"strings"

	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/headers"
)

func assessRisk(findings []finding.Finding, checks []headers.Check) Risk {
	_ = checks
	counts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
		"info":     0,
	}

	for _, item := range findings {
		counts[normalizeSeverity(item.Severity)]++
	}

	score := counts["critical"]*15 + counts["high"]*10 + counts["medium"]*5 + counts["low"]*2
	level := "low"
	switch {
	case score >= 30:
		level = "critical"
	case score >= 15:
		level = "high"
	case score >= 5:
		level = "medium"
	}

	return Risk{
		Level:  level,
		Score:  score,
		Counts: counts,
	}
}

func buildRecommendations(doc *Document) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(text string) {
		text = strings.TrimSpace(text)
		if text == "" {
			return
		}
		key := strings.ToLower(text)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, text)
	}

	for _, item := range doc.Findings {
		add(item.Recommendation)
	}
	for _, check := range doc.HeaderChecks {
		if check.Status == headers.StatusPass {
			continue
		}
		add(recommendationForCheck(check))
	}
	if doc.Risk.Level == "low" && len(out) == 0 {
		add("Maintain current controls and monitor exposed endpoints periodically.")
	}
	return out
}

func recommendationForCheck(check headers.Check) string {
	switch check.Name {
	case "HSTS":
		return "Enable HSTS with a long max-age and includeSubDomains."
	case "CSP":
		return "Deploy a restrictive Content-Security-Policy."
	case "XFO":
		return "Protect clickjacking with X-Frame-Options or CSP frame-ancestors."
	case "Cookies Secure":
		return "Mark session cookies as Secure on HTTPS."
	case "Cookies SameSite":
		return "Set SameSite=Lax or Strict on session cookies."
	default:
		if check.Status == headers.StatusFail {
			return "Review and fix the " + check.Name + " configuration."
		}
		return ""
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo:
		return strings.ToLower(value)
	default:
		return finding.SeverityInfo
	}
}
