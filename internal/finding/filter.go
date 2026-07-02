package finding

import "strings"

// FilterContext carries scan-wide signals used to score finding confidence.
type FilterContext struct {
	IsHTTPS          bool
	SPADetected      bool
	HasBundleContent bool
	HasSessionCookie bool
}

// ScoreAll assigns confidence to findings that do not already have one.
func ScoreAll(findings []Finding, ctx FilterContext) []Finding {
	out := make([]Finding, len(findings))
	for i, item := range findings {
		out[i] = ScoreConfidence(item, ctx)
	}
	return out
}

// ScoreConfidence assigns a confidence level based on module, title, and context.
func ScoreConfidence(f Finding, ctx FilterContext) Finding {
	if f.Confidence != "" {
		return f
	}

	switch f.Module {
	case ModuleCorrelation:
		f.Confidence = ConfidenceHigh
	case ModuleBundle:
		f.Confidence = scoreBundleConfidence(f)
	case ModuleEndpoint:
		f.Confidence = scoreEndpointConfidence(f, ctx)
	case ModuleHeaders:
		f.Confidence = scoreHeadersConfidence(f, ctx)
	case ModuleNuclei:
		f.Confidence = scoreNucleiConfidence(f)
	case ModuleBurp:
		f.Confidence = ConfidenceLow
	case ModuleAuth:
		f.Confidence = scoreAuthConfidence(f, ctx)
	case ModuleAuthorization:
		f.Confidence = scoreAuthorizationConfidence(f, ctx)
	case ModuleCSP, ModuleFingerprint, ModulePlugins:
		f.Confidence = ConfidenceMedium
	default:
		f.Confidence = ConfidenceMedium
	}
	return f
}

// FilterLowConfidence removes findings scored as low confidence.
func FilterLowConfidence(findings []Finding) []Finding {
	var out []Finding
	for _, item := range findings {
		if strings.EqualFold(item.Confidence, ConfidenceLow) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func scoreBundleConfidence(f Finding) string {
	if strings.Contains(f.ID, "secret") {
		return ConfidenceHigh
	}
	return ConfidenceMedium
}

func scoreEndpointConfidence(f Finding, ctx FilterContext) string {
	lower := strings.ToLower(f.Title + " " + f.Evidence)
	if ctx.SPADetected && (strings.Contains(lower, "admin") || strings.Contains(lower, "swagger") || strings.Contains(lower, "openapi")) {
		return ConfidenceLow
	}
	if strings.Contains(lower, "admin") {
		return ConfidenceMedium
	}
	return ConfidenceMedium
}

func scoreHeadersConfidence(f Finding, ctx FilterContext) string {
	lower := strings.ToLower(f.Title)
	if !ctx.IsHTTPS && strings.Contains(lower, "hsts") {
		return ConfidenceLow
	}
	return ConfidenceMedium
}

func scoreNucleiConfidence(f Finding) string {
	if strings.EqualFold(f.Severity, SeverityCritical) {
		return ConfidenceMedium
	}
	return ConfidenceLow
}

func scoreAuthConfidence(f Finding, ctx FilterContext) string {
	lower := strings.ToLower(f.Title)
	if strings.Contains(lower, "csrf") && !ctx.HasBundleContent {
		return ConfidenceLow
	}
	if strings.Contains(lower, "jwt") && !ctx.HasBundleContent {
		return ConfidenceLow
	}
	return ConfidenceMedium
}

func scoreAuthorizationConfidence(f Finding, ctx FilterContext) string {
	lower := strings.ToLower(f.Title)
	if ctx.SPADetected && strings.Contains(lower, "vertical") {
		return ConfidenceLow
	}
	if strings.Contains(lower, "admin pages") {
		return ConfidenceMedium
	}
	return ConfidenceMedium
}
