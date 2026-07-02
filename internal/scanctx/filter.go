package scanctx

import (
	"net/url"
	"strings"

	"github.com/dionebastos/vibesec/internal/finding"
)

// BuildFilterContext assembles confidence-scoring context from scan state.
func (c *Context) BuildFilterContext() finding.FilterContext {
	ctx := finding.FilterContext{}
	if c == nil {
		return ctx
	}

	if parsed, err := url.Parse(c.Target); err == nil {
		ctx.IsHTTPS = parsed.Scheme == "https"
	}

	if c.Endpoints != nil {
		ctx.SPADetected = c.Endpoints.SPADetected
	}

	if c.Bundle != nil && strings.TrimSpace(c.Bundle.CombinedContent) != "" {
		ctx.HasBundleContent = true
	}

	if c.Auth != nil {
		for _, signal := range c.Auth.Signals {
			if signal.Category == "Cookies" && (signal.Status == "FAIL" || signal.Status == "WARNING") {
				ctx.HasSessionCookie = true
				break
			}
		}
	}
	if !ctx.HasSessionCookie && c.Fingerprint != nil {
		for _, cookie := range c.Fingerprint.Cookies {
			if looksLikeSessionCookie(cookie.Name) {
				ctx.HasSessionCookie = true
				break
			}
		}
	}

	return ctx
}

func looksLikeSessionCookie(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "session") || lower == "connect.sid"
}
