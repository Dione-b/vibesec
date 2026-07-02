package bundle

import (
	"net/url"
	"regexp"
	"strings"
)

type libraryRule struct {
	name    string
	pattern *regexp.Regexp
}

var libraryRules = []libraryRule{
	{name: "React Router", pattern: regexp.MustCompile(`(?i)react-router|createBrowserRouter|BrowserRouter`)},
	{name: "Vue Router", pattern: regexp.MustCompile(`(?i)vue-router|createRouter\(`)},
	{name: "Axios", pattern: regexp.MustCompile(`(?i)axios\.(?:get|post|create)|from ['"]axios['"]`)},
	{name: "Fetch", pattern: regexp.MustCompile(`(?i)\bfetch\s*\(`)},
	{name: "GraphQL", pattern: regexp.MustCompile(`(?i)graphql|gql|apollo`)},
	{name: "Websocket", pattern: regexp.MustCompile(`(?i)new\s+WebSocket\s*\(|wss?://`)},
	{name: "Firebase", pattern: regexp.MustCompile(`(?i)firebase(?:app|auth|firestore)?`)},
	{name: "Sentry", pattern: regexp.MustCompile(`(?i)@sentry/|Sentry\.init`)},
	{name: "jQuery", pattern: regexp.MustCompile(`(?i)jquery|\$\(\s*document\s*\)`)},
	{name: "Bootstrap", pattern: regexp.MustCompile(`(?i)bootstrap(?:\.min)?\.js`)},
	{name: "Stripe", pattern: regexp.MustCompile(`(?i)stripe\.com|Stripe\(`)},
	{name: "Mercado Pago", pattern: regexp.MustCompile(`(?i)mercadopago|mp\.v2`)},
	{name: "Supabase", pattern: regexp.MustCompile(`(?i)supabase`)},
	{name: "Pocketbase", pattern: regexp.MustCompile(`(?i)pocketbase`)},
	{name: "JWT", pattern: regexp.MustCompile(`(?i)jwt\.decode|jsonwebtoken|Bearer\s+`)},
	{name: "React", pattern: regexp.MustCompile(`(?i)react(?:-dom)?|createRoot\(`)},
	{name: "Vue", pattern: regexp.MustCompile(`(?i)createApp\(|Vue\.`)},
	{name: "Angular", pattern: regexp.MustCompile(`(?i)@angular/|platformBrowserDynamic`)},
	{name: "Analytics", pattern: regexp.MustCompile(`(?i)google-analytics|gtag\(|GTM-|plausible`)},
}

var (
	routePattern    = regexp.MustCompile(`(?i)(?:path|route)\s*[:=]\s*['"](/[^'"` + "`" + `\s]+)['"]`)
	endpointPattern = regexp.MustCompile(`['"](/(?:api|v\d+|auth|admin|users|graphql)[^'"` + "`" + `\s]*)['"]`)
	adminPattern    = regexp.MustCompile(`(?i)['"](/admin[^'"` + "`" + `\s]*)['"]`)
	secretPattern   = regexp.MustCompile(`(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]([a-zA-Z0-9_\-]{8,})['"]`)
	csrfPattern     = regexp.MustCompile(`(?i)csrf|xsrf`)
)

func scanContent(content string, result *Result, seen map[string]struct{}) {
	addUnique := func(slice *[]string, value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		*slice = append(*slice, value)
	}

	for _, rule := range libraryRules {
		if rule.pattern.MatchString(content) {
			addUnique(&result.Libraries, rule.name)
		}
	}
	if csrfPattern.MatchString(content) {
		addUnique(&result.Libraries, "CSRF")
	}

	for _, match := range routePattern.FindAllStringSubmatch(content, 50) {
		if len(match) > 1 {
			addUnique(&result.Routes, match[1])
		}
	}
	for _, match := range endpointPattern.FindAllStringSubmatch(content, 100) {
		if len(match) > 1 {
			addUnique(&result.Endpoints, match[1])
		}
	}
	for _, match := range adminPattern.FindAllStringSubmatch(content, 20) {
		if len(match) > 1 {
			addUnique(&result.AdminPages, match[1])
			addUnique(&result.Endpoints, match[1])
		}
	}
	for _, match := range secretPattern.FindAllStringSubmatch(content, 10) {
		if len(match) > 1 && IsLikelySecret(match[1]) {
			addUnique(&result.Secrets, redactSecret(match[1]))
		}
	}
}

func redactSecret(value string) string {
	if len(value) <= 6 {
		return "***"
	}
	return value[:3] + "..." + value[len(value)-3:]
}

func resolveScriptURL(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(strings.ToLower(raw), "data:") {
		return "", false
	}
	ref, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	resolved := base.ResolveReference(ref)
	if resolved.Scheme == "" || resolved.Host == "" {
		return "", false
	}
	return resolved.String(), true
}
