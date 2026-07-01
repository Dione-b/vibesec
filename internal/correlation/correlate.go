package correlation

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/dionebastos/vibesec/internal/auth"
	"github.com/dionebastos/vibesec/internal/bundle"
	"github.com/dionebastos/vibesec/internal/burp"
	"github.com/dionebastos/vibesec/internal/endpoint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/headers"
	"github.com/dionebastos/vibesec/internal/nuclei"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

type Snapshot struct {
	Bundle    *bundle.Result
	Endpoints *endpoint.Result
	Headers   *headers.Result
	Auth      *auth.Result
	Nuclei    *nuclei.Result
	Burp      *burp.Result
}

func FromContext(ctx *scanctx.Context) Snapshot {
	if ctx == nil {
		return Snapshot{}
	}
	return Snapshot{
		Bundle:    ctx.Bundle,
		Endpoints: ctx.Endpoints,
		Headers:   ctx.Headers,
		Auth:      ctx.Auth,
		Nuclei:    ctx.Nuclei,
		Burp:      ctx.Burp,
	}
}

func Analyze(s Snapshot) []finding.Finding {
	var out []finding.Finding
	seen := make(map[string]struct{})

	add := func(item finding.Finding) {
		if _, ok := seen[item.ID]; ok {
			return
		}
		seen[item.ID] = struct{}{}
		out = append(out, item)
	}

	reachable := reachableGET(s.Endpoints)
	loginPaths := loginReachable(s.Auth, reachable)

	for _, admin := range adminReferences(s.Bundle) {
		for path, probe := range reachable {
			if !pathsRelated(admin, path) {
				continue
			}
			add(correlated(finding.Options{
				ID: "admin-exposure-" + findingSlug(path),
				Severity: finding.SeverityHigh,
				Title: "Confirmed admin surface exposure",
				Description: "An administrative route referenced in client-side code is reachable over HTTP.",
				Evidence: fmt.Sprintf("bundle ref %q; GET %s %d", admin, path, probe.Status),
				Recommendation: "Enforce authentication, authorization, and network controls on administrative routes.",
				CWE: "CWE-284",
				OWASP: "A01:2021",
				CVSS: 6.8,
			}, "bundle", "endpoint"))
		}
	}

	if len(bundleSecrets(s.Bundle)) > 0 && len(loginPaths) > 0 {
		add(correlated(finding.Options{
			ID: "secret-near-auth",
			Severity: finding.SeverityHigh,
			Title: "Secret material exposed near authentication surface",
			Description: "Hardcoded secret-like values were found in JavaScript while a login route is publicly reachable.",
			Evidence: fmt.Sprintf("%d secret pattern(s); login paths: %s",
				len(bundleSecrets(s.Bundle)), strings.Join(loginPaths, ", ")),
			Recommendation: "Rotate exposed secrets, move credentials server-side, and review login hardening.",
			CWE: "CWE-798",
			OWASP: "A02:2021",
			CVSS: 7.8,
		}, "bundle", "endpoint", "auth"))
	}

	if headerFails(s.Headers, "HSTS", "Cookies (Secure)") && len(loginPaths) > 0 {
		add(correlated(finding.Options{
			ID: "weak-transport-login",
			Severity: finding.SeverityHigh,
			Title: "Authentication surface without transport protections",
			Description: "Missing HSTS or insecure cookies coincide with a reachable login route, increasing session hijack risk.",
			Evidence: fmt.Sprintf("header failures; login paths: %s", strings.Join(loginPaths, ", ")),
			Recommendation: "Enable HSTS, mark session cookies Secure and HttpOnly, and enforce HTTPS.",
			CWE: "CWE-319",
			OWASP: "A02:2021",
			CVSS: 6.5,
		}, "headers", "endpoint", "auth"))
	}

	for _, item := range nucleiFindings(s.Nuclei) {
		path := extractPath(item.Matched)
		if path == "" {
			continue
		}
		probe, ok := reachable[path]
		if !ok {
			continue
		}
		add(correlated(finding.Options{
			ID: "nuclei-confirmed-" + findingSlug(item.TemplateID+"-"+path),
			Severity: elevateSeverity(item.Severity),
			Title: "Nuclei finding confirmed by endpoint probe",
			Description: "A Nuclei template match aligns with a successful safe HTTP probe on the same path.",
			Evidence: fmt.Sprintf("template %s (%s); GET %s %d", item.TemplateID, item.Name, path, probe.Status),
			Recommendation: "Validate the template finding manually and remediate the underlying issue.",
			OWASP: "A05:2021",
			CVSS: 7.0,
		}, "nuclei", "endpoint"))
	}

	for _, issue := range burpIssues(s.Burp) {
		path := issue.Path
		if path == "" {
			path = extractPath(issue.Location)
		}
		if path == "" {
			continue
		}
		sources := []string{"burp"}
		evidence := issue.Name + " @ " + path

		if probe, ok := reachable[path]; ok {
			sources = append(sources, "endpoint")
			evidence = fmt.Sprintf("%s; GET %s %d", evidence, path, probe.Status)
		}
		for _, item := range nucleiFindings(s.Nuclei) {
			if pathsRelated(path, extractPath(item.Matched)) {
				sources = append(sources, "nuclei")
				evidence = fmt.Sprintf("%s; nuclei %s", evidence, item.TemplateID)
				break
			}
		}
		if len(sources) < 2 {
			continue
		}
		add(correlated(finding.Options{
			ID: "burp-corroborated-" + findingSlug(issue.Name+"-"+path),
			Severity: mapBurpSeverity(issue.Severity),
			Title: "Burp issue corroborated by active scan",
			Description: "An imported Burp issue matches signals from endpoint probing or Nuclei on the same path.",
			Evidence: evidence,
			Recommendation: firstNonEmpty(issue.Remediation, "Prioritize remediation; multiple scanners agree on this path."),
			CWE: "CWE-200",
			OWASP: "A05:2021",
			CVSS: 6.2,
		}, sources...))
	}

	if authCookieWeak(s.Auth) {
		for path, probe := range reachable {
			lower := strings.ToLower(path)
			if !strings.Contains(lower, "admin") && !strings.Contains(lower, "login") {
				continue
			}
			add(correlated(finding.Options{
				ID: "insecure-session-" + findingSlug(path),
				Severity: finding.SeverityHigh,
				Title: "Insecure session cookies on sensitive route",
				Description: "Authentication cookie weaknesses coincide with a reachable login or admin path.",
				Evidence: fmt.Sprintf("auth cookie warnings; GET %s %d", path, probe.Status),
				Recommendation: "Set Secure, HttpOnly, and SameSite on session cookies; restrict sensitive routes.",
				CWE: "CWE-614",
				OWASP: "A05:2021",
				CVSS: 6.4,
			}, "auth", "headers", "endpoint"))
		}
	}

	return out
}

func correlated(opts finding.Options, sources ...string) finding.Finding {
	opts.Module = finding.ModuleCorrelation
	opts.Confidence = finding.ConfidenceHigh
	if opts.Description != "" && len(sources) > 0 {
		opts.Description += " Correlated across: " + strings.Join(sources, ", ") + "."
	}
	return finding.New(opts)
}

func reachableGET(result *endpoint.Result) map[string]endpoint.Probe {
	out := make(map[string]endpoint.Probe)
	if result == nil {
		return out
	}
	for _, probe := range result.Matrix {
		if probe.Method != "GET" || probe.Status >= 400 || probe.Status == 0 {
			continue
		}
		path := normalizePath(probe.Path)
		if path == "" {
			continue
		}
		out[path] = probe
	}
	return out
}

func loginReachable(authResult *auth.Result, reachable map[string]endpoint.Probe) []string {
	var paths []string
	seen := make(map[string]struct{})
	add := func(path string) {
		path = normalizePath(path)
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	if authResult != nil && authResult.LoginPath != "" {
		add(authResult.LoginPath)
	}
	for path := range reachable {
		lower := strings.ToLower(path)
		if strings.Contains(lower, "login") || strings.Contains(lower, "signin") || strings.Contains(lower, "auth") {
			add(path)
		}
	}
	return paths
}

func adminReferences(result *bundle.Result) []string {
	if result == nil {
		return nil
	}
	seen := make(map[string]struct{})
	var refs []string
	for _, item := range result.AdminPages {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		refs = append(refs, item)
	}
	for _, item := range result.Routes {
		lower := strings.ToLower(item)
		if strings.Contains(lower, "admin") {
			key := strings.ToLower(strings.TrimSpace(item))
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			refs = append(refs, item)
		}
	}
	return refs
}

func bundleSecrets(result *bundle.Result) []string {
	if result == nil {
		return nil
	}
	return result.Secrets
}

func nucleiFindings(result *nuclei.Result) []nuclei.Finding {
	if result == nil {
		return nil
	}
	return result.Findings
}

func burpIssues(result *burp.Result) []burp.Issue {
	if result == nil {
		return nil
	}
	return result.Issues
}

func headerFails(result *headers.Result, names ...string) bool {
	if result == nil {
		return false
	}
	want := make(map[string]struct{}, len(names))
	for _, name := range names {
		want[strings.ToLower(name)] = struct{}{}
	}
	for _, check := range result.Checks {
		if check.Status != headers.StatusFail {
			continue
		}
		if _, ok := want[strings.ToLower(check.Name)]; ok {
			return true
		}
	}
	return false
}

func authCookieWeak(result *auth.Result) bool {
	if result == nil {
		return false
	}
	for _, signal := range result.Signals {
		if signal.Status != auth.StatusFail && signal.Status != auth.StatusWarning {
			continue
		}
		lower := strings.ToLower(signal.Category + " " + signal.Detail)
		if strings.Contains(lower, "cookie") || strings.Contains(lower, "samesite") || strings.Contains(lower, "secure") {
			return true
		}
	}
	return false
}

func normalizePath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		if u, err := url.Parse(value); err == nil {
			value = u.Path
		}
	}
	if !strings.HasPrefix(value, "/") {
		value = "/" + value
	}
	if value != "/" {
		value = strings.TrimRight(value, "/")
	}
	return value
}

func extractPath(raw string) string {
	return normalizePath(raw)
}

func pathsRelated(a, b string) bool {
	a = normalizePath(a)
	b = normalizePath(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	return strings.HasSuffix(b, a) || strings.HasSuffix(a, b) ||
		strings.Contains(strings.ToLower(b), strings.ToLower(a)) ||
		strings.Contains(strings.ToLower(a), strings.ToLower(b))
}

func findingSlug(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "item"
	}
	return out
}

func elevateSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium", "med":
		return finding.SeverityHigh
	default:
		return finding.SeverityMedium
	}
}

func mapBurpSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "high":
		return finding.SeverityHigh
	case "low":
		return finding.SeverityMedium
	default:
		return finding.SeverityMedium
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
