package ai

import (
	"fmt"
	"sort"
	"strings"

	"github.com/dionebastos/vibesec/internal/auth"
	"github.com/dionebastos/vibesec/internal/bundle"
	"github.com/dionebastos/vibesec/internal/endpoint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/headers"
	"github.com/dionebastos/vibesec/internal/nuclei"
	"github.com/dionebastos/vibesec/internal/plugin"
)

type Input struct {
	Target      string
	Stack       []string
	Infra       []string
	Headers     *headers.Result
	Bundle      *bundle.Result
	Endpoints   *endpoint.Result
	Auth        *auth.Result
	Plugins     *plugin.Collection
	Nuclei      *nuclei.Result
	Findings    []finding.Finding
}

func Analyze(in Input) *Result {
	if in.Target == "" && len(in.Findings) == 0 {
		return &Result{ExecutiveSummary: "No scan data available for analysis."}
	}

	attackSurface := buildAttackSurface(in)
	hypotheses := buildHypotheses(in)
	priorities := prioritizeFindings(in.Findings)
	recommendations := buildRecommendations(priorities, in)
	summary := buildExecutiveSummary(in, priorities)

	return &Result{
		ExecutiveSummary: summary,
		Hypotheses:       hypotheses,
		AttackSurface:    attackSurface,
		Prioritization:   priorities,
		Recommendations:  recommendations,
	}
}

func buildExecutiveSummary(in Input, priorities []PriorityItem) string {
	summary := finding.Summarize(in.Findings)
	risk := riskLabel(summary)

	parts := []string{
		fmt.Sprintf("Assessment for %s indicates %s security posture with %s.", in.Target, risk, summary.String()),
	}
	if len(in.Stack) > 0 {
		parts = append(parts, fmt.Sprintf("Observed stack: %s.", strings.Join(in.Stack, ", ")))
	}
	if len(priorities) > 0 {
		top := priorities[0]
		parts = append(parts, fmt.Sprintf("Highest priority: %s (%s).", top.Title, top.Severity))
	}
	if len(priorities) > 1 {
		parts = append(parts, fmt.Sprintf("%d additional ranked issues require remediation planning.", len(priorities)-1))
	}
	return strings.Join(parts, " ")
}

func riskLabel(summary finding.Summary) string {
	switch {
	case summary.Critical > 0 || summary.High >= 5:
		return "elevated"
	case summary.High > 0 || summary.Medium >= 5:
		return "moderate"
	case summary.Medium > 0 || summary.Low > 0:
		return "manageable"
	default:
		return "low"
	}
}

func buildAttackSurface(in Input) []string {
	seen := make(map[string]struct{})
	var surface []string
	add := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		key := strings.ToLower(line)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		surface = append(surface, line)
	}

	for _, item := range in.Stack {
		add("Technology: " + item)
	}
	for _, item := range in.Infra {
		add("Infrastructure: " + item)
	}
	if in.Endpoints != nil {
		for _, probe := range in.Endpoints.Matrix {
			if probe.Method != "GET" || probe.Status >= 400 || probe.Status == 0 {
				continue
			}
			add(fmt.Sprintf("Reachable route: GET %s (%d)", probe.Path, probe.Status))
		}
	}
	if in.Bundle != nil {
		for _, lib := range in.Bundle.Libraries {
			add("Client library: " + lib)
		}
		for _, route := range in.Bundle.Routes {
			add("Client route reference: " + route)
		}
	}
	if in.Auth != nil && in.Auth.LoginPath != "" {
		add("Authentication entry: " + in.Auth.LoginPath)
	}
	if in.Plugins != nil {
		for _, result := range in.Plugins.Results {
			if result.Name == "subfinder" && len(result.Subdomains) > 0 {
				add(fmt.Sprintf("Subdomains discovered: %d", len(result.Subdomains)))
			}
			if result.Name == "nmap" && result.Summary != "" {
				add("Nmap: " + result.Summary)
			}
		}
	}
	if in.Nuclei != nil && len(in.Nuclei.Findings) > 0 {
		add(fmt.Sprintf("Nuclei template matches: %d", len(in.Nuclei.Findings)))
	}
	return surface
}

func buildHypotheses(in Input) []string {
	var hypotheses []string
	seen := make(map[string]struct{})
	add := func(text string) {
		key := strings.ToLower(text)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		hypotheses = append(hypotheses, text)
	}

	stack := strings.ToLower(strings.Join(in.Stack, " "))
	hasLogin := loginExposed(in)
	insecureCookies := headerFail(in.Headers, "Cookies Secure") || authCookieWeak(in.Auth)
	missingCSP := headerFail(in.Headers, "CSP")
	missingHSTS := headerFail(in.Headers, "HSTS")
	hasSecrets := in.Bundle != nil && len(in.Bundle.Secrets) > 0
	hasCorrelation := hasModuleFinding(in.Findings, finding.ModuleCorrelation)

	if missingCSP && (strings.Contains(stack, "react") || strings.Contains(stack, "jquery") || hasSecrets) {
		add("Missing CSP combined with client-side JavaScript increases XSS and data exfiltration risk.")
	}
	if insecureCookies && hasLogin {
		add("Session cookies without Secure/SameSite on a reachable login surface may enable session hijacking over mixed contexts.")
	}
	if missingHSTS && hasLogin {
		add("Absent HSTS on an authentication surface raises downgrade and cookie interception hypotheses.")
	}
	if strings.Contains(stack, "laravel") && hasLogin {
		add("Laravel session handling with exposed /login suggests focusing on CSRF, session fixation, and auth bypass tests.")
	}
	if hasSecrets {
		add("Secret-like strings in bundles may indicate leaked API keys or tokens embedded in frontend assets.")
	}
	if hasCorrelation {
		add("Correlated findings across modules indicate issues that are more likely exploitable than isolated warnings.")
	}
	if strings.Contains(stack, "cloudflare") {
		add("Cloudflare edge protection may mask origin weaknesses; validate controls at the application layer.")
	}

	if len(hypotheses) == 0 {
		add("No strong attack hypotheses beyond baseline misconfiguration signals; deeper authenticated testing may be required.")
	}
	return hypotheses
}

func prioritizeFindings(items []finding.Finding) []PriorityItem {
	type scored struct {
		item  finding.Finding
		score float64
	}
	var ranked []scored
	for _, item := range items {
		if item.Severity == finding.SeverityInfo {
			continue
		}
		score := item.CVSS
		if score == 0 {
			score = defaultScore(item.Severity)
		}
		if item.Confidence == finding.ConfidenceHigh {
			score += 1.5
		}
		if item.Module == finding.ModuleCorrelation {
			score += 0.5
		}
		ranked = append(ranked, scored{item: item, score: score})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score == ranked[j].score {
			return ranked[i].item.Title < ranked[j].item.Title
		}
		return ranked[i].score > ranked[j].score
	})

	limit := len(ranked)
	if limit > 8 {
		limit = 8
	}
	out := make([]PriorityItem, 0, limit)
	for i := 0; i < limit; i++ {
		entry := ranked[i]
		out = append(out, PriorityItem{
			Rank:      i + 1,
			Title:     entry.item.Title,
			Severity:  entry.item.Severity,
			Score:     entry.score,
			Rationale: priorityRationale(entry.item),
		})
	}
	return out
}

func priorityRationale(item finding.Finding) string {
	parts := []string{item.Module + " module"}
	if item.Confidence != "" {
		parts = append(parts, item.Confidence+" confidence")
	}
	if item.CWE != "" {
		parts = append(parts, item.CWE)
	}
	if item.OWASP != "" {
		parts = append(parts, "OWASP "+item.OWASP)
	}
	return strings.Join(parts, "; ")
}

func buildRecommendations(priorities []PriorityItem, in Input) []string {
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

	for _, item := range in.Findings {
		if item.Recommendation != "" && (item.Severity == finding.SeverityHigh || item.Severity == finding.SeverityCritical) {
			add(item.Recommendation)
		}
	}
	for _, item := range priorities {
		for _, f := range in.Findings {
			if f.Title == item.Title && f.Recommendation != "" {
				add(f.Recommendation)
			}
		}
	}
	if headerFail(in.Headers, "HSTS") {
		add("Deploy HSTS with includeSubDomains and preload after verifying HTTPS coverage.")
	}
	if headerFail(in.Headers, "CSP") {
		add("Introduce a restrictive Content-Security-Policy and iterate with report-only mode first.")
	}
	if authCookieWeak(in.Auth) {
		add("Harden session cookies with Secure, HttpOnly, and SameSite attributes.")
	}
	if len(out) == 0 {
		add("Continue periodic scanning and expand coverage with authenticated scenarios.")
	}
	return out
}

func defaultScore(severity string) float64 {
	switch severity {
	case finding.SeverityCritical:
		return 9.0
	case finding.SeverityHigh:
		return 7.0
	case finding.SeverityMedium:
		return 5.0
	case finding.SeverityLow:
		return 3.0
	default:
		return 1.0
	}
}

func headerFail(result *headers.Result, name string) bool {
	if result == nil {
		return false
	}
	for _, check := range result.Checks {
		if check.Name == name && check.Status == headers.StatusFail {
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
		if signal.Status == auth.StatusFail && strings.Contains(strings.ToLower(signal.Category), "cookie") {
			return true
		}
	}
	return false
}

func loginExposed(in Input) bool {
	if in.Auth != nil && in.Auth.LoginPath != "" {
		return true
	}
	if in.Endpoints == nil {
		return false
	}
	for _, probe := range in.Endpoints.Matrix {
		if probe.Method == "GET" && probe.Status < 400 && strings.Contains(strings.ToLower(probe.Path), "login") {
			return true
		}
	}
	return false
}

func hasModuleFinding(items []finding.Finding, module string) bool {
	for _, item := range items {
		if item.Module == module {
			return true
		}
	}
	return false
}
