package headers

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dionebastos/vibesec/internal/httpclient"
)

func Analyze(target string, resp *httpclient.Response, checkCORS bool) (*Result, error) {
	if resp == nil {
		return nil, fmt.Errorf("response is nil")
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}

	isHTTPS := parsed.Scheme == "https"
	headers := resp.Headers
	cookies := resp.Headers.Values("Set-Cookie")

	result := &Result{
		Checks: []Check{
			checkHSTS(headers, isHTTPS),
			checkCSP(headers),
			checkXFO(headers),
			checkReferrerPolicy(headers),
			checkPermissionsPolicy(headers),
			checkCacheControl(headers),
		},
	}

	if checkCORS {
		result.Checks = append(result.Checks, checkCORSHeaders(headers))
	}
	result.Checks = append(result.Checks, checkRateLimit(headers)...)
	result.Checks = append(result.Checks, checkCookies(cookies, isHTTPS)...)

	return result, nil
}

func checkHSTS(headers http.Header, isHTTPS bool) Check {
	value := strings.TrimSpace(headers.Get("Strict-Transport-Security"))
	if !isHTTPS {
		return Check{Name: "HSTS", Status: StatusWarning, Detail: "target is not HTTPS"}
	}
	if value == "" {
		return Check{
			Name:   "HSTS",
			Status: StatusFail,
			Detail: "Strict-Transport-Security header missing",
		}
	}
	lower := strings.ToLower(value)
	if !strings.Contains(lower, "max-age=") {
		return Check{Name: "HSTS", Status: StatusWarning, Detail: value}
	}
	if strings.Contains(lower, "max-age=0") {
		return Check{Name: "HSTS", Status: StatusFail, Detail: value}
	}
	if !strings.Contains(lower, "includesubdomains") {
		return Check{Name: "HSTS", Status: StatusWarning, Detail: value}
	}
	return Check{Name: "HSTS", Status: StatusPass, Detail: value}
}

func checkCSP(headers http.Header) Check {
	value := strings.TrimSpace(firstHeader(headers, "Content-Security-Policy", "Content-Security-Policy-Report-Only"))
	if value == "" {
		return Check{
			Name:   "CSP",
			Status: StatusFail,
			Detail: "Content-Security-Policy header missing",
		}
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "unsafe-inline") && strings.Contains(lower, "unsafe-eval") {
		return Check{Name: "CSP", Status: StatusWarning, Detail: "allows unsafe-inline and unsafe-eval"}
	}
	if strings.Contains(lower, "unsafe-inline") {
		return Check{Name: "CSP", Status: StatusWarning, Detail: "allows unsafe-inline"}
	}
	if strings.Contains(lower, "*") && strings.Contains(lower, "default-src") {
		return Check{Name: "CSP", Status: StatusWarning, Detail: "wildcard in default-src"}
	}
	return Check{Name: "CSP", Status: StatusPass, Detail: truncate(value, 80)}
}

func checkXFO(headers http.Header) Check {
	value := strings.TrimSpace(headers.Get("X-Frame-Options"))
	csp := strings.ToLower(headers.Get("Content-Security-Policy"))
	if value == "" && !strings.Contains(csp, "frame-ancestors") {
		return Check{
			Name:   "XFO",
			Status: StatusFail,
			Detail: "X-Frame-Options and frame-ancestors missing",
		}
	}
	if strings.EqualFold(value, "DENY") || strings.EqualFold(value, "SAMEORIGIN") || strings.Contains(csp, "frame-ancestors") {
		detail := value
		if detail == "" {
			detail = "frame-ancestors in CSP"
		}
		return Check{Name: "XFO", Status: StatusPass, Detail: detail}
	}
	return Check{Name: "XFO", Status: StatusWarning, Detail: value}
}

func checkReferrerPolicy(headers http.Header) Check {
	value := strings.TrimSpace(headers.Get("Referrer-Policy"))
	if value == "" {
		return Check{
			Name:   "Referrer Policy",
			Status: StatusWarning,
			Detail: "Referrer-Policy header missing",
		}
	}
	lower := strings.ToLower(value)
	switch {
	case strings.Contains(lower, "no-referrer"), strings.Contains(lower, "strict-origin"), strings.Contains(lower, "same-origin"):
		return Check{Name: "Referrer Policy", Status: StatusPass, Detail: value}
	case strings.Contains(lower, "unsafe-url"):
		return Check{Name: "Referrer Policy", Status: StatusFail, Detail: value}
	default:
		return Check{Name: "Referrer Policy", Status: StatusWarning, Detail: value}
	}
}

func checkPermissionsPolicy(headers http.Header) Check {
	value := strings.TrimSpace(firstHeader(headers, "Permissions-Policy", "Feature-Policy"))
	if value == "" {
		return Check{
			Name:   "Permissions Policy",
			Status: StatusWarning,
			Detail: "Permissions-Policy header missing",
		}
	}
	return Check{Name: "Permissions Policy", Status: StatusPass, Detail: truncate(value, 80)}
}

func checkCacheControl(headers http.Header) Check {
	value := strings.TrimSpace(headers.Get("Cache-Control"))
	if value == "" {
		return Check{
			Name:   "Cache Control",
			Status: StatusWarning,
			Detail: "Cache-Control header missing",
		}
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "no-store") || strings.Contains(lower, "private") {
		return Check{Name: "Cache Control", Status: StatusPass, Detail: value}
	}
	if strings.Contains(lower, "public") && strings.Contains(lower, "max-age=0") {
		return Check{Name: "Cache Control", Status: StatusWarning, Detail: value}
	}
	return Check{Name: "Cache Control", Status: StatusPass, Detail: value}
}

func checkCORSHeaders(headers http.Header) Check {
	origin := strings.TrimSpace(headers.Get("Access-Control-Allow-Origin"))
	if origin == "" {
		return Check{Name: "CORS", Status: StatusPass, Detail: "no CORS headers exposed"}
	}
	if origin == "*" {
		credentials := strings.EqualFold(headers.Get("Access-Control-Allow-Credentials"), "true")
		if credentials {
			return Check{
				Name:   "CORS",
				Status: StatusFail,
				Detail: "Access-Control-Allow-Origin: * with credentials",
			}
		}
		return Check{Name: "CORS", Status: StatusWarning, Detail: "Access-Control-Allow-Origin: *"}
	}
	methods := headers.Get("Access-Control-Allow-Methods")
	if strings.Contains(methods, "DELETE") || strings.Contains(methods, "PUT") || strings.Contains(methods, "PATCH") {
		return Check{Name: "CORS", Status: StatusWarning, Detail: fmt.Sprintf("origin=%s methods=%s", origin, methods)}
	}
	return Check{Name: "CORS", Status: StatusPass, Detail: fmt.Sprintf("origin=%s", origin)}
}

func checkRateLimit(headers http.Header) []Check {
	names := []string{
		"RateLimit-Limit",
		"RateLimit-Remaining",
		"X-RateLimit-Limit",
		"X-RateLimit-Remaining",
		"Retry-After",
	}
	var found []string
	for _, name := range names {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			found = append(found, fmt.Sprintf("%s=%s", name, value))
		}
	}
	if len(found) == 0 {
		return []Check{{
			Name:   "Rate Limit",
			Status: StatusWarning,
			Detail: "no rate limit headers detected",
		}}
	}
	return []Check{{
		Name:   "Rate Limit",
		Status: StatusPass,
		Detail: strings.Join(found, ", "),
	}}
}

func checkCookies(rawCookies []string, isHTTPS bool) []Check {
	if len(rawCookies) == 0 {
		return []Check{{
			Name:   "Cookies",
			Status: StatusPass,
			Detail: "no Set-Cookie headers in response",
		}}
	}

	secureFail := 0
	httpOnlyFail := 0
	sameSiteWarn := 0
	var names []string

	for _, raw := range rawCookies {
		name := cookieName(raw)
		if name == "" {
			continue
		}
		names = append(names, name)
		lower := strings.ToLower(raw)
		if isHTTPS && !strings.Contains(lower, "secure") {
			secureFail++
		}
		if !strings.Contains(lower, "httponly") {
			httpOnlyFail++
		}
		if !strings.Contains(lower, "samesite=") {
			sameSiteWarn++
		} else if strings.Contains(lower, "samesite=none") && !strings.Contains(lower, "secure") {
			sameSiteWarn++
		}
	}

	checks := []Check{
		cookieSubcheck("Cookies Secure", secureFail, len(names), isHTTPS),
		cookieSubcheck("Cookies HttpOnly", httpOnlyFail, len(names), true),
	}

	sameSiteStatus := StatusPass
	sameSiteDetail := "SameSite set on all cookies"
	if sameSiteWarn > 0 {
		sameSiteStatus = StatusWarning
		sameSiteDetail = fmt.Sprintf("%d cookie(s) missing or weak SameSite", sameSiteWarn)
	}
	checks = append(checks, Check{Name: "Cookies SameSite", Status: sameSiteStatus, Detail: sameSiteDetail})
	return checks
}

func cookieSubcheck(name string, failures, total int, applicable bool) Check {
	if !applicable || total == 0 {
		return Check{Name: name, Status: StatusPass, Detail: "n/a"}
	}
	if failures == 0 {
		return Check{Name: name, Status: StatusPass, Detail: fmt.Sprintf("%d cookie(s) compliant", total)}
	}
	if failures == total {
		return Check{Name: name, Status: StatusFail, Detail: fmt.Sprintf("%d cookie(s) non-compliant", failures)}
	}
	return Check{Name: name, Status: StatusWarning, Detail: fmt.Sprintf("%d of %d cookie(s) non-compliant", failures, total)}
}

func cookieName(raw string) string {
	part := strings.TrimSpace(strings.Split(raw, ";")[0])
	name, _, ok := strings.Cut(part, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(name)
}

func firstHeader(headers http.Header, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			return value
		}
	}
	return ""
}

func truncate(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
