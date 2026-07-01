package auth

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

type Cookie struct {
	Name     string
	Secure   bool
	HttpOnly bool
	SameSite string
}

type Input struct {
	Target          string
	Headers         http.Header
	Body            []byte
	Cookies         []Cookie
	EndpointProbes  []EndpointProbe
	BundleLibraries []string
	BundleContent   string
}

type EndpointProbe struct {
	Path   string
	Method string
	Status int
}

var (
	jwtPattern      = regexp.MustCompile(`(?i)jwt\.decode|jsonwebtoken|Bearer\s+[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
	rolePattern     = regexp.MustCompile(`(?i)(isAdmin|userRole|role\s*===|role\s*==|checkRole|hasRole)`)
	oauthPattern    = regexp.MustCompile(`(?i)oauth|openid-connect|oidc|next-auth|auth0`)
	csrfPattern     = regexp.MustCompile(`(?i)csrf|xsrf|_token|csrftoken`)
	localJWTStorage = regexp.MustCompile(`(?i)localStorage\.(setItem|getItem)\s*\(\s*['"](?:token|jwt|access_token)`)
)

func Analyze(in Input) *Result {
	result := &Result{}
	isHTTPS := isHTTPSTarget(in.Target)
	body := string(in.Body)
	if in.BundleContent != "" {
		body += "\n" + in.BundleContent
	}

	result.Mechanisms = detectMechanisms(in, body)
	result.LoginPath, result.LogoutPath, result.RefreshPath = detectAuthPaths(in.EndpointProbes)

	result.Signals = append(result.Signals, analyzeCookies(in.Cookies, isHTTPS)...)
	result.Signals = append(result.Signals, analyzeJWT(body)...)
	result.Signals = append(result.Signals, analyzeCSRF(body, in.Cookies)...)
	result.Signals = append(result.Signals, analyzeOAuthOIDC(body, in.BundleLibraries)...)
	result.Signals = append(result.Signals, analyzeRoles(body)...)
	result.Signals = append(result.Signals, analyzeSession(in.Cookies, in.Headers)...)
	result.Signals = append(result.Signals, analyzeAuthEndpoints(result)...)

	return result
}

func isHTTPSTarget(target string) bool {
	parsed, err := url.Parse(target)
	if err != nil {
		return strings.HasPrefix(strings.ToLower(target), "https://")
	}
	return parsed.Scheme == "https"
}

func detectMechanisms(in Input, body string) []string {
	seen := map[string]struct{}{}
	var mechanisms []string
	add := func(name string) {
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		mechanisms = append(mechanisms, name)
	}

	for _, c := range in.Cookies {
		lower := strings.ToLower(c.Name)
		if strings.Contains(lower, "session") || lower == "connect.sid" {
			add("Session cookie")
		}
	}
	if jwtPattern.MatchString(body) {
		add("JWT")
	}
	if oauthPattern.MatchString(body) {
		add("OAuth/OIDC")
	}
	if csrfPattern.MatchString(body) {
		add("CSRF token")
	}
	for _, lib := range in.BundleLibraries {
		switch lib {
		case "JWT":
			add("JWT")
		case "CSRF":
			add("CSRF token")
		}
	}
	return mechanisms
}

func detectAuthPaths(probes []EndpointProbe) (login, logout, refresh string) {
	for _, probe := range probes {
		if probe.Method != http.MethodGet || probe.Status >= 400 {
			continue
		}
		lower := strings.ToLower(probe.Path)
		switch {
		case strings.Contains(lower, "login"):
			login = probe.Path
		case strings.Contains(lower, "logout"):
			logout = probe.Path
		case strings.Contains(lower, "refresh"):
			refresh = probe.Path
		}
	}
	return login, logout, refresh
}

func analyzeCookies(cookies []Cookie, isHTTPS bool) []Signal {
	if len(cookies) == 0 {
		return []Signal{{Category: "Cookies", Status: StatusInfo, Detail: "no session cookies observed"}}
	}

	var signals []Signal
	for _, cookie := range cookies {
		name := cookie.Name
		if !looksLikeSessionCookie(name) {
			continue
		}
		if isHTTPS && !cookie.Secure {
			signals = append(signals, Signal{
				Category: "Cookies",
				Status:   StatusFail,
				Detail:   name + " missing Secure flag",
			})
		}
		if !cookie.HttpOnly {
			signals = append(signals, Signal{
				Category: "Cookies",
				Status:   StatusFail,
				Detail:   name + " missing HttpOnly flag",
			})
		}
		if cookie.SameSite == "" {
			signals = append(signals, Signal{
				Category: "Cookies",
				Status:   StatusWarning,
				Detail:   name + " missing SameSite attribute",
			})
		}
	}
	if len(signals) == 0 {
		return []Signal{{Category: "Cookies", Status: StatusPass, Detail: "session cookies look compliant"}}
	}
	return signals
}

func looksLikeSessionCookie(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "session") ||
		lower == "connect.sid" ||
		strings.Contains(lower, "auth") ||
		strings.Contains(lower, "token")
}

func analyzeJWT(body string) []Signal {
	if !jwtPattern.MatchString(body) {
		return []Signal{{Category: "JWT", Status: StatusInfo, Detail: "no JWT usage detected in client code"}}
	}
	if localJWTStorage.MatchString(body) {
		return []Signal{{
			Category: "JWT",
			Status:   StatusWarning,
			Detail:   "JWT may be stored in localStorage",
		}}
	}
	return []Signal{{Category: "JWT", Status: StatusPass, Detail: "JWT references found without localStorage storage pattern"}}
}

func analyzeCSRF(body string, cookies []Cookie) []Signal {
	hasSession := false
	for _, c := range cookies {
		if looksLikeSessionCookie(c.Name) {
			hasSession = true
			break
		}
	}
	if !hasSession {
		return []Signal{{Category: "CSRF", Status: StatusInfo, Detail: "no session cookie to protect"}}
	}
	if csrfPattern.MatchString(body) {
		return []Signal{{Category: "CSRF", Status: StatusPass, Detail: "CSRF token patterns present"}}
	}
	return []Signal{{
		Category: "CSRF",
		Status:   StatusWarning,
		Detail:   "session cookie without visible CSRF token pattern",
	}}
}

func analyzeOAuthOIDC(body string, libraries []string) []Signal {
	for _, lib := range libraries {
		if strings.Contains(strings.ToLower(lib), "oauth") {
			return []Signal{{Category: "OAuth/OIDC", Status: StatusInfo, Detail: "OAuth/OIDC integration detected"}}
		}
	}
	if oauthPattern.MatchString(body) {
		return []Signal{{Category: "OAuth/OIDC", Status: StatusInfo, Detail: "OAuth/OIDC patterns in client code"}}
	}
	return nil
}

func analyzeRoles(body string) []Signal {
	if rolePattern.MatchString(body) {
		return []Signal{{
			Category: "Roles",
			Status:   StatusWarning,
			Detail:   "client-side role checks detected",
		}}
	}
	return []Signal{{Category: "Roles", Status: StatusPass, Detail: "no obvious client-side role checks"}}
}

func analyzeSession(cookies []Cookie, headers http.Header) []Signal {
	if len(cookies) == 0 {
		return nil
	}
	if headers.Get("Set-Cookie") != "" && !strings.Contains(strings.ToLower(headers.Get("Cache-Control")), "no-store") {
		return []Signal{{
			Category: "Session",
			Status:   StatusWarning,
			Detail:   "session issued on GET without no-store cache directive",
		}}
	}
	return []Signal{{Category: "Session", Status: StatusPass, Detail: "session response caching looks acceptable"}}
}

func analyzeAuthEndpoints(result *Result) []Signal {
	var signals []Signal
	if result.LoginPath != "" {
		signals = append(signals, Signal{Category: "Login", Status: StatusInfo, Detail: result.LoginPath + " reachable"})
	}
	if result.LogoutPath != "" {
		signals = append(signals, Signal{Category: "Logout", Status: StatusInfo, Detail: result.LogoutPath + " reachable"})
	}
	if result.RefreshPath != "" {
		signals = append(signals, Signal{
			Category: "Refresh",
			Status:   StatusWarning,
			Detail:   result.RefreshPath + " reachable via GET",
		})
	}
	return signals
}
