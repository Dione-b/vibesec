package fingerprint

import (
	"net/http"
	"regexp"
	"strings"
)

var (
	nextDataPattern      = regexp.MustCompile(`(?i)__NEXT_DATA__|/_next/static/`)
	reactPattern         = regexp.MustCompile(`(?i)react(?:-dom)?(?:\.production)?\.min\.js|data-reactroot|__react`)
	vuePattern           = regexp.MustCompile(`(?i)vue(?:\.runtime)?(?:\.global)?\.js|data-v-[a-f0-9]+`)
	angularPattern       = regexp.MustCompile(`(?i)ng-version=|angular(?:\.min)?\.js`)
	sveltePattern        = regexp.MustCompile(`(?i)svelte|__svelte`)
	vitePattern          = regexp.MustCompile(`(?i)/@vite/|vite/client`)
	graphqlPattern       = regexp.MustCompile(`(?i)/graphql|apollo`)
	prismaPattern        = regexp.MustCompile(`(?i)prisma`)
	aspnetPattern        = regexp.MustCompile(`(?i)__VIEWSTATE|asp\.net`)
	djangoPattern        = regexp.MustCompile(`(?i)csrfmiddlewaretoken|django`)
	laravelPattern       = regexp.MustCompile(`(?i)laravel|livewire`)
	laravelCookiePattern = regexp.MustCompile(`^eyJpdiI6`)
)

type bodyRule struct {
	pattern *regexp.Regexp
	name    string
}

var bodyFrameworkRules = []bodyRule{
	{nextDataPattern, "Next"},
	{reactPattern, "React"},
	{vuePattern, "Vue"},
	{angularPattern, "Angular"},
	{sveltePattern, "Svelte"},
	{vitePattern, "Vite"},
	{graphqlPattern, "GraphQL"},
	{prismaPattern, "Prisma"},
	{aspnetPattern, "ASP.NET"},
	{djangoPattern, "Django"},
	{laravelPattern, "Laravel"},
}

var cookieFrameworkRules = map[string]string{
	"laravel_session": "Laravel",
	"connect.sid":     "Express",
	"csrftoken":       "Django",
	"sessionid":       "Django",
	"jsessionid":      "Spring",
	"asp.net_sessionid": "ASP.NET",
	"__secure-next-auth.session-token": "Next",
	"next-auth.session-token":          "Next",
}

func detectFrameworks(headers http.Header, body []byte) []string {
	seen := make(map[string]struct{})
	var frameworks []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		frameworks = append(frameworks, name)
	}

	poweredBy := strings.ToLower(headers.Get("X-Powered-By"))
	switch {
	case strings.Contains(poweredBy, "express"):
		add("Express")
	case strings.Contains(poweredBy, "php"):
		add("PHP")
	case strings.Contains(poweredBy, "asp.net"):
		add("ASP.NET")
	case strings.Contains(poweredBy, "next"):
		add("Next")
	}

	server := strings.ToLower(headers.Get("Server"))
	if strings.Contains(server, "nginx") {
		add("Nginx")
	}
	if strings.Contains(server, "apache") {
		add("Apache")
	}

	if headers.Get("X-Fastify-Request-Id") != "" || headers.Get("Fastify-Request-Id") != "" {
		add("Fastify")
	}

	for _, raw := range headers.Values("Set-Cookie") {
		name := strings.ToLower(cookieName(raw))
		if fw, ok := cookieFrameworkRules[name]; ok {
			add(fw)
		}
		if laravelCookiePattern.MatchString(cookieValue(raw)) {
			add("Laravel")
		}
	}

	bodyText := string(body)
	for _, rule := range bodyFrameworkRules {
		if rule.pattern.MatchString(bodyText) {
			add(rule.name)
		}
	}

	if strings.Contains(bodyText, "flask") {
		add("Flask")
	}
	if strings.Contains(strings.ToLower(bodyText), "spring") && strings.Contains(strings.ToLower(bodyText), "boot") {
		add("Spring")
	}

	return frameworks
}
