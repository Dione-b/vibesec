package fingerprint

import "strings"

type TLSInfo struct {
	Version string `json:"version"`
	Cipher  string `json:"cipher"`
	Issuer  string `json:"issuer,omitempty"`
}

type CookieInfo struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	SameSite string `json:"same_site,omitempty"`
}

type Result struct {
	Server     string       `json:"server,omitempty"`
	PoweredBy  string       `json:"powered_by,omitempty"`
	TLS        TLSInfo      `json:"tls"`
	Cookies    []CookieInfo `json:"cookies,omitempty"`
	Infra      []string     `json:"infra,omitempty"`
	Frameworks []string     `json:"frameworks,omitempty"`
	Stack      []string     `json:"stack,omitempty"`
}

func (r *Result) BuildStack() {
	if r == nil {
		return
	}
	seen := make(map[string]struct{})
	var stack []string
	add := func(items ...string) {
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			key := strings.ToLower(item)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			stack = append(stack, item)
		}
	}

	add(runtimeFromFrameworks(r.Frameworks)...)
	add(r.Frameworks...)
	add(r.Infra...)
	if r.Server != "" {
		add(r.Server)
	}

	r.Stack = stack
}

func runtimeFromFrameworks(frameworks []string) []string {
	var runtimes []string
	for _, fw := range frameworks {
		switch strings.ToLower(fw) {
		case "express", "fastify", "next", "react", "vue", "angular", "svelte":
			runtimes = append(runtimes, "Node")
		case "laravel":
			runtimes = append(runtimes, "PHP")
		case "django", "flask":
			runtimes = append(runtimes, "Python")
		case "spring":
			runtimes = append(runtimes, "Java")
		case "asp.net":
			runtimes = append(runtimes, ".NET")
		}
	}
	return runtimes
}
