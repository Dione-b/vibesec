package fingerprint

import (
	"net/http"
	"strings"
)

type headerRule struct {
	header string
	match  func(value string) bool
	name   string
}

var infraHeaderRules = []headerRule{
	{header: "cf-ray", match: always, name: "Cloudflare"},
	{header: "cf-cache-status", match: always, name: "Cloudflare"},
	{header: "server", match: containsFold("cloudflare"), name: "Cloudflare"},
	{header: "x-vercel-id", match: always, name: "Vercel"},
	{header: "server", match: containsFold("vercel"), name: "Vercel"},
	{header: "fly-request-id", match: always, name: "Fly.io"},
	{header: "server", match: containsFold("fly.io"), name: "Fly.io"},
	{header: "x-railway-edge", match: always, name: "Railway"},
	{header: "x-railway-request-id", match: always, name: "Railway"},
	{header: "x-render-origin-server", match: always, name: "Render"},
	{header: "server", match: containsFold("render"), name: "Render"},
	{header: "x-nf-request-id", match: always, name: "Netlify"},
	{header: "server", match: containsFold("netlify"), name: "Netlify"},
	{header: "x-amz-cf-id", match: always, name: "AWS"},
	{header: "x-amz-request-id", match: always, name: "AWS"},
	{header: "via", match: containsFold("cloudfront"), name: "AWS"},
	{header: "server", match: containsFold("amazon"), name: "AWS"},
	{header: "x-azure-ref", match: always, name: "Azure"},
	{header: "server", match: containsFold("microsoft-iis"), name: "Azure"},
	{header: "via", match: containsFold("google"), name: "GCP"},
	{header: "server", match: containsFold("gws"), name: "GCP"},
}

func detectInfra(headers http.Header, finalURL string) []string {
	seen := make(map[string]struct{})
	var infra []string
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		infra = append(infra, name)
	}

	for _, rule := range infraHeaderRules {
		value := headers.Get(rule.header)
		if value != "" && rule.match(value) {
			add(rule.name)
		}
	}

	lowerURL := strings.ToLower(finalURL)
	switch {
	case strings.Contains(lowerURL, "cloudflare"):
		add("Cloudflare")
	case strings.Contains(lowerURL, "vercel.app"):
		add("Vercel")
	case strings.Contains(lowerURL, "fly.dev"):
		add("Fly.io")
	case strings.Contains(lowerURL, "railway.app"):
		add("Railway")
	case strings.Contains(lowerURL, "onrender.com"):
		add("Render")
	case strings.Contains(lowerURL, "netlify.app"):
		add("Netlify")
	}

	return infra
}

func always(string) bool { return true }

func containsFold(needle string) func(string) bool {
	needle = strings.ToLower(needle)
	return func(value string) bool {
		return strings.Contains(strings.ToLower(value), needle)
	}
}
