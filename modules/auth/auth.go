package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/dionebastos/vibesec/internal/auth"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/fingerprint"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	page, err := ctx.FetchPage(context.Background())
	if err != nil {
		return nil, err
	}

	input := auth.Input{
		Target:  ctx.Target,
		Headers: page.Headers,
		Body:    page.Body,
	}
	input.Cookies = cookiesFromFingerprint(ctx.Fingerprint)
	if len(input.Cookies) == 0 {
		input.Cookies = cookiesFromHeaders(page.Headers)
	}
	if ctx.Endpoints != nil {
		for _, probe := range ctx.Endpoints.Matrix {
			input.EndpointProbes = append(input.EndpointProbes, auth.EndpointProbe{
				Path:   probe.Path,
				Method: probe.Method,
				Status: probe.Status,
			})
		}
	}
	if ctx.Bundle != nil {
		input.BundleLibraries = append([]string(nil), ctx.Bundle.Libraries...)
	}

	result := auth.Analyze(input)
	ctx.Auth = result

	signals := make([]finding.AuthSignal, len(result.Signals))
	for i, s := range result.Signals {
		signals[i] = finding.AuthSignal{Category: s.Category, Status: s.Status, Detail: s.Detail}
	}
	return finding.FromAuth(&finding.AuthSnapshot{Signals: signals}), nil
}

func cookiesFromFingerprint(fp *fingerprint.Result) []auth.Cookie {
	if fp == nil {
		return nil
	}
	cookies := make([]auth.Cookie, len(fp.Cookies))
	for i, c := range fp.Cookies {
		cookies[i] = auth.Cookie{
			Name:     c.Name,
			Secure:   c.Secure,
			HttpOnly: c.HttpOnly,
			SameSite: c.SameSite,
		}
	}
	return cookies
}

func cookiesFromHeaders(headers http.Header) []auth.Cookie {
	var cookies []auth.Cookie
	for _, raw := range headers.Values("Set-Cookie") {
		name := cookieName(raw)
		if name == "" {
			continue
		}
		lower := strings.ToLower(raw)
		cookies = append(cookies, auth.Cookie{
			Name:     name,
			Secure:   strings.Contains(lower, "secure"),
			HttpOnly: strings.Contains(lower, "httponly"),
			SameSite: parseSameSite(lower),
		})
	}
	return cookies
}

func cookieName(raw string) string {
	part := strings.TrimSpace(strings.Split(raw, ";")[0])
	name, _, ok := strings.Cut(part, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(name)
}

func parseSameSite(raw string) string {
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "samesite=") {
			return strings.TrimPrefix(part, "samesite=")
		}
	}
	return ""
}
