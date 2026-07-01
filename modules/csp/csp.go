package csp

import (
	"context"
	"strings"

	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/scanctx"
)

func Run(ctx *scanctx.Context) ([]finding.Finding, error) {
	policy := extractPolicy(ctx)
	if strings.TrimSpace(policy) == "" {
		return nil, nil
	}
	return finding.FromCSP(policy, false), nil
}

func extractPolicy(ctx *scanctx.Context) string {
	if ctx.Headers != nil {
		for _, check := range ctx.Headers.Checks {
			if check.Name == "CSP" && check.Status != "FAIL" && check.Detail != "" {
				return check.Detail
			}
		}
	}
	page, err := ctx.FetchPage(context.Background())
	if err != nil {
		return ""
	}
	return strings.TrimSpace(firstHeader(page.Headers, "Content-Security-Policy", "Content-Security-Policy-Report-Only"))
}

func firstHeader(headers interface{ Get(string) string }, names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(headers.Get(name)); value != "" {
			return value
		}
	}
	return ""
}
