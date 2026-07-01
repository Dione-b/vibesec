package recon

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/dionebastos/vibesec/internal/scanctx"
	"github.com/dionebastos/vibesec/internal/ui"
)

type Asset struct {
	Path    string
	Status  int
	Summary string
}

type Result struct {
	Assets []Asset
}

func Collect(ctx *scanctx.Context) (*Result, error) {
	base, err := url.Parse(ctx.Target)
	if err != nil {
		return nil, err
	}

	paths := []struct {
		path    string
		summary func(body string, status int) string
	}{
		{"/robots.txt", summarizeRobots},
		{"/sitemap.xml", summarizeSitemap},
		{"/.well-known/security.txt", summarizeText},
		{"/openapi.json", summarizeJSON},
		{"/swagger", summarizeHTML},
		{"/graphql", summarizeGraphQL},
	}

	result := &Result{}
	for _, item := range paths {
		full := base.ResolveReference(&url.URL{Path: item.path}).String()
		resp, err := ctx.HTTP.Get(context.Background(), full)
		if err != nil {
			continue
		}
		summary := item.summary(string(resp.Body), resp.StatusCode)
		if resp.StatusCode >= 400 && summary == "" {
			continue
		}
		result.Assets = append(result.Assets, Asset{
			Path:    item.path,
			Status:  resp.StatusCode,
			Summary: summary,
		})
	}
	return result, nil
}

func FormatOutput(result *Result) []string {
	if result == nil || len(result.Assets) == 0 {
		return []string{"", ui.Muted("  no additional recon assets found")}
	}
	lines := []string{"", ui.Subsection("Recon assets"), ""}
	for _, asset := range result.Assets {
		line := fmt.Sprintf("  %-28s %d", asset.Path, asset.Status)
		if asset.Summary != "" {
			line += "  " + ui.Muted(asset.Summary)
		}
		lines = append(lines, line)
	}
	return lines
}

func summarizeRobots(body string, status int) string {
	if status >= 400 {
		return ""
	}
	lines := strings.Split(body, "\n")
	count := 0
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "disallow:") {
			count++
		}
	}
	return fmt.Sprintf("%d disallow rules", count)
}

func summarizeSitemap(body string, status int) string {
	if status >= 400 {
		return ""
	}
	return fmt.Sprintf("%d <loc> entries", strings.Count(strings.ToLower(body), "<loc>"))
}

func summarizeText(body string, status int) string {
	if status >= 400 || strings.TrimSpace(body) == "" {
		return ""
	}
	return truncate(body, 60)
}

func summarizeJSON(body string, status int) string {
	if status >= 400 {
		return ""
	}
	if strings.Contains(body, "openapi") || strings.Contains(body, "swagger") {
		return "OpenAPI document detected"
	}
	return truncate(body, 40)
}

func summarizeHTML(body string, status int) string {
	if status >= 400 {
		return ""
	}
	lower := strings.ToLower(body)
	if strings.Contains(lower, "swagger") {
		return "Swagger UI detected"
	}
	return ""
}

func summarizeGraphQL(body string, status int) string {
	if status == http.StatusBadRequest && strings.Contains(strings.ToLower(body), "graphql") {
		return "GraphQL endpoint responds"
	}
	if status < 400 {
		return "reachable"
	}
	return ""
}

func truncate(value string, max int) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}
