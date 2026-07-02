package bundle

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/dionebastos/vibesec/internal/httpclient"
)

const (
	maxScripts    = 25
	maxScriptSize = 2 << 20 // 2MB
)

func Analyze(ctx context.Context, target string, page *httpclient.Response, client *httpclient.Client) (*Result, error) {
	if page == nil {
		return nil, fmt.Errorf("page response is nil")
	}
	if client == nil {
		return nil, fmt.Errorf("http client is nil")
	}

	base, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("invalid target URL")
	}

	result := &Result{}
	seen := make(map[string]struct{})

	result.CombinedContent = string(page.Body)
	scanContent(string(page.Body), result, seen)

	scriptURLs, err := extractScriptURLs(base, page.Body)
	if err != nil {
		return nil, err
	}
	if len(scriptURLs) > maxScripts {
		scriptURLs = scriptURLs[:maxScripts]
	}
	result.Scripts = scriptURLs

	for _, scriptURL := range scriptURLs {
		body, err := downloadScript(ctx, client, scriptURL)
		if err != nil {
			continue
		}
		result.CombinedContent += "\n" + body
		scanContent(body, result, seen)
	}

	return result, nil
}

func extractScriptURLs(base *url.URL, html []byte) ([]string, error) {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(html)))
	if err != nil {
		return nil, fmt.Errorf("parse html: %w", err)
	}

	seen := make(map[string]struct{})
	var urls []string
	doc.Find("script[src]").Each(func(_ int, sel *goquery.Selection) {
		src, ok := sel.Attr("src")
		if !ok {
			return
		}
		resolved, ok := resolveScriptURL(base, src)
		if !ok {
			return
		}
		if _, exists := seen[resolved]; exists {
			return
		}
		seen[resolved] = struct{}{}
		urls = append(urls, resolved)
	})
	return urls, nil
}

func downloadScript(ctx context.Context, client *httpclient.Client, scriptURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, scriptURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}
	if len(resp.Body) > maxScriptSize {
		return string(resp.Body[:maxScriptSize]), nil
	}
	return string(resp.Body), nil
}
