package endpoint

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/dionebastos/vibesec/internal/bundle"
	"github.com/dionebastos/vibesec/internal/httpclient"
)

const maxPaths = 80

var safeMethods = []string{http.MethodHead, http.MethodGet, http.MethodOptions}

func Discover(ctx context.Context, target string, bundleResult *bundle.Result, client *httpclient.Client) (*Result, error) {
	base, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}

	paths := collectPaths(bundleResult)
	paths = append(paths, loadWordlist()...)
	paths = uniquePaths(paths)
	if len(paths) > maxPaths {
		paths = paths[:maxPaths]
	}

	result := &Result{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10)

	for _, path := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			probes := probePath(ctx, client, base, path)
			if len(probes) == 0 {
				return
			}
			mu.Lock()
			result.Matrix = append(result.Matrix, probes...)
			mu.Unlock()
		}(path)
	}
	wg.Wait()

	sort.Slice(result.Matrix, func(i, j int) bool {
		if result.Matrix[i].Path == result.Matrix[j].Path {
			return result.Matrix[i].Method < result.Matrix[j].Method
		}
		return result.Matrix[i].Path < result.Matrix[j].Path
	})
	return result, nil
}

func collectPaths(bundleResult *bundle.Result) []string {
	if bundleResult == nil {
		return nil
	}
	var paths []string
	paths = append(paths, bundleResult.Routes...)
	paths = append(paths, bundleResult.Endpoints...)
	paths = append(paths, bundleResult.AdminPages...)
	return paths
}

func loadWordlist() []string {
	candidates := []string{
		"tools/wordlists/common.txt",
		filepath.Join("tools", "wordlists", "common.txt"),
	}
	for _, path := range candidates {
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		defer file.Close()

		var paths []string
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			paths = append(paths, line)
		}
		return paths
	}
	return defaultWordlist()
}

func defaultWordlist() []string {
	return []string{"/", "/api", "/admin", "/login", "/robots.txt"}
}

func uniquePaths(paths []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, path := range paths {
		path = normalizePath(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out
}

func normalizePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func probePath(ctx context.Context, client *httpclient.Client, base *url.URL, path string) []Probe {
	full := base.ResolveReference(&url.URL{Path: path}).String()
	var probes []Probe

	for _, method := range safeMethods {
		req, err := http.NewRequestWithContext(ctx, method, full, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}

		probe := Probe{
			Path:   path,
			Method: method,
			Status: resp.StatusCode,
		}
		if method == http.MethodOptions {
			probe.AllowedMethods = resp.Headers.Get("Allow")
			if probe.AllowedMethods == "" {
				probe.AllowedMethods = resp.Headers.Get("Access-Control-Allow-Methods")
			}
		}
		probes = append(probes, probe)
	}
	return probes
}
