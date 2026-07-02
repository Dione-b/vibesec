package httpclient

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	"golang.org/x/net/http2"
)

func buildTransport(opts Options) (http.RoundTripper, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: opts.TLSInsecure,
		MinVersion:         tls.VersionTLS12,
	}
	transport := &http.Transport{
		Proxy:             proxyFunc(opts.ProxyURL),
		ForceAttemptHTTP2: true,
		TLSClientConfig:   tlsCfg,
	}
	if err := http2.ConfigureTransport(transport); err != nil {
		return nil, fmt.Errorf("configure http2: %w", err)
	}
	return transport, nil
}

func proxyFunc(raw string) func(*http.Request) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return http.ProxyFromEnvironment
	}
	proxyURL, err := url.Parse(raw)
	if err != nil {
		return func(*http.Request) (*url.URL, error) {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
	}
	return http.ProxyURL(proxyURL)
}

func newCookieJar() http.CookieJar {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil
	}
	return jar
}

func redirectPolicy(maxRedirects int) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		originalHost := via[0].URL.Hostname()
		redirectHost := req.URL.Hostname()
		if redirectHost != originalHost && !IsAllowedRedirectHost(redirectHost) {
			return fmt.Errorf("redirect blocked: %s is not allowed", redirectHost)
		}
		return nil
	}
}
