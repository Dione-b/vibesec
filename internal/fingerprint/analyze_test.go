package fingerprint

import (
	"net/http"
	"testing"

	"github.com/dionebastos/vibesec/internal/httpclient"
)

func TestAnalyzeCloudflareNext(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("CF-RAY", "abc123")
	headers.Set("Set-Cookie", "session=1; Secure; HttpOnly; SameSite=Lax")

	body := []byte(`<html><script src="/_next/static/chunks/main.js"></script><script id="__NEXT_DATA__">{}</script></html>`)
	resp := &httpclient.Response{
		StatusCode: 200,
		Headers:    headers,
		Body:       body,
		URL:        "https://app.example.com",
	}

	result, err := Analyze("https://app.example.com", resp)
	if err != nil {
		t.Fatal(err)
	}

	if !contains(result.Infra, "Cloudflare") {
		t.Fatalf("expected Cloudflare infra, got %v", result.Infra)
	}
	if !contains(result.Frameworks, "Next") {
		t.Fatalf("expected Next framework, got %v", result.Frameworks)
	}
	if !contains(result.Stack, "Node") {
		t.Fatalf("expected Node in stack, got %v", result.Stack)
	}
	if len(result.Cookies) != 1 || result.Cookies[0].Name != "session" {
		t.Fatalf("unexpected cookies: %+v", result.Cookies)
	}
}

func TestAnalyzeExpressFromCookie(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Powered-By", "Express")
	headers.Set("Set-Cookie", "connect.sid=s%3Aabc; Path=/; HttpOnly")

	resp := &httpclient.Response{
		StatusCode: 200,
		Headers:    headers,
		Body:       []byte("<html></html>"),
		URL:        "https://api.example.com",
	}

	result, err := Analyze("https://api.example.com", resp)
	if err != nil {
		t.Fatal(err)
	}

	if !contains(result.Frameworks, "Express") {
		t.Fatalf("expected Express, got %v", result.Frameworks)
	}
}

func contains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
