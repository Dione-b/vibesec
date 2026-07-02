package headers

import (
	"net/http"
	"testing"

	"github.com/dionebastos/vibesec/internal/httpclient"
)

func TestAnalyzeEscrithaLikeHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("X-Frame-Options", "SAMEORIGIN")
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("Cache-Control", "no-cache, private")
	headers.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	headers.Set("Set-Cookie", "escritha_session=abc; path=/; httponly")

	resp := &httpclient.Response{
		StatusCode: 200,
		Headers:    headers,
		URL:        "https://escritha.com",
	}

	result, err := Analyze("https://escritha.com", resp, true)
	if err != nil {
		t.Fatal(err)
	}

	assertCheck(t, result, "XFO", StatusPass)
	assertCheck(t, result, "Cache Control", StatusPass)
	assertCheck(t, result, "CSP", StatusFail)
	assertCheck(t, result, "HSTS", StatusFail)
	assertCheck(t, result, "Cookies Secure", StatusFail)
}

func TestAnalyzeStrongSecurityHeaders(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	headers.Set("Permissions-Policy", "camera=(), microphone=()")
	headers.Set("Cache-Control", "no-store")
	headers.Set("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Strict")

	resp := &httpclient.Response{StatusCode: 200, Headers: headers, URL: "https://secure.example.com"}
	result, err := Analyze("https://secure.example.com", resp, false)
	if err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"HSTS", "CSP", "XFO", "Referrer Policy", "Permissions Policy", "Cache Control", "Cookies Secure", "Cookies HttpOnly", "Cookies SameSite"} {
		assertCheck(t, result, name, StatusPass)
	}
}

func TestAnalyzeHTTPHSTSInfo(t *testing.T) {
	headers := http.Header{}
	resp := &httpclient.Response{StatusCode: 200, Headers: headers, URL: "http://localhost:3000"}
	result, err := Analyze("http://localhost:3000", resp, false)
	if err != nil {
		t.Fatal(err)
	}
	assertCheck(t, result, "HSTS", StatusInfo)
}

func TestAnalyzeRateLimitInfo(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Frame-Options", "DENY")
	resp := &httpclient.Response{StatusCode: 200, Headers: headers, URL: "https://secure.example.com"}
	result, err := Analyze("https://secure.example.com", resp, false)
	if err != nil {
		t.Fatal(err)
	}
	assertCheck(t, result, "Rate Limit", StatusInfo)
}

func assertCheck(t *testing.T, result *Result, name, want string) {
	t.Helper()
	for _, check := range result.Checks {
		if check.Name == name {
			if check.Status != want {
				t.Fatalf("%s: got %s want %s (%s)", name, check.Status, want, check.Detail)
			}
			return
		}
	}
	t.Fatalf("check %q not found", name)
}
