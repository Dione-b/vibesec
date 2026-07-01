package fingerprint

import (
	"net/http"
	"testing"

	"github.com/dionebastos/vibesec/internal/httpclient"
)

func TestAnalyzeLaravelEncryptedSessionCookie(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")
	headers.Set("CF-RAY", "abc123")
	headers.Set("Set-Cookie", "escritha_session=eyJpdiI6InExVlNtRXZmUVhWYlwvSjhvRVhySjlBPT0iLCJ2YWx1ZSI6InFhUUhNN1A0RXBJZHA1M2J4a1BnWG9KQTZLWU5va3k5R1hmdFwvZjB2UWZyNFwvbmx4S3c2NVFHUUwwSmxXajhscXVrTjRnRmZTeEFPdmgyRXVCeXFFMUVsUnQ3dHErcVhQeSt0WjFMeVRreHUwVUhsRkgrVnQzMVJ5aDRzOStldnoiLCJtYWMiOiI3YjNjNzRkZDRiZDMzYmE5YmM0ODIwNTg0NzFjMDI0MGI3Y2NiODkwZjZlODFhODYyOWFlY2M2YTQ3NDQ4YzRlIn0%3D; path=/; httponly")

	resp := &httpclient.Response{
		StatusCode: 200,
		Headers:    headers,
		Body:       []byte("<html></html>"),
		URL:        "https://escritha.com",
	}

	result, err := Analyze("https://escritha.com", resp)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(result.Frameworks, "Laravel") {
		t.Fatalf("expected Laravel, got %v", result.Frameworks)
	}
	if !contains(result.Stack, "PHP") {
		t.Fatalf("expected PHP runtime, got %v", result.Stack)
	}
}
