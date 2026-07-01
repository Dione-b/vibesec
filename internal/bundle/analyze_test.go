package bundle

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dionebastos/vibesec/internal/httpclient"
)

func TestAnalyzeScriptsAndLibraries(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>
				<script src="/app.js"></script>
				<script>const route = { path: "/dashboard" }</script>
			</body></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`axios.get("/api/users"); fetch("/admin/panel");`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}

	result, err := Analyze(context.Background(), server.URL, page, client)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(result.Libraries, "Axios") {
		t.Fatalf("expected Axios, got %v", result.Libraries)
	}
	if !contains(result.Libraries, "Fetch") {
		t.Fatalf("expected Fetch, got %v", result.Libraries)
	}
	if result.EndpointCount() == 0 {
		t.Fatalf("expected endpoints, got %v", result.Endpoints)
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
