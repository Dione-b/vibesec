package endpoint

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dionebastos/vibesec/internal/httpclient"
)

func TestDiscoverSafeMethodsOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodOptions:
			w.Header().Set("Allow", "GET, HEAD, OPTIONS")
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet, http.MethodHead:
			if r.URL.Path == "/api/users" {
				w.WriteHeader(http.StatusOK)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	defer server.Close()

	client, err := httpclient.New(httpclient.Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	result, err := Discover(context.Background(), server.URL, nil, client)
	if err != nil {
		t.Fatal(err)
	}
	if result.Count() == 0 {
		t.Fatal("expected probes")
	}
	for _, probe := range result.Matrix {
		switch probe.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
		default:
			t.Fatalf("unsafe method used: %s", probe.Method)
		}
	}
}
