package api

import (
	"net/http/httptest"
	"testing"

	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/enterprise"
	"github.com/dionebastos/vibesec/internal/store"
)

func TestHealthEndpoint(t *testing.T) {
	svc := newTestService(t)
	server := NewServer(svc)

	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestCreateScanRequiresAPIKey(t *testing.T) {
	svc := newTestService(t)
	server := NewServer(svc)

	req := httptest.NewRequest("POST", "/api/v1/scans", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != 401 {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
}

func newTestService(t *testing.T) *enterprise.Service {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/api.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return enterprise.NewService(config.Default(), st)
}
