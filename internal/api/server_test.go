package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

func TestCreateScanWithoutAPIKey(t *testing.T) {
	svc := newTestService(t)
	server := NewServer(svc)

	body := strings.NewReader(`{"target":"https://example.com"}`)
	req := httptest.NewRequest("POST", "/api/v1/scans", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != 202 {
		t.Fatalf("expected 202, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCreateScanInvalidBody(t *testing.T) {
	svc := newTestService(t)
	server := NewServer(svc)

	req := httptest.NewRequest("POST", "/api/v1/scans", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != 400 {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetScanAfterCreate(t *testing.T) {
	svc := newTestService(t)
	server := NewServer(svc)
	h := server.Handler()

	body := strings.NewReader(`{"target":"https://example.com"}`)
	req := httptest.NewRequest("POST", "/api/v1/scans", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 202 {
		t.Fatalf("create status %d body=%s", rec.Code, rec.Body.String())
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("missing scan id")
	}

	getReq := httptest.NewRequest("GET", "/api/v1/scans/"+id, nil)
	getRec := httptest.NewRecorder()
	h.ServeHTTP(getRec, getReq)
	if getRec.Code != 200 {
		t.Fatalf("get status %d body=%s", getRec.Code, getRec.Body.String())
	}
}

func TestGetScanEnrichesLegacyDocumentJSON(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)
	st := svc.Store()

	users, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) == 0 {
		t.Fatal("expected default admin user")
	}

	legacyDoc := `{"findings":[{"id":"headers/hsts","title":"HSTS","severity":"high","description":"Strict-Transport-Security header missing"}]}`
	id := store.NewID("scan")
	if _, err := st.CreateScan(ctx, id, store.CreateScanInput{
		UserID: users[0].ID,
		Target: "https://example.com",
		Status: store.ScanStatusCompleted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateScan(ctx, id, store.UpdateScanInput{
		Status:       store.ScanStatusCompleted,
		DocumentJSON: legacyDoc,
		Finished:     true,
	}); err != nil {
		t.Fatal(err)
	}

	server := NewServer(svc)
	req := httptest.NewRequest("GET", "/api/v1/scans/"+id, nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("get status %d body=%s", rec.Code, rec.Body.String())
	}

	var payload struct {
		DocumentJSON string `json:"document_json"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.DocumentJSON == "" {
		t.Fatal("expected document_json in response")
	}

	var doc struct {
		Findings []struct {
			LaypersonImpact         string `json:"layperson_impact"`
			LaypersonRecommendation string `json:"layperson_recommendation"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(payload.DocumentJSON), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(doc.Findings))
	}
	if doc.Findings[0].LaypersonImpact == "" {
		t.Fatal("expected layperson_impact in GET response for legacy scan")
	}
	if doc.Findings[0].LaypersonRecommendation == "" {
		t.Fatal("expected layperson_recommendation in GET response for legacy scan")
	}
	if strings.Contains(doc.Findings[0].LaypersonImpact, "Strict-Transport-Security") {
		t.Fatalf("layperson_impact should be PT, got: %s", doc.Findings[0].LaypersonImpact)
	}
}

func TestScanEventsNotFound(t *testing.T) {
	svc := newTestService(t)
	server := NewServer(svc)

	req := httptest.NewRequest("GET", "/api/v1/scans/missing-id/events", nil)
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)

	if rec.Code != 404 {
		t.Fatalf("expected 404, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestScanEventsInitialEvent(t *testing.T) {
	svc := newTestService(t)
	server := NewServer(svc)
	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)

	body := strings.NewReader(`{"target":"https://example.com"}`)
	req := httptest.NewRequest("POST", "/api/v1/scans", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	server.Handler().ServeHTTP(rec, req)
	if rec.Code != 202 {
		t.Fatalf("create status %d body=%s", rec.Code, rec.Body.String())
	}

	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id, _ := created["id"].(string)
	if id == "" {
		t.Fatal("missing scan id")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	sseReq, err := http.NewRequestWithContext(ctx, "GET", ts.URL+"/api/v1/scans/"+id+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(sseReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("expected text/event-stream, got %q", ct)
	}

	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	chunk := string(buf[:n])
	if !strings.Contains(chunk, "event: scan") {
		t.Fatalf("expected scan event, got: %s", chunk)
	}
	if !strings.Contains(chunk, `"status":"pending"`) {
		t.Fatalf("expected pending status, got: %s", chunk)
	}
}

func TestScanEventsClosesOnCompleted(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)
	server := NewServer(svc)
	st := svc.Store()

	users, err := st.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(users) == 0 {
		t.Fatal("expected default admin user")
	}

	id := store.NewID("scan")
	if _, err := st.CreateScan(ctx, id, store.CreateScanInput{
		UserID: users[0].ID,
		Target: "https://example.com",
		Status: store.ScanStatusCompleted,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateScan(ctx, id, store.UpdateScanInput{
		Status:   store.ScanStatusCompleted,
		Finished: true,
	}); err != nil {
		t.Fatal(err)
	}

	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)

	reqCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "GET", ts.URL+"/api/v1/scans/"+id+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	buf := make([]byte, 4096)
	n, err := resp.Body.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatal(err)
	}
	chunk := string(buf[:n])
	if !strings.Contains(chunk, `"status":"completed"`) {
		t.Fatalf("expected completed status, got: %s", chunk)
	}

	n2, err := resp.Body.Read(buf)
	if n2 > 0 {
		t.Fatalf("expected stream to close after terminal event, got extra: %s", string(buf[:n2]))
	}
	if err != io.EOF {
		t.Fatalf("expected EOF after terminal event, got: %v", err)
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
