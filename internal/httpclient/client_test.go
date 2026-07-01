package httpclient

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
)

func TestClientGet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Fatal("expected user-agent")
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html>ok</html>"))
	}))
	defer server.Close()

	client, err := New(Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	if !strings.Contains(string(resp.Body), "ok") {
		t.Fatalf("body: %q", resp.Body)
	}
}

func TestClientFollowsRedirects(t *testing.T) {
	var finalURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			http.Redirect(w, r, "/next", http.StatusFound)
		case "/next":
			finalURL = r.URL.String()
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(Options{Timeout: 5 * time.Second, MaxRedirects: 5})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	if !strings.HasSuffix(finalURL, "/next") {
		t.Fatalf("final path: %s", finalURL)
	}
}

func TestClientDecodesGzip(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte("gzip-body"))
		_ = gz.Close()
	}))
	defer server.Close()

	client, err := New(Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "gzip-body" {
		t.Fatalf("body: %q", resp.Body)
	}
}

func TestClientDecodesBrotli(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		br := brotli.NewWriter(w)
		_, _ = br.Write([]byte("brotli-body"))
		_ = br.Close()
	}))
	defer server.Close()

	client, err := New(Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Body) != "brotli-body" {
		t.Fatalf("body: %q", resp.Body)
	}
}

func TestClientRetriesOn503(t *testing.T) {
	var hits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&hits, 1)
		if n < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer server.Close()

	client, err := New(Options{
		Timeout:      5 * time.Second,
		Retries:      3,
		RetryBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Get(context.Background(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
	if atomic.LoadInt32(&hits) < 3 {
		t.Fatalf("expected at least 3 attempts, got %d", hits)
	}
}

func TestClientStoresCookies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/set":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc"})
			w.WriteHeader(http.StatusOK)
		case "/check":
			if _, err := r.Cookie("session"); err != nil {
				http.Error(w, "missing cookie", http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := New(Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.Get(context.Background(), server.URL+"/set"); err != nil {
		t.Fatal(err)
	}
	resp, err := client.Get(context.Background(), server.URL+"/check")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d", resp.StatusCode)
	}
}
