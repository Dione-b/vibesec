package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dionebastos/vibesec/internal/enterprise"
	"github.com/dionebastos/vibesec/internal/httpclient"
	"github.com/dionebastos/vibesec/internal/report"
	"github.com/dionebastos/vibesec/internal/store"
)

type Server struct {
	service        *enterprise.Service
	mux            *http.ServeMux
	rateLimiter    *rateLimiter
	allowedOrigins []string
	frontend       http.Handler
}

func NewServer(service *enterprise.Service) *Server {
	s := &Server{
		service:        service,
		mux:            http.NewServeMux(),
		rateLimiter:    newRateLimiter(60, time.Minute),
		allowedOrigins: []string{},
	}
	s.routes()
	return s
}

func NewServerWithOrigins(service *enterprise.Service, origins []string) *Server {
	s := NewServer(service)
	if len(origins) > 0 {
		s.allowedOrigins = origins
	}
	return s
}

func (s *Server) SetFrontend(h http.Handler) {
	s.frontend = h
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /api/", s.withRateLimit(s.mux))
	mux.Handle("POST /api/", s.withRateLimit(s.mux))
	mux.HandleFunc("/", s.handleFrontend)
	return s.withCORS(mux)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/scans", s.handleListScans)
	s.mux.HandleFunc("POST /api/v1/scans", s.handleCreateScan)
	s.mux.HandleFunc("GET /api/v1/scans/{id}", s.handleGetScan)
	s.mux.HandleFunc("GET /api/v1/schedules", s.handleListSchedules)
	s.mux.HandleFunc("POST /api/v1/schedules", s.handleCreateSchedule)
}

func (s *Server) handleFrontend(w http.ResponseWriter, r *http.Request) {
	if s.frontend != nil {
		s.frontend.ServeHTTP(w, r)
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(dashboardHTML)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) handleListScans(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil {
			limit = n
		}
	}
	if limit < 1 || limit > 500 {
		limit = 50
	}
	items, err := s.service.Store().ListScans(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list scans"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": items})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	item, err := s.service.Store().GetScan(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, errors.New("scan not found"))
			return
		}
		writeError(w, http.StatusInternalServerError, errors.New("failed to load scan"))
		return
	}
	if item.DocumentJSON != "" {
		if enriched, err := report.EnrichDocumentJSON(item.DocumentJSON); err == nil {
			item.DocumentJSON = enriched
		}
	}
	writeJSON(w, http.StatusOK, item)
}

type createScanRequest struct {
	Target string `json:"target"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	user, err := s.defaultUser(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to resolve user"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	var req createScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeError(w, http.StatusBadRequest, errors.New("target is required"))
		return
	}
	if err := httpclient.ValidateURL(target); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid target: %w", err))
		return
	}
	scanRow, err := s.service.EnqueueScan(r.Context(), user.ID, target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to create scan"))
		return
	}
	writeJSON(w, http.StatusAccepted, scanRow)
}

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := s.service.Store().ListSchedules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to list schedules"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schedules": items})
}

type createScheduleRequest struct {
	Target          string `json:"target"`
	IntervalMinutes int    `json:"interval_minutes"`
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	user, err := s.defaultUser(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to resolve user"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid request body"))
		return
	}
	var req createScheduleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, errors.New("invalid JSON body"))
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeError(w, http.StatusBadRequest, errors.New("target is required"))
		return
	}
	if err := httpclient.ValidateURL(target); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("invalid target: %w", err))
		return
	}
	item, err := s.service.CreateSchedule(r.Context(), user.ID, target, req.IntervalMinutes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errors.New("failed to create schedule"))
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(dashboardHTML)
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, err error) {
	msg := err.Error()
	if status >= 500 {
		msg = http.StatusText(status)
	}
	writeJSON(w, status, map[string]string{"error": msg})
}

type rateLimiter struct {
	mu      sync.Mutex
	visitors map[string]*visitor
	limit    int
	window   time.Duration
}

type visitor struct {
	count    int
	resetAt  time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		visitors: make(map[string]*visitor),
		limit:    limit,
		window:   window,
	}
}

func (rl *rateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, ok := rl.visitors[key]
	if !ok || now.After(v.resetAt) {
		rl.visitors[key] = &visitor{count: 1, resetAt: now.Add(rl.window)}
		return true
	}
	v.count++
	return v.count <= rl.limit
}

func (s *Server) withRateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		if !s.rateLimiter.Allow(r.RemoteAddr) {
			writeError(w, http.StatusTooManyRequests, errors.New("rate limit exceeded"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) defaultUser(ctx context.Context) (*store.User, error) {
	users, err := s.service.Store().ListUsers(ctx)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, errors.New("no users configured")
	}
	return &users[0], nil
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" {
			allowed := false
			for _, o := range s.allowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			} else if len(s.allowedOrigins) == 0 {
				w.Header().Set("Access-Control-Allow-Origin", "")
			} else {
				w.Header().Set("Access-Control-Allow-Origin", s.allowedOrigins[0])
			}
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Credentials", "false")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

