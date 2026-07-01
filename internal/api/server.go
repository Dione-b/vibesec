package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dionebastos/vibesec/internal/enterprise"
	"github.com/dionebastos/vibesec/internal/store"
)

type Server struct {
	service *enterprise.Service
	mux     *http.ServeMux
}

func NewServer(service *enterprise.Service) *Server {
	s := &Server{service: service, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.withCORS(s.withAuth(s.mux))
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.handleDashboard)
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)
	s.mux.HandleFunc("GET /api/v1/scans", s.handleListScans)
	s.mux.HandleFunc("POST /api/v1/scans", s.handleCreateScan)
	s.mux.HandleFunc("GET /api/v1/scans/{id}", s.handleGetScan)
	s.mux.HandleFunc("GET /api/v1/schedules", s.handleListSchedules)
	s.mux.HandleFunc("POST /api/v1/schedules", s.handleCreateSchedule)
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
	items, err := s.service.Store().ListScans(r.Context(), limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"scans": items})
}

func (s *Server) handleGetScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	item, err := s.service.Store().GetScan(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type createScanRequest struct {
	Target string `json:"target"`
}

func (s *Server) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	user, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var req createScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeError(w, http.StatusBadRequest, errors.New("target is required"))
		return
	}
	scanRow, err := s.service.EnqueueScan(r.Context(), user.ID, target)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusAccepted, scanRow)
}

func (s *Server) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	items, err := s.service.Store().ListSchedules(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"schedules": items})
}

type createScheduleRequest struct {
	Target          string `json:"target"`
	IntervalMinutes int    `json:"interval_minutes"`
}

func (s *Server) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	user, ok := userFromContext(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("unauthorized"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	var req createScheduleRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	target := strings.TrimSpace(req.Target)
	if target == "" {
		writeError(w, http.StatusBadRequest, errors.New("target is required"))
		return
	}
	item, err := s.service.CreateSchedule(r.Context(), user.ID, target, req.IntervalMinutes)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
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
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func (s *Server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || r.URL.Path == "/api/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if apiKey == "" {
			auth := r.Header.Get("Authorization")
			if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
				apiKey = strings.TrimSpace(auth[7:])
			}
		}
		if apiKey == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("missing API key"))
			return
		}
		user, err := s.service.Store().GetUserByAPIKey(r.Context(), apiKey)
		if err != nil {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("invalid API key"))
			return
		}
		ctx := contextWithUser(r.Context(), user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type contextKey string

const userContextKey contextKey = "vibesec-user"

func contextWithUser(ctx context.Context, user *store.User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func userFromContext(ctx context.Context) (*store.User, bool) {
	user, ok := ctx.Value(userContextKey).(*store.User)
	return user, ok && user != nil
}
