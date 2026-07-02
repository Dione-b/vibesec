package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dionebastos/vibesec/internal/report"
	"github.com/dionebastos/vibesec/internal/store"
)

func enrichScanDocument(item *store.Scan) {
	if item == nil || item.DocumentJSON == "" {
		return
	}
	if enriched, err := report.EnrichDocumentJSON(item.DocumentJSON); err == nil {
		item.DocumentJSON = enriched
	}
}

func scanIsTerminal(status string) bool {
	return status == store.ScanStatusCompleted || status == store.ScanStatusFailed
}

func writeSSE(w http.ResponseWriter, flusher http.Flusher, event string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func writeSSEComment(w http.ResponseWriter, flusher http.Flusher, comment string) error {
	if _, err := fmt.Fprintf(w, ": %s\n\n", comment); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func (s *Server) handleScanEvents(w http.ResponseWriter, r *http.Request) {
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

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	lastStatus := ""
	emit := func(scan *store.Scan) error {
		enrichScanDocument(scan)
		if err := writeSSE(w, flusher, "scan", scan); err != nil {
			return err
		}
		lastStatus = scan.Status
		return nil
	}

	if err := emit(item); err != nil {
		return
	}
	if scanIsTerminal(item.Status) {
		return
	}

	pollTicker := time.NewTicker(2 * time.Second)
	defer pollTicker.Stop()
	keepaliveTicker := time.NewTicker(15 * time.Second)
	defer keepaliveTicker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepaliveTicker.C:
			if err := writeSSEComment(w, flusher, "ping"); err != nil {
				return
			}
		case <-pollTicker.C:
			current, err := s.service.Store().GetScan(r.Context(), id)
			if err != nil {
				return
			}
			if current.Status != lastStatus {
				if err := emit(current); err != nil {
					return
				}
				if scanIsTerminal(current.Status) {
					return
				}
			}
		}
	}
}
