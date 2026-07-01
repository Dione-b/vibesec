package enterprise

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/dionebastos/vibesec/internal/config"
	"github.com/dionebastos/vibesec/internal/scan"
	"github.com/dionebastos/vibesec/internal/store"
)

type Service struct {
	cfg     *config.Config
	store   *store.Store
	mu      sync.Mutex
	active  map[string]struct{}
}

func NewService(cfg *config.Config, st *store.Store) *Service {
	if cfg == nil {
		cfg = config.Default()
	}
	return &Service{
		cfg:    cfg,
		store:  st,
		active: make(map[string]struct{}),
	}
}

func (s *Service) Store() *store.Store {
	return s.store
}

func (s *Service) EnqueueScan(ctx context.Context, userID int64, target string) (*store.Scan, error) {
	id := store.NewID("scan")
	return s.store.CreateScan(ctx, id, store.CreateScanInput{
		UserID: userID,
		Target: target,
		Status: store.ScanStatusPending,
	})
}

func (s *Service) SaveCompletedScan(ctx context.Context, userID int64, result *scan.Result, documentJSON string) (*store.Scan, error) {
	if result == nil {
		return nil, fmt.Errorf("scan result is nil")
	}
	id := store.NewID("scan")
	scanRow, err := s.store.CreateScan(ctx, id, store.CreateScanInput{
		UserID: userID,
		Target: result.Target,
		Status: store.ScanStatusCompleted,
	})
	if err != nil {
		return nil, err
	}
	var reportMarkdown, reportJSON, reportHTML string
	if result.Report != nil {
		reportMarkdown = result.Report.Markdown
		reportJSON = result.Report.JSON
		reportHTML = result.Report.HTML
	}
	if err := s.store.UpdateScan(ctx, id, store.UpdateScanInput{
		Status:         store.ScanStatusCompleted,
		RiskLevel:      result.RiskLevel,
		FindingCount:   result.FindingCount,
		HighCount:      result.HighCount,
		CriticalCount:  result.CriticalCount,
		ReportMarkdown: reportMarkdown,
		ReportJSON:     reportJSON,
		ReportHTML:     reportHTML,
		DocumentJSON:   documentJSON,
		Finished:       true,
	}); err != nil {
		return nil, err
	}
	scanRow.Status = store.ScanStatusCompleted
	scanRow.RiskLevel = result.RiskLevel
	scanRow.FindingCount = result.FindingCount
	scanRow.HighCount = result.HighCount
	scanRow.CriticalCount = result.CriticalCount
	return scanRow, nil
}

func (s *Service) RunScanByID(ctx context.Context, scanID string) error {
	s.mu.Lock()
	if _, ok := s.active[scanID]; ok {
		s.mu.Unlock()
		return nil
	}
	s.active[scanID] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.active, scanID)
		s.mu.Unlock()
	}()

	row, err := s.store.GetScan(ctx, scanID)
	if err != nil {
		return err
	}
	if row.Status != store.ScanStatusPending {
		return nil
	}

	if err := s.store.UpdateScan(ctx, scanID, store.UpdateScanInput{Status: store.ScanStatusRunning}); err != nil {
		return err
	}

	modules := scan.ModulesFromConfig(s.cfg)
	result, err := scan.Execute(row.Target, s.cfg, modules, scan.Options{Silent: true})
	if err != nil {
		_ = s.store.UpdateScan(ctx, scanID, store.UpdateScanInput{
			Status:       store.ScanStatusFailed,
			ErrorMessage: err.Error(),
			Finished:     true,
		})
		return err
	}

	docJSON, _ := json.Marshal(result.Document)
	var reportMarkdown, reportJSON, reportHTML string
	if result.Report != nil {
		reportMarkdown = result.Report.Markdown
		reportJSON = result.Report.JSON
		reportHTML = result.Report.HTML
	}
	return s.store.UpdateScan(ctx, scanID, store.UpdateScanInput{
		Status:         store.ScanStatusCompleted,
		RiskLevel:      result.RiskLevel,
		FindingCount:   result.FindingCount,
		HighCount:      result.HighCount,
		CriticalCount:  result.CriticalCount,
		ReportMarkdown: reportMarkdown,
		ReportJSON:     reportJSON,
		ReportHTML:     reportHTML,
		DocumentJSON:   string(docJSON),
		Finished:       true,
	})
}

func (s *Service) ProcessPending(ctx context.Context) {
	rows, err := s.store.ListPendingScans(ctx, 5)
	if err != nil {
		return
	}
	for _, row := range rows {
		_ = s.RunScanByID(ctx, row.ID)
	}
}

func (s *Service) CreateSchedule(ctx context.Context, userID int64, target string, intervalMinutes int) (*store.Schedule, error) {
	return s.store.CreateSchedule(ctx, store.NewID("sched"), store.CreateScheduleInput{
		UserID:          userID,
		Target:          target,
		IntervalMinutes: intervalMinutes,
	})
}

func (s *Service) ProcessSchedules(ctx context.Context) error {
	items, err := s.store.ListDueSchedules(ctx, s.cfg.Now())
	if err != nil {
		return err
	}
	for _, item := range items {
		if _, err := s.EnqueueScan(ctx, item.UserID, item.Target); err != nil {
			return err
		}
		if err := s.store.TouchSchedule(ctx, item.ID, s.cfg.Now()); err != nil {
			return err
		}
	}
	return nil
}
