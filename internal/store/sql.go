package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

func (s *Store) Migrate(ctx context.Context) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL UNIQUE,
			api_key TEXT NOT NULL UNIQUE,
			created_at TEXT NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS scans (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			target TEXT NOT NULL,
			status TEXT NOT NULL,
			risk_level TEXT,
			finding_count INTEGER NOT NULL DEFAULT 0,
			high_count INTEGER NOT NULL DEFAULT 0,
			critical_count INTEGER NOT NULL DEFAULT 0,
			report_markdown TEXT,
			report_json TEXT,
			report_html TEXT,
			document_json TEXT,
			error_message TEXT,
			created_at TEXT NOT NULL,
			finished_at TEXT,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)`,
		`CREATE TABLE IF NOT EXISTS schedules (
			id TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			target TEXT NOT NULL,
			interval_minutes INTEGER NOT NULL DEFAULT 1440,
			enabled INTEGER NOT NULL DEFAULT 1,
			last_run_at TEXT,
			created_at TEXT NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id)
		)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return s.EnsureDefaultUser(ctx)
}

func (s *Store) EnsureDefaultUser(ctx context.Context) error {
	var count int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	_, err := s.CreateUser(ctx, "admin", NewAPIKey())
	return err
}

func (s *Store) CreateUser(ctx context.Context, name, apiKey string) (*User, error) {
	now := time.Now().UTC()
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users(name, api_key, created_at) VALUES(?, ?, ?)`,
		name, apiKey, now.Format(time.RFC3339),
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &User{ID: id, Name: name, APIKey: apiKey, CreatedAt: now}, nil
}

func (s *Store) GetUserByAPIKey(ctx context.Context, apiKey string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT id, name, api_key, created_at FROM users WHERE api_key = ?`, apiKey,
	)
	return scanUser(row)
}

func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, api_key, created_at FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []User
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, *user)
	}
	return users, rows.Err()
}

func (s *Store) CreateScan(ctx context.Context, id string, in CreateScanInput) (*Scan, error) {
	now := time.Now().UTC()
	status := in.Status
	if status == "" {
		status = ScanStatusPending
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scans(id, user_id, target, status, created_at) VALUES(?, ?, ?, ?, ?)`,
		id, in.UserID, in.Target, status, now.Format(time.RFC3339),
	)
	if err != nil {
		return nil, err
	}
	return &Scan{
		ID:        id,
		UserID:    in.UserID,
		Target:    in.Target,
		Status:    status,
		CreatedAt: now,
	}, nil
}

func (s *Store) UpdateScan(ctx context.Context, id string, in UpdateScanInput) error {
	finishedAt := ""
	if in.Finished {
		finishedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := s.db.ExecContext(ctx, `
		UPDATE scans SET
			status = ?, risk_level = ?, finding_count = ?, high_count = ?, critical_count = ?,
			report_markdown = ?, report_json = ?, report_html = ?, document_json = ?,
			error_message = ?, finished_at = COALESCE(NULLIF(?, ''), finished_at)
		WHERE id = ?`,
		in.Status, in.RiskLevel, in.FindingCount, in.HighCount, in.CriticalCount,
		in.ReportMarkdown, in.ReportJSON, in.ReportHTML, in.DocumentJSON,
		in.ErrorMessage, finishedAt, id,
	)
	return err
}

func (s *Store) GetScan(ctx context.Context, id string) (*Scan, error) {
	row := s.db.QueryRowContext(ctx, scanSelectSQL+` WHERE id = ?`, id)
	return scanScan(row)
}

func (s *Store) ListScans(ctx context.Context, limit int) ([]Scan, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.QueryContext(ctx, scanSelectSQL+` ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectScans(rows)
}

func (s *Store) ListPendingScans(ctx context.Context, limit int) ([]Scan, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.db.QueryContext(ctx, scanSelectSQL+` WHERE status = ? ORDER BY created_at ASC LIMIT ?`,
		ScanStatusPending, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return collectScans(rows)
}

func (s *Store) CreateSchedule(ctx context.Context, id string, in CreateScheduleInput) (*Schedule, error) {
	now := time.Now().UTC()
	interval := in.IntervalMinutes
	if interval <= 0 {
		interval = 1440
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO schedules(id, user_id, target, interval_minutes, enabled, created_at) VALUES(?, ?, ?, ?, 1, ?)`,
		id, in.UserID, in.Target, interval, now.Format(time.RFC3339),
	)
	if err != nil {
		return nil, err
	}
	return &Schedule{
		ID:              id,
		UserID:          in.UserID,
		Target:          in.Target,
		IntervalMinutes: interval,
		Enabled:         true,
		CreatedAt:       now,
	}, nil
}

func (s *Store) ListSchedules(ctx context.Context) ([]Schedule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, target, interval_minutes, enabled, last_run_at, created_at FROM schedules ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Schedule
	for rows.Next() {
		item, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

func (s *Store) ListDueSchedules(ctx context.Context, now time.Time) ([]Schedule, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, target, interval_minutes, enabled, last_run_at, created_at FROM schedules WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var due []Schedule
	for rows.Next() {
		item, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		if scheduleDue(*item, now) {
			due = append(due, *item)
		}
	}
	return due, rows.Err()
}

func (s *Store) TouchSchedule(ctx context.Context, id string, at time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE schedules SET last_run_at = ? WHERE id = ?`, at.Format(time.RFC3339), id)
	return err
}

const scanSelectSQL = `
	SELECT id, user_id, target, status, risk_level, finding_count, high_count, critical_count,
	       report_markdown, report_json, report_html, document_json, error_message, created_at, finished_at
	FROM scans`

func collectScans(rows *sql.Rows) ([]Scan, error) {
	var items []Scan
	for rows.Next() {
		item, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, rows.Err()
}

func scanUser(row interface{ Scan(dest ...any) error }) (*User, error) {
	var user User
	var created string
	if err := row.Scan(&user.ID, &user.Name, &user.APIKey, &created); err != nil {
		return nil, err
	}
	user.CreatedAt = parseTime(created)
	return &user, nil
}

func scanScan(row interface{ Scan(dest ...any) error }) (*Scan, error) {
	var item Scan
	var riskLevel, reportMarkdown, reportJSON, reportHTML, documentJSON, errorMessage sql.NullString
	var created, finished sql.NullString
	if err := row.Scan(
		&item.ID, &item.UserID, &item.Target, &item.Status, &riskLevel,
		&item.FindingCount, &item.HighCount, &item.CriticalCount,
		&reportMarkdown, &reportJSON, &reportHTML, &documentJSON,
		&errorMessage, &created, &finished,
	); err != nil {
		return nil, err
	}
	if riskLevel.Valid {
		item.RiskLevel = riskLevel.String
	}
	if reportMarkdown.Valid {
		item.ReportMarkdown = reportMarkdown.String
	}
	if reportJSON.Valid {
		item.ReportJSON = reportJSON.String
	}
	if reportHTML.Valid {
		item.ReportHTML = reportHTML.String
	}
	if documentJSON.Valid {
		item.DocumentJSON = documentJSON.String
	}
	if errorMessage.Valid {
		item.ErrorMessage = errorMessage.String
	}
	if created.Valid {
		item.CreatedAt = parseTime(created.String)
	}
	if finished.Valid {
		item.FinishedAt = parseTime(finished.String)
	}
	return &item, nil
}

func scanSchedule(row interface{ Scan(dest ...any) error }) (*Schedule, error) {
	var item Schedule
	var enabled int
	var lastRun, created sql.NullString
	if err := row.Scan(&item.ID, &item.UserID, &item.Target, &item.IntervalMinutes, &enabled, &lastRun, &created); err != nil {
		return nil, err
	}
	item.Enabled = enabled == 1
	if created.Valid {
		item.CreatedAt = parseTime(created.String)
	}
	if lastRun.Valid {
		item.LastRunAt = parseTime(lastRun.String)
	}
	return &item, nil
}

func parseTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}
	}
	return t
}

func scheduleDue(item Schedule, now time.Time) bool {
	if !item.Enabled {
		return false
	}
	if item.LastRunAt.IsZero() {
		return true
	}
	return now.Sub(item.LastRunAt) >= time.Duration(item.IntervalMinutes)*time.Minute
}
