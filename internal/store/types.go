package store

import "time"

const (
	ScanStatusPending   = "pending"
	ScanStatusRunning   = "running"
	ScanStatusCompleted = "completed"
	ScanStatusFailed    = "failed"
)

type User struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	APIKey    string    `json:"-"`
	CreatedAt time.Time `json:"created_at"`
}

type UserResponse struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

func (u *User) ToResponse() UserResponse {
	return UserResponse{ID: u.ID, Name: u.Name, CreatedAt: u.CreatedAt}
}

type Scan struct {
	ID            string    `json:"id"`
	UserID        int64     `json:"user_id"`
	Target        string    `json:"target"`
	Status        string    `json:"status"`
	RiskLevel     string    `json:"risk_level,omitempty"`
	FindingCount  int       `json:"finding_count"`
	HighCount     int       `json:"high_count"`
	CriticalCount int       `json:"critical_count"`
	ReportMarkdown string   `json:"report_markdown,omitempty"`
	ReportJSON    string    `json:"report_json,omitempty"`
	ReportHTML    string    `json:"report_html,omitempty"`
	DocumentJSON  string    `json:"document_json,omitempty"`
	ErrorMessage  string    `json:"error_message,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	FinishedAt    time.Time `json:"finished_at,omitempty"`
}

type Schedule struct {
	ID              string    `json:"id"`
	UserID          int64     `json:"user_id"`
	Target          string    `json:"target"`
	IntervalMinutes int       `json:"interval_minutes"`
	Enabled         bool      `json:"enabled"`
	LastRunAt       time.Time `json:"last_run_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type CreateScanInput struct {
	UserID int64
	Target string
	Status string
}

type UpdateScanInput struct {
	Status        string
	RiskLevel     string
	FindingCount  int
	HighCount     int
	CriticalCount int
	ReportMarkdown string
	ReportJSON    string
	ReportHTML    string
	DocumentJSON  string
	ErrorMessage  string
	Finished      bool
}

type CreateScheduleInput struct {
	UserID          int64
	Target          string
	IntervalMinutes int
}
