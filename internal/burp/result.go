package burp

type Issue struct {
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence,omitempty"`
	Host        string `json:"host,omitempty"`
	Path        string `json:"path,omitempty"`
	Location    string `json:"location,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

type Result struct {
	Source  string  `json:"source"`
	Status  string  `json:"status"`
	Summary string  `json:"summary,omitempty"`
	Error   string  `json:"error,omitempty"`
	Issues  []Issue `json:"issues,omitempty"`
}

const (
	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusError   = "error"
)
