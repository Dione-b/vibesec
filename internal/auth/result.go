package auth

type Signal struct {
	Category string `json:"category"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

type Result struct {
	LoginPath    string   `json:"login_path,omitempty"`
	LogoutPath   string   `json:"logout_path,omitempty"`
	RefreshPath  string   `json:"refresh_path,omitempty"`
	Mechanisms   []string `json:"mechanisms,omitempty"`
	Signals      []Signal `json:"signals,omitempty"`
}

const (
	StatusPass    = "PASS"
	StatusFail    = "FAIL"
	StatusWarning = "WARNING"
	StatusInfo    = "INFO"
)
