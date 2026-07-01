package authorization

type Signal struct {
	Category string `json:"category"`
	Status   string `json:"status"`
	Detail   string `json:"detail,omitempty"`
}

type Result struct {
	AdminPaths     []string `json:"admin_paths,omitempty"`
	IDORCandidates []string `json:"idor_candidates,omitempty"`
	Signals        []Signal `json:"signals,omitempty"`
}

const (
	StatusPass    = "PASS"
	StatusFail    = "FAIL"
	StatusWarning = "WARNING"
	StatusInfo    = "INFO"
)
