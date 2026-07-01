package headers

const (
	StatusPass    = "PASS"
	StatusFail    = "FAIL"
	StatusWarning = "WARNING"
)

type Check struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type Result struct {
	Checks []Check `json:"checks"`
}

func (r *Result) Count(status string) int {
	if r == nil {
		return 0
	}
	n := 0
	for _, check := range r.Checks {
		if check.Status == status {
			n++
		}
	}
	return n
}
