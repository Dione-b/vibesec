package endpoint

type Probe struct {
	Path           string `json:"path"`
	Method         string `json:"method"`
	Status         int    `json:"status"`
	AllowedMethods string `json:"allowed_methods,omitempty"`
}

type Result struct {
	Matrix []Probe `json:"matrix"`
}

func (r *Result) Count() int {
	if r == nil {
		return 0
	}
	return len(r.Matrix)
}
