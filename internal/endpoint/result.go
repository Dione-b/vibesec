package endpoint

type Probe struct {
	Path           string `json:"path"`
	Method         string `json:"method"`
	Status         int    `json:"status"`
	AllowedMethods string `json:"allowed_methods,omitempty"`
	ContentLength  int    `json:"content_length,omitempty"`
	ContentHash    string `json:"content_hash,omitempty"`
}

type Result struct {
	Matrix       []Probe `json:"matrix"`
	SPADetected  bool    `json:"spa_detected,omitempty"`
}

func (r *Result) Count() int {
	if r == nil {
		return 0
	}
	return len(r.Matrix)
}
