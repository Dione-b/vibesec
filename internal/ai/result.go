package ai

type PriorityItem struct {
	Rank      int     `json:"rank"`
	Title     string  `json:"title"`
	Severity  string  `json:"severity"`
	Score     float64 `json:"score"`
	Rationale string  `json:"rationale"`
}

type Result struct {
	ExecutiveSummary string         `json:"executive_summary"`
	Hypotheses       []string       `json:"hypotheses,omitempty"`
	AttackSurface    []string       `json:"attack_surface,omitempty"`
	Prioritization   []PriorityItem `json:"prioritization,omitempty"`
	Recommendations  []string       `json:"recommendations,omitempty"`
}
