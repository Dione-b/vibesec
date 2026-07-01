package plugin

import "encoding/json"

type Port struct {
	Number  int    `json:"number"`
	Service string `json:"service,omitempty"`
	State   string `json:"state,omitempty"`
}

type Result struct {
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Summary    string          `json:"summary,omitempty"`
	Error      string          `json:"error,omitempty"`
	Hosts      []string        `json:"hosts,omitempty"`
	URLs       []string        `json:"urls,omitempty"`
	Subdomains []string        `json:"subdomains,omitempty"`
	Ports      []Port          `json:"ports,omitempty"`
	Technologies []string      `json:"technologies,omitempty"`
	Raw        json.RawMessage `json:"raw,omitempty"`
}

type Collection struct {
	Results []Result `json:"results"`
}

const (
	StatusOK      = "ok"
	StatusSkipped = "skipped"
	StatusError   = "error"
)
