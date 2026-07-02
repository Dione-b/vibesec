package report

import (
	"time"

	"github.com/dionebastos/vibesec/internal/auth"
	"github.com/dionebastos/vibesec/internal/ai"
	"github.com/dionebastos/vibesec/internal/bundle"
	"github.com/dionebastos/vibesec/internal/burp"
	"github.com/dionebastos/vibesec/internal/endpoint"
	"github.com/dionebastos/vibesec/internal/finding"
	"github.com/dionebastos/vibesec/internal/fingerprint"
	"github.com/dionebastos/vibesec/internal/headers"
	"github.com/dionebastos/vibesec/internal/nuclei"
	"github.com/dionebastos/vibesec/internal/plugin"
)

type ReconAsset struct {
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Summary string `json:"summary,omitempty"`
}

type Summary struct {
	Target      string    `json:"target"`
	GeneratedAt time.Time `json:"generated_at"`
	ModulesRun  int       `json:"modules_run"`
	FindingCount int      `json:"finding_count"`
}

type Risk struct {
	Level  string         `json:"level"`
	Score  int            `json:"score"`
	Counts map[string]int `json:"counts"`
}

type Document struct {
	Summary          Summary            `json:"summary"`
	Stack            []string           `json:"stack,omitempty"`
	Infrastructure   []string           `json:"infrastructure,omitempty"`
	HeaderChecks     []headers.Check    `json:"header_checks,omitempty"`
	Bundle           *bundle.Result     `json:"bundle,omitempty"`
	Endpoints        []endpoint.Probe   `json:"endpoints,omitempty"`
	Auth             *auth.Result       `json:"auth,omitempty"`
	Plugins          *plugin.Collection `json:"plugins,omitempty"`
	Nuclei           *nuclei.Result     `json:"nuclei,omitempty"`
	Burp             *burp.Result       `json:"burp,omitempty"`
	AI               *ai.Result         `json:"ai,omitempty"`
	ReconAssets      []ReconAsset       `json:"recon_assets,omitempty"`
	Findings         []finding.Finding  `json:"findings,omitempty"`
	Risk             Risk               `json:"risk"`
	Recommendations  []string           `json:"recommendations,omitempty"`
	Fingerprint      *fingerprint.Result `json:"fingerprint,omitempty"`
}

type LatestPointer struct {
	Target            string    `json:"target"`
	Generated         time.Time `json:"generated_at"`
	Markdown          string    `json:"markdown,omitempty"`
	JSON              string    `json:"json,omitempty"`
	HTML              string    `json:"html,omitempty"`
	ExecutiveMarkdown string    `json:"executive_markdown,omitempty"`
	ExecutiveHTML     string    `json:"executive_html,omitempty"`
}

type Output struct {
	Markdown          string
	JSON              string
	HTML              string
	ExecutiveMarkdown string
	ExecutiveHTML     string
}
