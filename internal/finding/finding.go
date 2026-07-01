package finding

import (
	"fmt"
	"strings"
)

type Finding struct {
	ID             string  `json:"id"`
	Module         string  `json:"module,omitempty"`
	Severity       string  `json:"severity"`
	Confidence     string  `json:"confidence,omitempty"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Evidence       string  `json:"evidence"`
	Recommendation string  `json:"recommendation"`
	CWE            string  `json:"cwe,omitempty"`
	OWASP          string  `json:"owasp,omitempty"`
	ASVS           string  `json:"asvs,omitempty"`
	CAPEC          string  `json:"capec,omitempty"`
	CVSS           float64 `json:"cvss,omitempty"`
}

type Options struct {
	Module         string
	ID             string
	Severity       string
	Confidence     string
	Title          string
	Description    string
	Evidence       string
	Recommendation string
	CWE            string
	OWASP          string
	ASVS           string
	CAPEC          string
	CVSS           float64
}

func New(opts Options) Finding {
	id := opts.ID
	if opts.Module != "" && id != "" && !strings.Contains(id, "/") {
		id = opts.Module + "/" + slug(id)
	}
	return Finding{
		ID:             id,
		Module:         opts.Module,
		Severity:       normalizeSeverity(opts.Severity),
		Confidence:     strings.ToLower(strings.TrimSpace(opts.Confidence)),
		Title:          opts.Title,
		Description:    opts.Description,
		Evidence:       opts.Evidence,
		Recommendation: opts.Recommendation,
		CWE:            opts.CWE,
		OWASP:          opts.OWASP,
		ASVS:           opts.ASVS,
		CAPEC:          opts.CAPEC,
		CVSS:           opts.CVSS,
	}
}

func normalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return strings.ToLower(value)
	case "fail":
		return SeverityHigh
	case "warning", "warn":
		return SeverityMedium
	default:
		return SeverityInfo
	}
}

func slug(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "finding"
	}
	return out
}

func Merge(items ...[]Finding) []Finding {
	var out []Finding
	for _, group := range items {
		out = append(out, group...)
	}
	return Dedup(out)
}

func Dedup(items []Finding) []Finding {
	seen := make(map[string]struct{}, len(items))
	var out []Finding
	for _, item := range items {
		if item.ID == "" {
			item.ID = fmt.Sprintf("finding-%d", len(out)+1)
		}
		if _, ok := seen[item.ID]; ok {
			continue
		}
		seen[item.ID] = struct{}{}
		out = append(out, item)
	}
	return out
}
