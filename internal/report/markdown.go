package report

import (
	"fmt"
	"strings"
)

func RenderMarkdown(doc *Document) string {
	if doc == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("# VibeSec Report\n\n")
	b.WriteString("## Summary\n\n")
	b.WriteString(fmt.Sprintf("- **Target:** %s\n", doc.Summary.Target))
	b.WriteString(fmt.Sprintf("- **Generated:** %s\n", doc.Summary.GeneratedAt.Format(timeLayout)))
	b.WriteString(fmt.Sprintf("- **Findings:** %d\n", doc.Summary.FindingCount))
	b.WriteString(fmt.Sprintf("- **Risk:** %s (score %d)\n\n", doc.Risk.Level, doc.Risk.Score))

	writeSection(&b, "Stack", doc.Stack)
	writeSection(&b, "Infrastructure", doc.Infrastructure)

	if len(doc.HeaderChecks) > 0 {
		b.WriteString("## Header Checks\n\n")
		b.WriteString("| Check | Status | Detail |\n")
		b.WriteString("|-------|--------|--------|\n")
		for _, check := range doc.HeaderChecks {
			b.WriteString(fmt.Sprintf("| %s | %s | %s |\n", escapeMD(check.Name), check.Status, escapeMD(check.Detail)))
		}
		b.WriteString("\n")
	}

	if doc.Bundle != nil {
		b.WriteString("## Bundle\n\n")
		b.WriteString(fmt.Sprintf("- Routes: %d\n", doc.Bundle.RouteCount()))
		b.WriteString(fmt.Sprintf("- Endpoints: %d\n", doc.Bundle.EndpointCount()))
		b.WriteString(fmt.Sprintf("- Admin pages: %d\n", doc.Bundle.AdminCount()))
		if len(doc.Bundle.Libraries) > 0 {
			b.WriteString(fmt.Sprintf("- Libraries: %s\n", strings.Join(doc.Bundle.Libraries, ", ")))
		}
		if len(doc.Bundle.Secrets) > 0 {
			b.WriteString(fmt.Sprintf("- Possible secrets: %s\n", strings.Join(doc.Bundle.Secrets, ", ")))
		}
		b.WriteString("\n")
	}

	if len(doc.Endpoints) > 0 {
		b.WriteString("## Endpoints\n\n")
		b.WriteString("| Method | Path | Status | Allowed |\n")
		b.WriteString("|--------|------|--------|---------|\n")
		for _, probe := range doc.Endpoints {
			b.WriteString(fmt.Sprintf("| %s | %s | %d | %s |\n",
				probe.Method, escapeMD(probe.Path), probe.Status, escapeMD(probe.AllowedMethods)))
		}
		b.WriteString("\n")
	}

	if len(doc.ReconAssets) > 0 {
		b.WriteString("## Recon Assets\n\n")
		for _, asset := range doc.ReconAssets {
			b.WriteString(fmt.Sprintf("- `%s` — %d — %s\n", asset.Path, asset.Status, asset.Summary))
		}
		b.WriteString("\n")
	}

	if doc.Auth != nil && len(doc.Auth.Signals) > 0 {
		b.WriteString("## Auth\n\n")
		for _, signal := range doc.Auth.Signals {
			b.WriteString(fmt.Sprintf("- **%s** %s — %s\n", signal.Category, signal.Status, signal.Detail))
		}
		b.WriteString("\n")
	}

	if doc.Plugins != nil && len(doc.Plugins.Results) > 0 {
		b.WriteString("## Plugins\n\n")
		for _, p := range doc.Plugins.Results {
			b.WriteString(fmt.Sprintf("- **%s** %s — %s\n", p.Name, p.Status, p.Summary))
		}
		b.WriteString("\n")
	}

	if doc.Nuclei != nil {
		b.WriteString("## Nuclei\n\n")
		b.WriteString(fmt.Sprintf("- status: %s — %s\n", doc.Nuclei.Status, doc.Nuclei.Summary))
		for _, item := range doc.Nuclei.Findings {
			b.WriteString(fmt.Sprintf("- `%s` (%s) %s\n", item.TemplateID, item.Severity, item.Name))
		}
		b.WriteString("\n")
	}

	if doc.Burp != nil && len(doc.Burp.Issues) > 0 {
		b.WriteString("## Burp\n\n")
		b.WriteString(fmt.Sprintf("- status: %s — %s\n", doc.Burp.Status, doc.Burp.Summary))
		for _, issue := range doc.Burp.Issues {
			b.WriteString(fmt.Sprintf("- **%s** (%s) %s\n", issue.Name, issue.Severity, issue.Location))
		}
		b.WriteString("\n")
	}

	if doc.AI != nil {
		b.WriteString("## AI Analysis\n\n")
		if doc.AI.ExecutiveSummary != "" {
			b.WriteString("### Executive Summary\n\n")
			b.WriteString(doc.AI.ExecutiveSummary + "\n\n")
		}
		if len(doc.AI.Hypotheses) > 0 {
			b.WriteString("### Hypotheses\n\n")
			for _, item := range doc.AI.Hypotheses {
				b.WriteString(fmt.Sprintf("- %s\n", item))
			}
			b.WriteString("\n")
		}
		if len(doc.AI.AttackSurface) > 0 {
			b.WriteString("### Attack Surface\n\n")
			for _, item := range doc.AI.AttackSurface {
				b.WriteString(fmt.Sprintf("- %s\n", item))
			}
			b.WriteString("\n")
		}
		if len(doc.AI.Prioritization) > 0 {
			b.WriteString("### Prioritization\n\n")
			for _, item := range doc.AI.Prioritization {
				b.WriteString(fmt.Sprintf("%d. **%s** (%s, score %.1f) — %s\n",
					item.Rank, item.Title, item.Severity, item.Score, item.Rationale))
			}
			b.WriteString("\n")
		}
		if len(doc.AI.Recommendations) > 0 {
			b.WriteString("### AI Recommendations\n\n")
			for _, item := range doc.AI.Recommendations {
				b.WriteString(fmt.Sprintf("- %s\n", item))
			}
			b.WriteString("\n")
		}
	}

	if len(doc.Findings) > 0 {
		b.WriteString("## Findings\n\n")
		for _, item := range doc.Findings {
			b.WriteString(fmt.Sprintf("### %s (%s)\n\n", item.Title, item.Severity))
			if item.Description != "" {
				b.WriteString(item.Description + "\n\n")
			}
			if item.Evidence != "" {
				b.WriteString(fmt.Sprintf("**Evidence:** %s\n\n", item.Evidence))
			}
			if item.Recommendation != "" {
				b.WriteString(fmt.Sprintf("**Recommendation:** %s\n\n", item.Recommendation))
			}
			if item.Confidence != "" {
				b.WriteString(fmt.Sprintf("**Confidence:** %s\n\n", item.Confidence))
			}
			meta := []string{}
			if item.OWASP != "" {
				meta = append(meta, "OWASP "+item.OWASP)
			}
			if item.ASVS != "" {
				meta = append(meta, "ASVS "+item.ASVS)
			}
			if item.CWE != "" {
				meta = append(meta, item.CWE)
			}
			if item.CAPEC != "" {
				meta = append(meta, item.CAPEC)
			}
			if item.CVSS > 0 {
				meta = append(meta, fmt.Sprintf("CVSS %.1f", item.CVSS))
			}
			if len(meta) > 0 {
				b.WriteString("**Taxonomy:** " + strings.Join(meta, " | ") + "\n\n")
			}
		}
	}

	if len(doc.Recommendations) > 0 {
		b.WriteString("## Recommendations\n\n")
		for _, rec := range doc.Recommendations {
			b.WriteString(fmt.Sprintf("- %s\n", rec))
		}
		b.WriteString("\n")
	}

	return b.String()
}

const timeLayout = "2006-01-02 15:04:05 UTC"

func writeSection(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	b.WriteString("## " + title + "\n\n")
	for _, item := range items {
		b.WriteString(fmt.Sprintf("- %s\n", item))
	}
	b.WriteString("\n")
}

func escapeMD(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}
