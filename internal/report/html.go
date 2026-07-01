package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/dionebastos/vibesec/internal/finding"
)

func RenderHTML(doc *Document) string {
	if doc == nil {
		return ""
	}
	data := buildHTMLData(doc)
	var buf bytes.Buffer
	if err := htmlTemplate.Execute(&buf, data); err != nil {
		return fmt.Sprintf("<!DOCTYPE html><html><body><pre>render error: %s</pre></body></html>", template.HTMLEscapeString(err.Error()))
	}
	return buf.String()
}

type htmlData struct {
	Document         *Document
	SeverityBars     []severityBar
	ModuleTimeline   []timelineItem
	RiskClass        string
	HighSeverityPlus int
}

type severityBar struct {
	Label string
	Count int
	Width int
	Class string
}

type timelineItem struct {
	Step  int
	Label string
	Time  string
}

func buildHTMLData(doc *Document) htmlData {
	data := htmlData{
		Document:  doc,
		RiskClass: riskCSSClass(doc.Risk.Level),
	}
	data.HighSeverityPlus = doc.Risk.Counts["high"] + doc.Risk.Counts["critical"]
	data.SeverityBars = severityBars(doc)
	data.ModuleTimeline = moduleTimeline(doc)
	return data
}

func severityBars(doc *Document) []severityBar {
	order := []struct {
		key   string
		label string
		class string
	}{
		{"critical", "Critical", "sev-critical"},
		{"high", "High", "sev-high"},
		{"medium", "Medium", "sev-medium"},
		{"low", "Low", "sev-low"},
		{"info", "Info", "sev-info"},
	}
	max := 1
	for _, item := range order {
		if c := doc.Risk.Counts[item.key]; c > max {
			max = c
		}
	}
	var bars []severityBar
	for _, item := range order {
		count := doc.Risk.Counts[item.key]
		width := 0
		if count > 0 {
			width = (count * 100) / max
			if width < 8 {
				width = 8
			}
		}
		bars = append(bars, severityBar{
			Label: item.label,
			Count: count,
			Width: width,
			Class: item.class,
		})
	}
	return bars
}

func moduleTimeline(doc *Document) []timelineItem {
	steps := []string{
		"Fingerprint", "Headers", "CSP", "Bundle", "Endpoints",
		"Auth", "Authorization", "Plugins", "Nuclei", "Burp",
		"Correlation", "AI Analyzer", "Report",
	}
	limit := doc.Summary.ModulesRun
	if limit > len(steps) {
		limit = len(steps)
	}
	items := make([]timelineItem, 0, limit)
	for i := 0; i < limit; i++ {
		items = append(items, timelineItem{
			Step:  i + 1,
			Label: steps[i],
			Time:  doc.Summary.GeneratedAt.Format("15:04:05"),
		})
	}
	return items
}

func riskCSSClass(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "risk-critical"
	case "high":
		return "risk-high"
	case "medium":
		return "risk-medium"
	default:
		return "risk-low"
	}
}

func findingSeverityClass(severity string) string {
	switch strings.ToLower(severity) {
	case finding.SeverityCritical:
		return "sev-critical"
	case finding.SeverityHigh:
		return "sev-high"
	case finding.SeverityMedium:
		return "sev-medium"
	case finding.SeverityLow:
		return "sev-low"
	default:
		return "sev-info"
	}
}

func headerStatusClass(status string) string {
	switch status {
	case "FAIL":
		return "status-fail"
	case "WARNING":
		return "status-warn"
	default:
		return "status-pass"
	}
}

var htmlTemplate = template.Must(template.New("report").Funcs(template.FuncMap{
	"severityClass":        findingSeverityClass,
	"headerStatusClass":    headerStatusClass,
	"joinTags":             joinTags,
	"hasTaxonomy":          hasTaxonomy,
	"formatCVSS":           formatCVSS,
}).Parse(htmlPageTemplate))

func joinTags(items []string) string {
	return strings.Join(items, ", ")
}

func hasTaxonomy(item finding.Finding) bool {
	return item.OWASP != "" || item.CWE != "" || item.ASVS != "" || item.CAPEC != "" || item.CVSS > 0
}

func formatCVSS(value float64) string {
	if value <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f", value)
}

const htmlPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VibeSec Report — {{.Document.Summary.Target}}</title>
  <style>
    :root {
      --bg: #0b1020;
      --panel: #121a2e;
      --panel-2: #1a2440;
      --border: #2a3555;
      --text: #e8edf8;
      --muted: #9aa8c7;
      --accent: #6ee7b7;
      --accent-2: #38bdf8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: radial-gradient(circle at top, #152042 0%, var(--bg) 45%);
      color: var(--text);
      line-height: 1.5;
    }
    .wrap { max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem 4rem; }
    header.hero {
      display: flex; flex-wrap: wrap; gap: 1rem; justify-content: space-between; align-items: flex-end;
      margin-bottom: 1.5rem;
    }
    .brand { font-size: .85rem; letter-spacing: .12em; text-transform: uppercase; color: var(--accent); }
    h1 { margin: .25rem 0 0; font-size: 1.75rem; }
    .meta { color: var(--muted); font-size: .95rem; }
    .grid { display: grid; gap: 1rem; }
    .grid-4 { grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); }
    .grid-2 { grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
    .card {
      background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.1rem 1.2rem;
      box-shadow: 0 10px 30px rgba(0,0,0,.25);
    }
    .card h2, .card h3 { margin: 0 0 .75rem; font-size: 1rem; }
    .stat-value { font-size: 1.8rem; font-weight: 700; }
    .stat-label { color: var(--muted); font-size: .85rem; }
    .risk-pill {
      display: inline-block; padding: .35rem .75rem; border-radius: 999px;
      font-weight: 700; text-transform: uppercase; font-size: .75rem; letter-spacing: .06em;
    }
    .risk-critical { background: #7f1d1d; color: #fecaca; }
    .risk-high { background: #7c2d12; color: #fed7aa; }
    .risk-medium { background: #713f12; color: #fde68a; }
    .risk-low { background: #14532d; color: #bbf7d0; }
    .bar-row { display: grid; grid-template-columns: 90px 1fr 36px; gap: .6rem; align-items: center; margin: .45rem 0; }
    .bar-track { background: #0f172a; border-radius: 999px; height: 10px; overflow: hidden; }
    .bar-fill { height: 100%; border-radius: 999px; }
    .sev-critical { background: #dc2626; }
    .sev-high { background: #ea580c; }
    .sev-medium { background: #ca8a04; }
    .sev-low { background: #2563eb; }
    .sev-info { background: #64748b; }
    .timeline { list-style: none; padding: 0; margin: 0; }
    .timeline li {
      display: flex; gap: .75rem; align-items: center; padding: .45rem 0;
      border-bottom: 1px dashed var(--border);
    }
    .timeline .step {
      width: 28px; height: 28px; border-radius: 50%; display: grid; place-items: center;
      background: #1e293b; color: var(--accent-2); font-size: .75rem; font-weight: 700;
    }
    .tags { display: flex; flex-wrap: wrap; gap: .35rem; margin-top: .5rem; }
    .tag {
      font-size: .72rem; padding: .15rem .45rem; border-radius: 6px;
      background: #0f172a; border: 1px solid var(--border); color: var(--muted);
    }
    table { width: 100%; border-collapse: collapse; font-size: .9rem; }
    th, td { text-align: left; padding: .55rem .4rem; border-bottom: 1px solid var(--border); vertical-align: top; }
    th { color: var(--muted); font-weight: 600; font-size: .78rem; text-transform: uppercase; letter-spacing: .05em; }
    .finding {
      border: 1px solid var(--border); border-radius: 12px; padding: 1rem; margin-bottom: .8rem;
      background: rgba(15,23,42,.35);
    }
    .finding h4 { margin: 0 0 .35rem; display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; }
    .badge {
      font-size: .7rem; font-weight: 700; text-transform: uppercase; letter-spacing: .05em;
      padding: .2rem .5rem; border-radius: 999px;
    }
    .status-fail { color: #fecaca; }
    .status-warn { color: #fde68a; }
    .status-pass { color: #bbf7d0; }
    .muted { color: var(--muted); }
    .section { margin-top: 1.25rem; }
    ul.clean { margin: 0; padding-left: 1.1rem; }
    footer { margin-top: 2rem; color: var(--muted); font-size: .8rem; text-align: center; }
    @media (max-width: 700px) {
      .bar-row { grid-template-columns: 70px 1fr 28px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header class="hero">
      <div>
        <div class="brand">VibeSec</div>
        <h1>Security Assessment</h1>
        <div class="meta">{{.Document.Summary.Target}} · {{.Document.Summary.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}</div>
      </div>
      <div>
        <span class="risk-pill {{.RiskClass}}">{{.Document.Risk.Level}} risk</span>
        <div class="meta" style="margin-top:.5rem;text-align:right;">Score {{.Document.Risk.Score}}</div>
      </div>
    </header>

    <section class="grid grid-4 section">
      <div class="card"><div class="stat-label">Findings</div><div class="stat-value">{{.Document.Summary.FindingCount}}</div></div>
      <div class="card"><div class="stat-label">Modules</div><div class="stat-value">{{.Document.Summary.ModulesRun}}</div></div>
      <div class="card"><div class="stat-label">High+</div><div class="stat-value">{{.HighSeverityPlus}}</div></div>
      <div class="card"><div class="stat-label">Endpoints probed</div><div class="stat-value">{{len .Document.Endpoints}}</div></div>
    </section>

    <section class="grid grid-2 section">
      <div class="card">
        <h2>Severity distribution</h2>
        {{range .SeverityBars}}
        <div class="bar-row">
          <span>{{.Label}}</span>
          <div class="bar-track"><div class="bar-fill {{.Class}}" style="width:{{.Width}}%"></div></div>
          <span class="muted">{{.Count}}</span>
        </div>
        {{end}}
      </div>
      <div class="card">
        <h2>Scan timeline</h2>
        <ul class="timeline">
          {{range .ModuleTimeline}}
          <li><span class="step">{{.Step}}</span><span>{{.Label}}</span><span class="muted" style="margin-left:auto">{{.Time}}</span></li>
          {{end}}
        </ul>
      </div>
    </section>

    {{if or .Document.Stack .Document.Infrastructure}}
    <section class="grid grid-2 section">
      {{if .Document.Stack}}
      <div class="card">
        <h2>Stack</h2>
        <div class="tags">{{range .Document.Stack}}<span class="tag">{{.}}</span>{{end}}</div>
      </div>
      {{end}}
      {{if .Document.Infrastructure}}
      <div class="card">
        <h2>Infrastructure</h2>
        <div class="tags">{{range .Document.Infrastructure}}<span class="tag">{{.}}</span>{{end}}</div>
      </div>
      {{end}}
    </section>
    {{end}}

    {{if .Document.AI}}
    <section class="card section">
      <h2>AI analysis</h2>
      {{if .Document.AI.ExecutiveSummary}}<p>{{.Document.AI.ExecutiveSummary}}</p>{{end}}
      {{if .Document.AI.Hypotheses}}
      <h3>Hypotheses</h3><ul class="clean">{{range .Document.AI.Hypotheses}}<li>{{.}}</li>{{end}}</ul>
      {{end}}
      {{if .Document.AI.Prioritization}}
      <h3>Prioritization</h3>
      <table>
        <thead><tr><th>#</th><th>Issue</th><th>Severity</th><th>Score</th><th>Rationale</th></tr></thead>
        <tbody>
        {{range .Document.AI.Prioritization}}
        <tr>
          <td>{{.Rank}}</td><td>{{.Title}}</td>
          <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
          <td>{{printf "%.1f" .Score}}</td><td class="muted">{{.Rationale}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
      {{end}}
    </section>
    {{end}}

    {{if .Document.HeaderChecks}}
    <section class="card section">
      <h2>Header checks</h2>
      <table>
        <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>
        {{range .Document.HeaderChecks}}
        <tr>
          <td>{{.Name}}</td>
          <td class="{{headerStatusClass .Status}}">{{.Status}}</td>
          <td>{{.Detail}}</td>
        </tr>
        {{end}}
        </tbody>
      </table>
    </section>
    {{end}}

  <section class="section">
    <h2 style="margin:0 0 .75rem 0;">Findings</h2>
    {{range .Document.Findings}}
    <article class="finding">
      <h4>
        <span>{{.Title}}</span>
        <span class="badge {{severityClass .Severity}}">{{.Severity}}</span>
        {{if .Confidence}}<span class="tag">confidence: {{.Confidence}}</span>{{end}}
      </h4>
      {{if .Description}}<p class="muted">{{.Description}}</p>{{end}}
      {{if .Evidence}}<p><strong>Evidence:</strong> <code>{{.Evidence}}</code></p>{{end}}
      {{if .Recommendation}}<p><strong>Recommendation:</strong> {{.Recommendation}}</p>{{end}}
      {{if hasTaxonomy .}}
      <div class="tags">
        {{if .OWASP}}<span class="tag">OWASP {{.OWASP}}</span>{{end}}
        {{if .ASVS}}<span class="tag">ASVS {{.ASVS}}</span>{{end}}
        {{if .CWE}}<span class="tag">{{.CWE}}</span>{{end}}
        {{if .CAPEC}}<span class="tag">{{.CAPEC}}</span>{{end}}
        {{if .CVSS}}<span class="tag">CVSS {{formatCVSS .CVSS}}</span>{{end}}
      </div>
      {{end}}
    </article>
    {{else}}
    <div class="card muted">No findings recorded.</div>
    {{end}}
  </section>

  {{if .Document.Recommendations}}
  <section class="card section">
    <h2>Recommendations</h2>
    <ul class="clean">{{range .Document.Recommendations}}<li>{{.}}</li>{{end}}</ul>
  </section>
  {{end}}

    <footer>Generated by VibeSec · {{.Document.Summary.GeneratedAt.Format "2006-01-02 15:04:05 UTC"}}</footer>
  </div>
</body>
</html>`
