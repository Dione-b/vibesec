package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/dionebastos/vibesec/internal/finding"
)

// RenderExecutiveHTML generates a visually rich, non-technical HTML report
// designed for stakeholders who need to understand the security posture
// without diving into technical details.
func RenderExecutiveHTML(doc *Document) string {
	if doc == nil {
		return ""
	}
	data := buildExecutiveHTMLData(doc)
	var buf bytes.Buffer
	if err := executiveHTMLTemplate.Execute(&buf, data); err != nil {
		return fmt.Sprintf("<!DOCTYPE html><html><body><pre>render error: %s</pre></body></html>", template.HTMLEscapeString(err.Error()))
	}
	return buf.String()
}

type executiveHTMLData struct {
	Document       *Document
	RiskClass      string
	RiskLabel      string
	FindingItems   []executiveFinding
	HasFindings    bool
	SeverityCounts []executiveSeverityCount
}

type executiveFinding struct {
	Index          int
	Title          string
	SeverityClass  string
	SeverityLabel  string
	SeverityEmoji  string
	Impact         string
	Recommendation string
}

type executiveSeverityCount struct {
	Label string
	Count int
	Class string
	Emoji string
}

func buildExecutiveHTMLData(doc *Document) executiveHTMLData {
	data := executiveHTMLData{
		Document:    doc,
		RiskClass:   riskCSSClass(doc.Risk.Level),
		RiskLabel:   execTranslateRisk(doc.Risk.Level),
		HasFindings: len(doc.Findings) > 0,
	}

	severityOrder := []struct {
		key   string
		label string
		class string
		emoji string
	}{
		{"critical", "Crítico", "sev-critical", "🔴"},
		{"high", "Alto", "sev-high", "🟠"},
		{"medium", "Médio", "sev-medium", "🟡"},
		{"low", "Baixo", "sev-low", "🔵"},
		{"info", "Informativo", "sev-info", "⚪"},
	}
	for _, s := range severityOrder {
		count := doc.Risk.Counts[s.key]
		if count > 0 {
			data.SeverityCounts = append(data.SeverityCounts, executiveSeverityCount{
				Label: s.label,
				Count: count,
				Class: s.class,
				Emoji: s.emoji,
			})
		}
	}

	for i, item := range doc.Findings {
		data.FindingItems = append(data.FindingItems, executiveFinding{
			Index:          i + 1,
			Title:          item.Title,
			SeverityClass:  findingSeverityClass(item.Severity),
			SeverityLabel:  execTranslateSeverity(item.Severity),
			SeverityEmoji:  execSeverityEmoji(item.Severity),
			Impact:         finding.LaypersonExplanation(item),
			Recommendation: item.Recommendation,
		})
	}

	return data
}

func execTranslateRisk(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "Crítico"
	case "high":
		return "Alto"
	case "medium":
		return "Médio"
	case "low":
		return "Baixo"
	default:
		return level
	}
}

func execTranslateSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Crítico"
	case "high":
		return "Alto"
	case "medium":
		return "Médio"
	case "low":
		return "Baixo"
	case "info":
		return "Informativo"
	default:
		return severity
	}
}

func execSeverityEmoji(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "🔴"
	case "high":
		return "🟠"
	case "medium":
		return "🟡"
	case "low":
		return "🔵"
	default:
		return "⚪"
	}
}



var executiveHTMLTemplate = template.Must(template.New("executive").Parse(executiveHTMLPageTemplate))

const executiveHTMLPageTemplate = `<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Relatório de Segurança — {{.Document.Summary.Target}}</title>
  <style>
    :root {
      --bg: #0f1729;
      --panel: #162040;
      --panel-2: #1c2a50;
      --border: #2d3f6b;
      --text: #e8edf8;
      --muted: #9aa8c7;
      --accent: #6ee7b7;
      --accent-2: #38bdf8;
      --danger: #f87171;
      --warning: #fbbf24;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
      background: linear-gradient(135deg, #0f1729 0%, #152042 50%, #0f1729 100%);
      color: var(--text);
      line-height: 1.65;
      min-height: 100vh;
    }
    .wrap { max-width: 900px; margin: 0 auto; padding: 2.5rem 1.5rem 4rem; }

    /* Header */
    .header {
      text-align: center;
      margin-bottom: 2.5rem;
      padding-bottom: 2rem;
      border-bottom: 1px solid var(--border);
    }
    .header .brand {
      font-size: .8rem;
      letter-spacing: .15em;
      text-transform: uppercase;
      color: var(--accent);
      margin-bottom: .5rem;
    }
    .header h1 {
      font-size: 2rem;
      font-weight: 700;
      margin-bottom: .75rem;
    }
    .header .meta {
      color: var(--muted);
      font-size: .95rem;
    }

    /* Risk banner */
    .risk-banner {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 1rem;
      padding: 1.25rem 1.5rem;
      border-radius: 16px;
      margin-bottom: 2rem;
      border: 1px solid var(--border);
    }
    .risk-banner.risk-critical { background: linear-gradient(135deg, #450a0a 0%, #7f1d1d 100%); border-color: #991b1b; }
    .risk-banner.risk-high { background: linear-gradient(135deg, #431407 0%, #7c2d12 100%); border-color: #9a3412; }
    .risk-banner.risk-medium { background: linear-gradient(135deg, #422006 0%, #713f12 100%); border-color: #854d0e; }
    .risk-banner.risk-low { background: linear-gradient(135deg, #052e16 0%, #14532d 100%); border-color: #166534; }
    .risk-banner .risk-label {
      font-size: 1.4rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .05em;
    }
    .risk-banner .risk-score {
      font-size: .9rem;
      color: var(--muted);
    }

    /* Info box */
    .info-box {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 2rem;
      color: var(--muted);
      font-size: .95rem;
    }
    .info-box strong { color: var(--text); }

    /* Summary cards */
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: .75rem;
      margin-bottom: 2rem;
    }
    .summary-card {
      background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1rem;
      text-align: center;
    }
    .summary-card .emoji { font-size: 1.5rem; }
    .summary-card .count { font-size: 1.6rem; font-weight: 700; margin: .25rem 0; }
    .summary-card .label { font-size: .8rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }

    /* Section titles */
    .section-title {
      font-size: 1.25rem;
      font-weight: 700;
      margin: 2rem 0 1rem;
      padding-bottom: .5rem;
      border-bottom: 1px solid var(--border);
    }

    /* Finding cards */
    .finding-card {
      background: linear-gradient(180deg, var(--panel) 0%, rgba(28, 42, 80, .6) 100%);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.25rem 1.5rem;
      margin-bottom: 1rem;
      transition: border-color .2s;
    }
    .finding-card:hover { border-color: var(--accent-2); }
    .finding-header {
      display: flex;
      align-items: center;
      gap: .75rem;
      margin-bottom: .75rem;
    }
    .finding-number {
      width: 32px;
      height: 32px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      font-weight: 700;
      font-size: .85rem;
      flex-shrink: 0;
    }
    .finding-number.sev-critical { background: #7f1d1d; color: #fecaca; }
    .finding-number.sev-high { background: #7c2d12; color: #fed7aa; }
    .finding-number.sev-medium { background: #713f12; color: #fde68a; }
    .finding-number.sev-low { background: #1e3a5f; color: #bfdbfe; }
    .finding-number.sev-info { background: #334155; color: #cbd5e1; }
    .finding-title { font-weight: 600; font-size: 1.05rem; }
    .finding-badge {
      font-size: .7rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .04em;
      padding: .2rem .55rem;
      border-radius: 999px;
      margin-left: auto;
      flex-shrink: 0;
    }
    .finding-badge.sev-critical { background: #7f1d1d; color: #fecaca; }
    .finding-badge.sev-high { background: #7c2d12; color: #fed7aa; }
    .finding-badge.sev-medium { background: #713f12; color: #fde68a; }
    .finding-badge.sev-low { background: #1e3a5f; color: #bfdbfe; }
    .finding-badge.sev-info { background: #334155; color: #cbd5e1; }
    .finding-body p {
      margin-bottom: .6rem;
      font-size: .95rem;
      color: var(--muted);
    }
    .finding-body p strong {
      color: var(--text);
    }
    .finding-body .impact-label { color: var(--danger); }
    .finding-body .action-label { color: var(--accent); }

    /* Recommendations */
    .recommendations {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 1.25rem 1.5rem;
    }
    .recommendations ol {
      padding-left: 1.2rem;
      color: var(--muted);
    }
    .recommendations li {
      margin-bottom: .5rem;
      font-size: .95rem;
    }

    /* No findings */
    .no-findings {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 2rem;
      text-align: center;
      color: var(--accent);
      font-size: 1.1rem;
    }

    /* Footer */
    footer {
      margin-top: 3rem;
      text-align: center;
      color: var(--muted);
      font-size: .8rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border);
    }

    @media (max-width: 600px) {
      .header h1 { font-size: 1.5rem; }
      .summary-grid { grid-template-columns: repeat(2, 1fr); }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div class="brand">VibeSec — Relatório Executivo</div>
      <h1>Análise de Segurança</h1>
      <div class="meta">{{.Document.Summary.Target}} · {{.Document.Summary.GeneratedAt.Format "02/01/2006 15:04 UTC"}}</div>
    </div>

    <div class="risk-banner {{.RiskClass}}">
      <span class="risk-label">Risco {{.RiskLabel}}</span>
      <span class="risk-score">Pontuação: {{.Document.Risk.Score}}</span>
    </div>

    <div class="info-box">
      <strong>O que é este relatório?</strong><br>
      Este documento resume os problemas de segurança encontrados no seu site.
      Cada item explica, em linguagem simples, o que foi detectado e como isso pode afetar você ou seus usuários.
    </div>

    {{if .SeverityCounts}}
    <div class="summary-grid">
      {{range .SeverityCounts}}
      <div class="summary-card">
        <div class="emoji">{{.Emoji}}</div>
        <div class="count">{{.Count}}</div>
        <div class="label">{{.Label}}</div>
      </div>
      {{end}}
    </div>
    {{end}}

    {{if .HasFindings}}
    <h2 class="section-title">Problemas Encontrados</h2>
    {{range .FindingItems}}
    <div class="finding-card">
      <div class="finding-header">
        <span class="finding-number {{.SeverityClass}}">{{.Index}}</span>
        <span class="finding-title">{{.Title}}</span>
        <span class="finding-badge {{.SeverityClass}}">{{.SeverityEmoji}} {{.SeverityLabel}}</span>
      </div>
      <div class="finding-body">
        {{if .Impact}}<p><strong class="impact-label">Como isso afeta seu sistema:</strong> {{.Impact}}</p>{{end}}
        {{if .Recommendation}}<p><strong class="action-label">O que fazer:</strong> {{.Recommendation}}</p>{{end}}
      </div>
    </div>
    {{end}}
    {{else}}
    <div class="no-findings">✅ Nenhum problema de segurança encontrado.</div>
    {{end}}

    {{if .Document.Recommendations}}
    <h2 class="section-title">Próximos Passos</h2>
    <div class="recommendations">
      <ol>
        {{range .Document.Recommendations}}<li>{{.}}</li>{{end}}
      </ol>
    </div>
    {{end}}

    <footer>Gerado por VibeSec · {{.Document.Summary.GeneratedAt.Format "02/01/2006 15:04 UTC"}}</footer>
  </div>
</body>
</html>`
