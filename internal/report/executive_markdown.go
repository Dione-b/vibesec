package report

import (
	"fmt"
	"strings"

	"github.com/dionebastos/vibesec/internal/finding"
)

// RenderExecutiveMarkdown generates a simplified report aimed at non-technical
// stakeholders. It explains each finding in plain language, focusing on the
// real-world impact rather than technical taxonomy.
func RenderExecutiveMarkdown(doc *Document) string {
	if doc == nil {
		return ""
	}

	var b strings.Builder
	b.WriteString("# Relatório de Segurança — Visão Executiva\n\n")
	b.WriteString(fmt.Sprintf("**Site analisado:** %s\n", doc.Summary.Target))
	b.WriteString(fmt.Sprintf("**Data:** %s\n", doc.Summary.GeneratedAt.Format(timeLayout)))
	b.WriteString(fmt.Sprintf("**Nível de risco geral:** %s\n\n", translateRiskLevel(doc.Risk.Level)))

	b.WriteString("---\n\n")
	b.WriteString("## O que é este relatório?\n\n")
	b.WriteString("Este documento resume os problemas de segurança encontrados no seu site. ")
	b.WriteString("Cada item explica, em linguagem simples, o que foi detectado e como isso pode afetar você ou seus usuários.\n\n")

	b.WriteString("---\n\n")
	b.WriteString("## Resumo\n\n")
	b.WriteString(fmt.Sprintf("Foram encontrados **%d problemas** durante a análise:\n\n", doc.Summary.FindingCount))

	if doc.Risk.Counts["critical"] > 0 {
		b.WriteString(fmt.Sprintf("- 🔴 **%d crítico(s)** — exigem ação imediata\n", doc.Risk.Counts["critical"]))
	}
	if doc.Risk.Counts["high"] > 0 {
		b.WriteString(fmt.Sprintf("- 🟠 **%d alto(s)** — devem ser corrigidos com urgência\n", doc.Risk.Counts["high"]))
	}
	if doc.Risk.Counts["medium"] > 0 {
		b.WriteString(fmt.Sprintf("- 🟡 **%d médio(s)** — importante corrigir em breve\n", doc.Risk.Counts["medium"]))
	}
	if doc.Risk.Counts["low"] > 0 {
		b.WriteString(fmt.Sprintf("- 🔵 **%d baixo(s)** — melhorias recomendadas\n", doc.Risk.Counts["low"]))
	}
	if doc.Risk.Counts["info"] > 0 {
		b.WriteString(fmt.Sprintf("- ⚪ **%d informativo(s)** — observações sem risco direto\n", doc.Risk.Counts["info"]))
	}
	b.WriteString("\n")

	if len(doc.Findings) > 0 {
		b.WriteString("---\n\n")
		b.WriteString("## Problemas Encontrados\n\n")

		for i, item := range doc.Findings {
			b.WriteString(fmt.Sprintf("### %d. %s\n\n", i+1, item.Title))
			b.WriteString(fmt.Sprintf("**Gravidade:** %s %s\n\n",
				severityEmoji(item.Severity), translateSeverity(item.Severity)))

			impact := executiveImpact(item)
			if impact != "" {
				b.WriteString(fmt.Sprintf("**Como isso afeta seu sistema:** %s\n\n", impact))
			}

			if item.Recommendation != "" {
				b.WriteString(fmt.Sprintf("**O que fazer:** %s\n\n", item.Recommendation))
			}
		}
	}

	if len(doc.Recommendations) > 0 {
		b.WriteString("---\n\n")
		b.WriteString("## Próximos Passos\n\n")
		for i, rec := range doc.Recommendations {
			b.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
		}
		b.WriteString("\n")
	}

	b.WriteString("---\n\n")
	b.WriteString("*Relatório gerado por VibeSec*\n")

	return b.String()
}

func translateRiskLevel(level string) string {
	switch strings.ToLower(level) {
	case "critical":
		return "🔴 Crítico"
	case "high":
		return "🟠 Alto"
	case "medium":
		return "🟡 Médio"
	case "low":
		return "🟢 Baixo"
	default:
		return level
	}
}

func translateSeverity(severity string) string {
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

func severityEmoji(severity string) string {
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

// executiveImpact returns a plain-language explanation of a finding's real-world
// impact, written for non-technical stakeholders. It uses the dictionary lookup
// which maps technical findings to layperson-friendly descriptions in Portuguese.
func executiveImpact(item finding.Finding) string {
	return finding.LaypersonExplanation(item)
}
