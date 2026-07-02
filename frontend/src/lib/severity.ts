const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export function translateSeverity(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "Crítico";
    case "high":
      return "Alto";
    case "medium":
      return "Médio";
    case "low":
      return "Baixo";
    case "info":
      return "Informativo";
    default:
      return severity;
  }
}

export function translateRiskLevel(level: string): string {
  return translateSeverity(level);
}

export function severityRank(severity: string): number {
  const idx = SEVERITY_ORDER.indexOf(severity.toLowerCase() as (typeof SEVERITY_ORDER)[number]);
  return idx === -1 ? SEVERITY_ORDER.length : idx;
}

export function severityEmoji(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
      return "🔴";
    case "high":
      return "🟠";
    case "medium":
      return "🟡";
    case "low":
      return "🔵";
    default:
      return "⚪";
  }
}

export const SEVERITY_SUMMARY_ROWS = [
  { key: "critical", label: "Crítico", emoji: "🔴", description: "exigem ação imediata" },
  { key: "high", label: "Alto", emoji: "🟠", description: "devem ser corrigidos com urgência" },
  { key: "medium", label: "Médio", emoji: "🟡", description: "importante corrigir em breve" },
  { key: "low", label: "Baixo", emoji: "🔵", description: "melhorias recomendadas" },
  { key: "info", label: "Informativo", emoji: "⚪", description: "observações sem risco direto" },
] as const;
