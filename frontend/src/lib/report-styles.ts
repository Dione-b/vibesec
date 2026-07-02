import { SEVERITY_SUMMARY_ROWS } from "./severity";

export interface SeverityBar {
  key: string;
  label: string;
  count: number;
  width: number;
}

export const MODULE_STEPS = [
  "Fingerprint",
  "Headers",
  "CSP",
  "Bundle",
  "Endpoints",
  "Auth",
  "Authorization",
  "Plugins",
  "Nuclei",
  "Burp",
  "Correlation",
  "AI Analyzer",
  "Report",
] as const;

export function riskBannerClasses(level: string): string {
  switch (level.toLowerCase()) {
    case "critical":
      return "bg-gradient-to-br from-red-950 to-red-900 border-red-800";
    case "high":
      return "bg-gradient-to-br from-orange-950 to-orange-900 border-orange-800";
    case "medium":
      return "bg-gradient-to-br from-yellow-950 to-yellow-900 border-yellow-800";
    case "low":
      return "bg-gradient-to-br from-green-950 to-green-900 border-green-800";
    default:
      return "bg-gradient-to-br from-panel to-panel-2 border-border";
  }
}

export function riskPillClasses(level: string): string {
  switch (level.toLowerCase()) {
    case "critical":
      return "bg-red-900 text-red-200";
    case "high":
      return "bg-orange-900 text-orange-200";
    case "medium":
      return "bg-yellow-900 text-yellow-200";
    case "low":
      return "bg-green-900 text-green-200";
    default:
      return "bg-slate-700 text-slate-200";
  }
}

export function severityNumberClasses(level: string): string {
  switch (level.toLowerCase()) {
    case "critical":
      return "bg-red-900 text-red-200";
    case "high":
      return "bg-orange-900 text-orange-200";
    case "medium":
      return "bg-yellow-900 text-yellow-200";
    case "low":
      return "bg-blue-900 text-blue-200";
    default:
      return "bg-slate-700 text-slate-200";
  }
}

export function severityBadgeClasses(level: string): string {
  return severityNumberClasses(level);
}

export function severityBarClasses(level: string): string {
  switch (level.toLowerCase()) {
    case "critical":
      return "bg-red-600";
    case "high":
      return "bg-orange-600";
    case "medium":
      return "bg-yellow-600";
    case "low":
      return "bg-blue-600";
    default:
      return "bg-slate-500";
  }
}

export function buildSeverityBars(counts: Record<string, number>): SeverityBar[] {
  let max = 1;
  for (const row of SEVERITY_SUMMARY_ROWS) {
    const count = counts[row.key] ?? 0;
    if (count > max) max = count;
  }

  return SEVERITY_SUMMARY_ROWS.map((row) => {
    const count = counts[row.key] ?? 0;
    let width = 0;
    if (count > 0) {
      width = Math.round((count * 100) / max);
      if (width < 8) width = 8;
    }
    return { key: row.key, label: row.label, count, width };
  });
}

export function buildModuleTimeline(modulesRun: number, generatedAt?: string): { step: number; label: string; time: string }[] {
  const time = generatedAt
    ? new Date(generatedAt).toLocaleTimeString("pt-BR", { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : "—";
  const limit = Math.min(modulesRun, MODULE_STEPS.length);
  return MODULE_STEPS.slice(0, limit).map((label, i) => ({
    step: i + 1,
    label,
    time,
  }));
}
