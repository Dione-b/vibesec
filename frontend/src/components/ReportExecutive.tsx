import type { Finding, ScanDocument } from "../types";
import RiskBadge from "./RiskBadge";
import {
  SEVERITY_SUMMARY_ROWS,
  severityRank,
  translateRiskLevel,
} from "../lib/severity";

interface Props {
  doc: ScanDocument;
}

interface GroupedFinding {
  key: string;
  finding: Finding;
  count: number;
}

function groupFindings(findings: Finding[]): GroupedFinding[] {
  const groups = new Map<string, GroupedFinding>();
  for (const f of findings) {
    const impact = f.layperson_impact ?? "";
    const action = f.layperson_recommendation ?? "";
    const key = `${f.title}|${impact}|${action}`;
    const existing = groups.get(key);
    if (existing) {
      existing.count += 1;
    } else {
      groups.set(key, { key, finding: f, count: 1 });
    }
  }
  return [...groups.values()];
}

export default function ReportExecutive({ doc }: Props) {
  const risk = doc.risk;
  const counts = risk.counts ?? {};
  const findings = [...(doc.findings ?? [])].sort(
    (a, b) => severityRank(a.severity) - severityRank(b.severity)
  );
  const groupedFindings = groupFindings(findings);

  return (
    <div className="space-y-8">
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Risco"
          value={translateRiskLevel(risk.level)}
          color={riskColor(risk.level)}
        />
        <StatCard label="Score" value={`${risk.score}/100`} color="text-text" />
        <StatCard label="Total" value={String(findings.length)} color="text-text" />
        <StatCard
          label="Críticos + Altos"
          value={String((counts.critical ?? 0) + (counts.high ?? 0))}
          color="text-danger"
        />
      </section>

      <section className="bg-panel border border-border rounded-xl p-5">
        <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-2">
          O que é este relatório?
        </h3>
        <p className="text-sm text-muted leading-relaxed">
          Este documento resume os problemas de segurança encontrados no seu site. Cada item
          explica, em linguagem simples, o que foi detectado e como isso pode afetar você ou seus
          usuários.
        </p>
      </section>

      {findings.length > 0 && (
        <section>
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-3">
            Resumo
          </h3>
          <p className="text-sm text-muted mb-3">
            Foram encontrados <strong className="text-text">{findings.length}</strong> problemas
            durante a análise:
          </p>
          <ul className="space-y-1.5 text-sm text-muted">
            {SEVERITY_SUMMARY_ROWS.map((row) => {
              const count = counts[row.key] ?? 0;
              if (count === 0) return null;
              return (
                <li key={row.key}>
                  {row.emoji} <strong className="text-text">{count}</strong> {row.label.toLowerCase()}
                  {count > 1 ? "s" : ""} — {row.description}
                </li>
              );
            })}
          </ul>
        </section>
      )}

      {groupedFindings.length > 0 ? (
        <section>
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-3">
            Problemas Encontrados
          </h3>
          <div className="space-y-4">
            {groupedFindings.map((group, i) => (
              <ExecutiveFindingCard
                key={group.key}
                index={i + 1}
                finding={group.finding}
                count={group.count}
              />
            ))}
          </div>
        </section>
      ) : (
        <p className="text-muted text-sm text-center py-8">Nenhum problema encontrado</p>
      )}
    </div>
  );
}

function ExecutiveFindingCard({
  index,
  finding,
  count,
}: {
  index: number;
  finding: Finding;
  count: number;
}) {
  const impact = finding.layperson_impact;
  const action = finding.layperson_recommendation;

  return (
    <div className="bg-panel border border-border rounded-xl p-4">
      <div className="flex items-start justify-between gap-3 mb-2">
        <h4 className="font-medium text-text text-sm">
          {index}. {finding.title}
          {count > 1 ? ` (×${count})` : ""}
        </h4>
        <RiskBadge level={finding.severity} />
      </div>
      {impact ? (
        <p className="text-sm text-muted leading-relaxed">
          <span className="text-text font-medium">Como isso afeta seu sistema: </span>
          {impact}
        </p>
      ) : (
        <p className="text-sm text-muted italic">Texto simplificado indisponível para este item.</p>
      )}
      {action && (
        <p className="mt-2 text-xs text-accent leading-relaxed">
          <span className="font-medium">O que fazer: </span>
          {action}
        </p>
      )}
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="bg-panel border border-border rounded-xl p-4 text-center">
      <p className="text-xs text-muted uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${color}`}>{value}</p>
    </div>
  );
}

function riskColor(level: string): string {
  switch (level.toLowerCase()) {
    case "critical":
      return "text-red-400";
    case "high":
      return "text-orange-400";
    case "medium":
      return "text-yellow-400";
    case "low":
      return "text-blue-400";
    default:
      return "text-muted";
  }
}
