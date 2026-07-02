import type { Finding, ScanDocument } from "../types";
import { severityRank } from "../lib/severity";
import RiskBanner from "./report/RiskBanner";
import ReportCard from "./report/ReportCard";
import SectionTitle from "./report/SectionTitle";
import SeveritySummaryGrid from "./report/SeveritySummaryGrid";
import ExecutiveFindingCard from "./report/ExecutiveFindingCard";
import RecommendationsList from "./report/RecommendationsList";

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
      <RiskBanner level={risk.level} score={risk.score} variant="banner" />

      <ReportCard>
        <p className="text-sm text-muted leading-relaxed">
          <strong className="text-text">O que é este relatório?</strong>
          <br />
          Este documento resume os problemas de segurança encontrados no seu site. Cada item
          explica, em linguagem simples, o que foi detectado e como isso pode afetar você ou seus
          usuários.
        </p>
      </ReportCard>

      <SeveritySummaryGrid counts={counts} />

      {groupedFindings.length > 0 ? (
        <section>
          <SectionTitle>Problemas Encontrados</SectionTitle>
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
        <ReportCard className="text-center text-accent text-lg py-8">
          Nenhum problema de segurança encontrado.
        </ReportCard>
      )}

      <RecommendationsList recommendations={doc.recommendations ?? []} />
    </div>
  );
}
