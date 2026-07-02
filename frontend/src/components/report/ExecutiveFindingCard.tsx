import type { Finding } from "../../types";
import { severityBadgeClasses, severityNumberClasses } from "../../lib/report-styles";
import { severityEmoji, translateSeverity } from "../../lib/severity";
import ReportCard from "./ReportCard";

interface Props {
  index: number;
  finding: Finding;
  count?: number;
}

export default function ExecutiveFindingCard({ index, finding, count = 1 }: Props) {
  const impact = finding.layperson_impact;
  const action = finding.layperson_recommendation ?? finding.recommendation;
  const severity = finding.severity;

  return (
    <ReportCard className="hover:border-accent-2/40 transition-colors">
      <div className="flex flex-wrap items-center gap-3 mb-3">
        <span
          className={`w-8 h-8 rounded-full flex items-center justify-center text-sm font-bold shrink-0 ${severityNumberClasses(severity)}`}
        >
          {index}
        </span>
        <h4 className="font-semibold text-base flex-1 min-w-0">
          {finding.title}
          {count > 1 ? ` (×${count})` : ""}
        </h4>
        <span
          className={`text-xs font-bold uppercase tracking-wide px-2.5 py-1 rounded-full shrink-0 ${severityBadgeClasses(severity)}`}
        >
          {severityEmoji(severity)} {translateSeverity(severity)}
        </span>
      </div>
      <div className="space-y-2 text-sm text-muted leading-relaxed">
        {impact ? (
          <p>
            <strong className="text-danger">Como isso afeta seu sistema:</strong> {impact}
          </p>
        ) : (
          <p className="italic">Texto simplificado indisponível para este item.</p>
        )}
        {action && (
          <p>
            <strong className="text-accent">O que fazer:</strong> {action}
          </p>
        )}
      </div>
    </ReportCard>
  );
}
