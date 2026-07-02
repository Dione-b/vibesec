import type { Finding } from "../../types";
import { severityBadgeClasses } from "../../lib/report-styles";
import ReportCard from "./ReportCard";

interface Props {
  finding: Finding;
}

export default function TechnicalFindingCard({ finding }: Props) {
  return (
    <ReportCard className="hover:border-accent-2/40 transition-colors !p-4">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-2 mb-2">
        <div className="flex-1 min-w-0">
          <h4 className="font-semibold text-text flex flex-wrap items-center gap-2">
            {finding.title}
            <span
              className={`text-[0.65rem] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full ${severityBadgeClasses(finding.severity)}`}
            >
              {finding.severity}
            </span>
          </h4>
          <p className="text-xs text-muted mt-1">
            {finding.module}
            {finding.cwe ? ` · ${finding.cwe}` : ""}
            {finding.confidence ? ` · ${finding.confidence}` : ""}
          </p>
        </div>
      </div>
      <p className="text-sm text-muted leading-relaxed">{finding.description}</p>
      {finding.evidence && (
        <pre className="mt-3 text-xs bg-bg/80 border border-border rounded-lg p-3 overflow-x-auto text-muted font-mono">
          {finding.evidence}
        </pre>
      )}
      {finding.recommendation && (
        <p className="mt-2 text-sm text-accent leading-relaxed">{finding.recommendation}</p>
      )}
    </ReportCard>
  );
}
