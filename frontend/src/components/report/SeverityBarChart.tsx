import { buildSeverityBars, severityBarClasses } from "../../lib/report-styles";
import ReportCard from "./ReportCard";
import SectionTitle from "./SectionTitle";

interface Props {
  counts: Record<string, number>;
  title?: string;
}

export default function SeverityBarChart({ counts, title = "Distribuição por severidade" }: Props) {
  const bars = buildSeverityBars(counts);

  return (
    <ReportCard>
      <SectionTitle className="!text-base !mb-3 !pb-2">{title}</SectionTitle>
      <div className="space-y-2">
        {bars.map((bar) => (
          <div key={bar.key} className="grid grid-cols-[72px_1fr_28px] sm:grid-cols-[90px_1fr_36px] gap-2 items-center">
            <span className="text-sm text-muted">{bar.label}</span>
            <div className="bg-bg rounded-full h-2.5 overflow-hidden">
              {bar.count > 0 && (
                <div
                  className={`h-full rounded-full ${severityBarClasses(bar.key)}`}
                  style={{ width: `${bar.width}%` }}
                />
              )}
            </div>
            <span className="text-sm text-muted text-right">{bar.count}</span>
          </div>
        ))}
      </div>
    </ReportCard>
  );
}
