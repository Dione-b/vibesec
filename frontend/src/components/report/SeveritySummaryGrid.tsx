import { SEVERITY_SUMMARY_ROWS } from "../../lib/severity";
import ReportCard from "./ReportCard";

interface Props {
  counts: Record<string, number>;
}

export default function SeveritySummaryGrid({ counts }: Props) {
  const items = SEVERITY_SUMMARY_ROWS.filter((row) => (counts[row.key] ?? 0) > 0);
  if (items.length === 0) return null;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 mb-8">
      {items.map((row) => (
        <ReportCard key={row.key} className="text-center !p-4">
          <div className="text-2xl mb-1">{row.emoji}</div>
          <div className="text-2xl font-bold">{counts[row.key]}</div>
          <div className="text-xs text-muted uppercase tracking-wide mt-1">{row.label}</div>
        </ReportCard>
      ))}
    </div>
  );
}
