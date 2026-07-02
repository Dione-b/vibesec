import ReportCard from "./ReportCard";

interface Props {
  label: string;
  value: string | number;
  accent?: string;
}

export default function TechStatCard({ label, value, accent }: Props) {
  return (
    <ReportCard className="!p-4 text-center">
      <p className="text-xs text-muted uppercase tracking-wide">{label}</p>
      <p className={`text-2xl sm:text-3xl font-bold mt-1 ${accent ?? "text-text"}`}>{value}</p>
    </ReportCard>
  );
}
