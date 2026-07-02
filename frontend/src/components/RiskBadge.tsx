import { translateSeverity } from "../lib/severity";

const RISK_STYLES: Record<string, string> = {
  critical: "bg-red-600/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-yellow-500/20 text-yellow-300 border-yellow-500/40",
  low: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  info: "bg-gray-500/20 text-gray-300 border-gray-500/40",
};

export default function RiskBadge({ level }: { level: string }) {
  const style = RISK_STYLES[level.toLowerCase()] ?? RISK_STYLES.info;
  const label = translateSeverity(level);
  return (
    <span
      className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-semibold border ${style}`}
    >
      {label}
    </span>
  );
}
