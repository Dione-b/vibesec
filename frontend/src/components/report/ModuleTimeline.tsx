import { buildModuleTimeline } from "../../lib/report-styles";
import ReportCard from "./ReportCard";
import SectionTitle from "./SectionTitle";

interface Props {
  modulesRun: number;
  generatedAt?: string;
  title?: string;
}

export default function ModuleTimeline({ modulesRun, generatedAt, title = "Timeline do scan" }: Props) {
  const items = buildModuleTimeline(modulesRun, generatedAt);
  if (items.length === 0) return null;

  return (
    <ReportCard>
      <SectionTitle className="!text-base !mb-3 !pb-2">{title}</SectionTitle>
      <ul className="space-y-0">
        {items.map((item) => (
          <li
            key={item.step}
            className="flex items-center gap-3 py-2 border-b border-dashed border-border last:border-0"
          >
            <span className="w-7 h-7 rounded-full bg-bg text-accent-2 text-xs font-bold flex items-center justify-center shrink-0">
              {item.step}
            </span>
            <span className="text-sm flex-1">{item.label}</span>
            <span className="text-xs text-muted">{item.time}</span>
          </li>
        ))}
      </ul>
    </ReportCard>
  );
}
