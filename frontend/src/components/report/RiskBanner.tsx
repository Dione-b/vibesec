import { riskBannerClasses, riskPillClasses } from "../../lib/report-styles";
import { translateRiskLevel } from "../../lib/severity";

interface Props {
  level: string;
  score: number;
  variant?: "banner" | "compact";
}

export default function RiskBanner({ level, score, variant = "banner" }: Props) {
  if (variant === "compact") {
    return (
      <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
        <div>
          <p className="text-xs uppercase tracking-widest text-accent mb-1">VibeSec</p>
          <p className="text-muted text-sm">Security Assessment</p>
        </div>
        <div className="text-right">
          <span
            className={`inline-block px-3 py-1.5 rounded-full text-xs font-bold uppercase tracking-wide ${riskPillClasses(level)}`}
          >
            {translateRiskLevel(level)} risk
          </span>
          <p className="text-muted text-sm mt-1">Score {score}</p>
        </div>
      </div>
    );
  }

  return (
    <div
      className={`flex flex-col sm:flex-row items-center justify-center gap-2 sm:gap-4 px-5 py-5 rounded-2xl border mb-6 ${riskBannerClasses(level)}`}
    >
      <span className="text-xl sm:text-2xl font-bold uppercase tracking-wide">
        Risco {translateRiskLevel(level)}
      </span>
      <span className="text-muted text-sm">Pontuação: {score}</span>
    </div>
  );
}
