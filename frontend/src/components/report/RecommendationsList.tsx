import ReportCard from "./ReportCard";
import SectionTitle from "./SectionTitle";

interface Props {
  recommendations: string[];
}

export default function RecommendationsList({ recommendations }: Props) {
  if (recommendations.length === 0) return null;

  return (
    <section>
      <SectionTitle>Próximos Passos</SectionTitle>
      <ReportCard>
        <ol className="list-decimal list-inside space-y-2 text-sm text-muted leading-relaxed">
          {recommendations.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ol>
      </ReportCard>
    </section>
  );
}
