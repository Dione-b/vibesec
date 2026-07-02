import { useState } from "react";
import { useParams } from "react-router";
import { useScan } from "../hooks/useScan";
import type { ScanDocument } from "../types";
import StatusBadge from "../components/StatusBadge";
import RiskBadge from "../components/RiskBadge";
import ReportExecutive from "../components/ReportExecutive";
import ReportTechnical from "../components/ReportTechnical";
import ReportCard from "../components/report/ReportCard";
import { ReportContentSkeleton, ReportPageSkeleton } from "../components/ReportSkeleton";
import { downloadTechnicalReportJSON } from "../lib/export-report";

type Tab = "executive" | "technical";

export default function Report() {
  const { id } = useParams<{ id: string }>();
  const { scan, isLoading, error } = useScan(id ?? null);
  const [tab, setTab] = useState<Tab>("executive");

  if (isLoading) {
    return <ReportPageSkeleton />;
  }

  if (error || !scan) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-red-400">Relatório não encontrado</div>
      </div>
    );
  }

  const doc: ScanDocument | null = scan.document_json
    ? JSON.parse(scan.document_json)
    : null;

  return (
    <div className="max-w-5xl mx-auto px-4 py-8">
      <div className="mb-8">
        <div className="flex flex-wrap items-center gap-2 sm:gap-3 mb-3">
          <StatusBadge status={scan.status} />
          {scan.risk_level && <RiskBadge level={scan.risk_level} />}
        </div>
        <h1 className="text-xl sm:text-2xl font-bold text-text truncate">{scan.target}</h1>
        <p className="text-muted text-xs sm:text-sm mt-1">
          {new Date(scan.created_at).toLocaleString("pt-BR")}
          {scan.finished_at && ` — ${new Date(scan.finished_at).toLocaleString("pt-BR")}`}
        </p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 sm:gap-4 mb-8">
        <StatCard label="Findings" value={scan.finding_count} />
        <StatCard label="High" value={scan.high_count} accent="text-orange-400" />
        <StatCard label="Critical" value={scan.critical_count} accent="text-red-400" />
      </div>

      {scan.status === "pending" || scan.status === "running" ? (
        <ReportContentSkeleton />
      ) : scan.status === "failed" ? (
        <div className="text-center py-16">
          <p className="text-red-400 mb-2">Scan falhou</p>
          {scan.error_message && (
            <p className="text-muted text-sm">{scan.error_message}</p>
          )}
        </div>
      ) : doc ? (
        <>
          <ReportCard className="!p-1.5 mb-6">
            <div className="flex w-full flex-col sm:flex-row gap-2 sm:items-center">
              <div className="flex w-full gap-1">
                <TabButton active={tab === "executive"} onClick={() => setTab("executive")}>
                  Empresarial
                </TabButton>
                <TabButton active={tab === "technical"} onClick={() => setTab("technical")}>
                  Técnico
                </TabButton>
              </div>
              {tab === "technical" ? (
                <button
                  type="button"
                  onClick={() => downloadTechnicalReportJSON(doc, scan.target)}
                  className="shrink-0 px-4 py-2.5 rounded-xl text-sm font-medium border border-accent/30 bg-accent/10 text-accent hover:bg-accent/15 transition-colors"
                >
                  Exportar JSON
                </button>
              ) : null}
            </div>
          </ReportCard>

          <div className="min-h-[40vh]">
            {tab === "executive" ? (
              <ReportExecutive doc={doc} />
            ) : (
              <ReportTechnical doc={doc} />
            )}
          </div>
        </>
      ) : (
        <p className="text-muted text-center py-16">Dados do relatório indisponíveis</p>
      )}
    </div>
  );
}

function TabButton({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={`flex-1 text-center px-5 py-2.5 rounded-xl text-sm font-medium transition-colors ${
        active
          ? "bg-accent/15 text-accent border border-accent/30 shadow-sm"
          : "text-muted hover:text-text border border-transparent hover:bg-bg/40"
      }`}
    >
      {children}
    </button>
  );
}

function StatCard({ label, value, accent }: { label: string; value: number; accent?: string }) {
  return (
    <div className="bg-panel border border-border rounded-xl p-4 text-center">
      <p className="text-xs text-muted uppercase tracking-wider">{label}</p>
      <p className={`text-2xl font-bold mt-1 ${accent ?? "text-text"}`}>{value}</p>
    </div>
  );
}
