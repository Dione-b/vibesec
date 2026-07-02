import type { ScanDocument } from "../types";
import RiskBadge from "./RiskBadge";
import RiskBanner from "./report/RiskBanner";
import ReportCard from "./report/ReportCard";
import SectionTitle from "./report/SectionTitle";
import SeverityBarChart from "./report/SeverityBarChart";
import ModuleTimeline from "./report/ModuleTimeline";
import TechnicalFindingCard from "./report/TechnicalFindingCard";
import TechStatCard from "./report/TechStatCard";
import TagList from "./report/TagList";

interface Props {
  doc: ScanDocument;
}

export default function ReportTechnical({ doc }: Props) {
  const counts = doc.risk?.counts ?? {};
  const highPlus = (counts.critical ?? 0) + (counts.high ?? 0);
  const findingCount = doc.summary?.finding_count ?? doc.findings?.length ?? 0;
  const modulesRun = doc.summary?.modules_run ?? 0;
  const endpointCount = doc.endpoints?.length ?? 0;

  return (
    <div className="space-y-8">
      <RiskBanner level={doc.risk.level} score={doc.risk.score} variant="compact" />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <TechStatCard label="Findings" value={findingCount} />
        <TechStatCard label="Modules" value={modulesRun} />
        <TechStatCard label="High+" value={highPlus} accent="text-orange-400" />
        <TechStatCard label="Endpoints" value={endpointCount} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <SeverityBarChart counts={counts} />
        <ModuleTimeline modulesRun={modulesRun} generatedAt={doc.summary?.generated_at} />
      </div>

      {(doc.stack?.length || doc.infrastructure?.length) ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {doc.stack?.length ? (
            <ReportCard>
              <SectionTitle className="!text-base !mb-3 !pb-2">Stack</SectionTitle>
              <TagList items={doc.stack} />
            </ReportCard>
          ) : null}
          {doc.infrastructure?.length ? (
            <ReportCard>
              <SectionTitle className="!text-base !mb-3 !pb-2">Infrastructure</SectionTitle>
              <TagList items={doc.infrastructure} />
            </ReportCard>
          ) : null}
        </div>
      ) : null}

      {doc.findings?.length ? (
        <section>
          <SectionTitle>Findings ({doc.findings.length})</SectionTitle>
          <div className="space-y-3">
            {doc.findings.map((f) => (
              <TechnicalFindingCard key={f.id} finding={f} />
            ))}
          </div>
        </section>
      ) : (
        <ReportCard className="text-center text-muted py-8">Nenhum finding encontrado</ReportCard>
      )}

      {doc.header_checks?.length ? (
        <section>
          <SectionTitle>Headers de Segurança</SectionTitle>
          <ReportCard>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {doc.header_checks.map((h) => (
                <div
                  key={h.name}
                  className={`flex items-center justify-between px-4 py-2.5 rounded-lg border ${
                    h.present && h.ok
                      ? "bg-green-500/5 border-green-500/20"
                      : h.present
                      ? "bg-yellow-500/5 border-yellow-500/20"
                      : "bg-red-500/5 border-red-500/20"
                  }`}
                >
                  <span className="text-sm font-mono min-w-0 truncate">{h.name}</span>
                  <span
                    className={`text-xs ${
                      h.present && h.ok
                        ? "text-green-400"
                        : h.present
                        ? "text-yellow-400"
                        : "text-red-400"
                    }`}
                  >
                    {h.present && h.ok ? "OK" : h.present ? "Presente" : "Ausente"}
                  </span>
                </div>
              ))}
            </div>
          </ReportCard>
        </section>
      ) : null}

      {doc.bundle?.libraries?.length ? (
        <section>
          <SectionTitle>Bibliotecas Detectadas</SectionTitle>
          <ReportCard>
            <div className="flex flex-wrap gap-2">
              {doc.bundle.libraries.map((lib, i) => (
                <span
                  key={`${lib.name}-${i}`}
                  className="px-3 py-1 rounded-lg bg-bg border border-border text-sm"
                >
                  {lib.name}
                  {lib.version && <span className="text-muted ml-1">{lib.version}</span>}
                </span>
              ))}
            </div>
          </ReportCard>
        </section>
      ) : null}

      {doc.bundle?.secrets?.length ? (
        <section>
          <SectionTitle>
            <span className="text-danger">Secrets Detectados ({doc.bundle.secrets.length})</span>
          </SectionTitle>
          <ReportCard>
            <div className="space-y-2">
              {doc.bundle.secrets.map((s, i) => (
                <div
                  key={i}
                  className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-3 px-4 py-2 rounded-lg bg-red-500/5 border border-red-500/20 text-sm"
                >
                  <span className="text-danger font-mono text-xs">{s.pattern}</span>
                  <span className="text-muted text-xs break-all">
                    {s.file}:{s.line}
                  </span>
                </div>
              ))}
            </div>
          </ReportCard>
        </section>
      ) : null}

      {doc.endpoints?.length ? (
        <section>
          <SectionTitle>Endpoints Descobertos ({doc.endpoints.length})</SectionTitle>
          <ReportCard className="!p-0 overflow-hidden">
            <div className="sm:hidden space-y-0 divide-y divide-border">
              {doc.endpoints.map((ep, i) => (
                <div key={i} className="p-4 text-sm space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-accent text-xs">{ep.method}</span>
                    <span className="font-mono text-xs text-muted">{ep.status}</span>
                  </div>
                  <p className="font-mono text-xs break-all">{ep.path}</p>
                </div>
              ))}
            </div>
            <div className="hidden sm:block overflow-x-auto p-4">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-muted text-xs uppercase border-b border-border">
                    <th className="text-left py-2 px-3">Método</th>
                    <th className="text-left py-2 px-3">Path</th>
                    <th className="text-right py-2 px-3">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {doc.endpoints.map((ep, i) => (
                    <tr key={i} className="border-b border-border/50">
                      <td className="py-2 px-3 font-mono text-accent text-xs">{ep.method}</td>
                      <td className="py-2 px-3 font-mono">{ep.path}</td>
                      <td className="py-2 px-3 text-right font-mono text-xs">{ep.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </ReportCard>
        </section>
      ) : null}

      {doc.auth ? (
        <section>
          <SectionTitle>Autenticação</SectionTitle>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {doc.auth.login_paths?.length ? (
              <InfoCard title="Login" items={doc.auth.login_paths} />
            ) : null}
            {doc.auth.logout_paths?.length ? (
              <InfoCard title="Logout" items={doc.auth.logout_paths} />
            ) : null}
            {doc.auth.session_cookies?.length ? (
              <InfoCard title="Cookies" items={doc.auth.session_cookies} />
            ) : null}
            <ReportCard className="!p-3">
              <p className="text-xs text-muted uppercase mb-1">JWT</p>
              <p className="text-sm">{doc.auth.jwt_detected ? "Detectado" : "Não detectado"}</p>
            </ReportCard>
            <ReportCard className="!p-3">
              <p className="text-xs text-muted uppercase mb-1">CSRF</p>
              <p className="text-sm">{doc.auth.csrf_detected ? "Detectado" : "Não detectado"}</p>
            </ReportCard>
          </div>
        </section>
      ) : null}

      {doc.ai?.prioritization?.length ? (
        <section>
          <SectionTitle>Priorização</SectionTitle>
          <ReportCard>
            <div className="sm:hidden space-y-4">
              {doc.ai.prioritization.map((p) => (
                <div key={p.rank} className="flex gap-3 text-sm border-b border-border/50 pb-4 last:border-0 last:pb-0">
                  <span className="w-7 h-7 rounded-full bg-accent/10 text-accent flex items-center justify-center text-xs font-bold shrink-0">
                    {p.rank}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="font-medium text-text">{p.title}</span>
                      <RiskBadge level={p.severity} />
                    </div>
                    <p className="text-xs text-muted">score {p.score.toFixed(1)}</p>
                    <p className="text-muted text-xs mt-1 leading-relaxed">{p.rationale}</p>
                  </div>
                </div>
              ))}
            </div>
            <div className="hidden sm:block overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-muted text-xs uppercase border-b border-border">
                    <th className="text-left py-2 px-2">#</th>
                    <th className="text-left py-2 px-2">Issue</th>
                    <th className="text-left py-2 px-2">Severity</th>
                    <th className="text-left py-2 px-2">Score</th>
                    <th className="text-left py-2 px-2">Rationale</th>
                  </tr>
                </thead>
                <tbody>
                  {doc.ai.prioritization.map((p) => (
                    <tr key={p.rank} className="border-b border-border/50">
                      <td className="py-2 px-2">{p.rank}</td>
                      <td className="py-2 px-2">{p.title}</td>
                      <td className="py-2 px-2">
                        <RiskBadge level={p.severity} />
                      </td>
                      <td className="py-2 px-2">{p.score.toFixed(1)}</td>
                      <td className="py-2 px-2 text-muted text-xs">{p.rationale}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </ReportCard>
        </section>
      ) : null}
    </div>
  );
}

function InfoCard({ title, items }: { title: string; items: string[] }) {
  return (
    <ReportCard className="!p-3">
      <p className="text-xs text-muted uppercase mb-1">{title}</p>
      <ul className="text-sm space-y-0.5">
        {items.map((item, i) => (
          <li key={`${item}-${i}`} className="font-mono text-xs break-all">
            {item}
          </li>
        ))}
      </ul>
    </ReportCard>
  );
}
