import type { ScanDocument } from "../types";
import RiskBadge from "./RiskBadge";

interface Props {
  doc: ScanDocument;
}

export default function ReportTechnical({ doc }: Props) {
  return (
    <div className="space-y-8">
      {doc.findings?.length ? (
        <section>
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-3">
            Findings ({doc.findings.length})
          </h3>
          <div className="space-y-3">
            {doc.findings.map((f) => (
              <div
                key={f.id}
                className="bg-panel border border-border rounded-xl p-4 hover:border-accent/30 transition-colors"
              >
                <div className="flex items-start justify-between gap-3 mb-2">
                  <div className="flex-1 min-w-0">
                    <h4 className="font-medium text-text text-sm">{f.title}</h4>
                    <p className="text-xs text-muted mt-0.5">
                      {f.module} {f.cwe ? `· ${f.cwe}` : ""} {f.confidence ? `· ${f.confidence}` : ""}
                    </p>
                  </div>
                  <RiskBadge level={f.severity} />
                </div>
                <p className="text-sm text-muted leading-relaxed">{f.description}</p>
                {f.evidence && (
                  <pre className="mt-2 text-xs bg-bg border border-border rounded-lg p-3 overflow-x-auto text-muted">
                    {f.evidence}
                  </pre>
                )}
                {f.recommendation && (
                  <p className="mt-2 text-xs text-accent">{f.recommendation}</p>
                )}
              </div>
            ))}
          </div>
        </section>
      ) : (
        <p className="text-muted text-sm text-center py-8">Nenhum finding encontrado</p>
      )}

      {doc.header_checks?.length ? (
        <section>
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-3">
            Headers de Segurança
          </h3>
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
                <span className="text-sm font-mono">{h.name}</span>
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
        </section>
      ) : null}

      {doc.bundle?.libraries?.length ? (
        <section>
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-3">
            Bibliotecas Detectadas
          </h3>
          <div className="flex flex-wrap gap-2">
            {doc.bundle.libraries.map((lib, i) => (
              <span
                key={`${lib.name}-${i}`}
                className="px-3 py-1 rounded-lg bg-panel border border-border text-sm"
              >
                {lib.name}
                {lib.version && <span className="text-muted ml-1">{lib.version}</span>}
              </span>
            ))}
          </div>
        </section>
      ) : null}

      {doc.bundle?.secrets?.length ? (
        <section>
          <h3 className="text-sm font-semibold text-danger uppercase tracking-wider mb-3">
            Secrets Detectados ({doc.bundle.secrets.length})
          </h3>
          <div className="space-y-2">
            {doc.bundle.secrets.map((s, i) => (
              <div
                key={i}
                className="flex items-center gap-3 px-4 py-2 rounded-lg bg-red-500/5 border border-red-500/20 text-sm"
              >
                <span className="text-danger font-mono text-xs">{s.pattern}</span>
                <span className="text-muted text-xs">
                  {s.file}:{s.line}
                </span>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {doc.endpoints?.length ? (
        <section>
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-3">
            Endpoints Descobertos ({doc.endpoints.length})
          </h3>
          <div className="overflow-x-auto">
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
        </section>
      ) : null}

      {doc.auth && (
        <section>
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-3">
            Autenticação
          </h3>
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
            <div className="bg-panel border border-border rounded-xl p-3">
              <p className="text-xs text-muted uppercase mb-1">JWT</p>
              <p className="text-sm">{doc.auth.jwt_detected ? "Detectado" : "Não detectado"}</p>
            </div>
            <div className="bg-panel border border-border rounded-xl p-3">
              <p className="text-xs text-muted uppercase mb-1">CSRF</p>
              <p className="text-sm">{doc.auth.csrf_detected ? "Detectado" : "Não detectado"}</p>
            </div>
          </div>
        </section>
      )}

      {doc.ai?.prioritization?.length ? (
        <section>
          <h3 className="text-sm font-semibold text-muted uppercase tracking-wider mb-3">
            Priorização
          </h3>
          <ol className="space-y-2">
            {doc.ai.prioritization.map((p) => (
              <li key={p.rank} className="flex gap-3 text-sm">
                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-accent/10 text-accent flex items-center justify-center text-xs font-bold">
                  {p.rank}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-medium text-text">{p.title}</span>
                    <RiskBadge level={p.severity} />
                    <span className="text-xs text-muted">score {p.score.toFixed(1)}</span>
                  </div>
                  <p className="text-muted text-xs leading-relaxed">{p.rationale}</p>
                </div>
              </li>
            ))}
          </ol>
        </section>
      ) : null}
    </div>
  );
}

function InfoCard({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="bg-panel border border-border rounded-xl p-3">
      <p className="text-xs text-muted uppercase mb-1">{title}</p>
      <ul className="text-sm space-y-0.5">
        {items.map((item, i) => (
          <li key={`${item}-${i}`} className="font-mono text-xs">
            {item}
          </li>
        ))}
      </ul>
    </div>
  );
}
