# VibeSec Dashboard

Frontend React do VibeSec — interface web para iniciar scans, acompanhar progresso e visualizar relatórios empresariais e técnicos.

## Stack

- React 19 + TypeScript
- Vite 8
- Tailwind CSS 4
- React Router 7
- TanStack Query (cache e refetch)

## Desenvolvimento

Na raiz do repositório:

```bash
make dev          # backend :8080 + frontend :5173
make dev-frontend # apenas este frontend
```

Ou manualmente:

```bash
npm install
npm run dev
```

O Vite faz proxy de `/api` para `http://localhost:8080`. Requisições SSE em `/api/v1/scans/{id}/events` têm buffering desabilitado no proxy.

## Scripts

| Comando | Descrição |
|---------|-----------|
| `npm run dev` | Servidor de desenvolvimento (porta 5173) |
| `npm run build` | Build de produção em `dist/` |
| `npm run lint` | Oxlint |
| `npm run preview` | Preview do build |

O build de produção é embutido no binário Go via `make build` (`frontend/dist` servido pelo `serve`).

## Estrutura

```
src/
├── api/client.ts       # Cliente HTTP da API
├── hooks/useScan.ts    # Polling + SSE para status do scan
├── pages/
│   ├── Home.tsx        # Formulário de novo scan
│   └── Report.tsx      # Relatório com abas Empresarial / Técnico
├── components/
│   ├── ReportExecutive.tsx   # Visão empresarial
│   ├── ReportTechnical.tsx   # Visão técnica detalhada
│   └── report/               # Cards, gráficos, timeline
├── lib/
│   ├── export-report.ts      # Download do relatório técnico em JSON
│   ├── report-styles.ts      # Classes e helpers visuais
│   └── severity.ts             # Tradução e ordenação de severidade
└── types/index.ts      # Scan, ScanDocument, Finding, etc.
```

## Páginas

### Home (`/`)

Envia `POST /api/v1/scans` com `{ "target": "https://..." }` e redireciona para `/report/{id}`.

### Relatório (`/report/:id`)

Consome `GET /api/v1/scans/{id}` e acompanha o status via:

1. **SSE** — `EventSource` em `/api/v1/scans/{id}/events`
2. **Fallback** — polling a cada 2s se SSE falhar

Enquanto `status` é `pending` ou `running`, exibe skeleton. Ao concluir, parseia `document_json` em `ScanDocument`.

#### Aba Empresarial

- Banner de risco e score
- Grid de severidades (apenas níveis com contagem > 0)
- Findings agrupados por título + textos layperson
- Recomendações deduplicadas
- Timeline dos módulos executados

#### Aba Técnico

- Estatísticas (findings, módulos, high+, endpoints)
- Gráfico de severidade e timeline
- Stack e infraestrutura
- Lista completa de findings com `confidence`, CWE, evidence
- Headers, bibliotecas, secrets, endpoints, auth, priorização AI

#### Exportar JSON

Na aba **Técnico**, o botão **Exportar JSON** baixa o `ScanDocument` completo:

```
vibesec-technical-{host}-{YYYY-MM-DD}.json
```

Útil para integração com SIEM, tickets ou análise offline. O arquivo contém os mesmos dados exibidos na aba técnica (findings já filtrados por confiança no backend).

## Tipos principais

```typescript
interface Scan {
  id: string;
  target: string;
  status: "pending" | "running" | "completed" | "failed";
  risk_level: string;
  finding_count: number;
  document_json?: string;  // ScanDocument serializado
}

interface Finding {
  id: string;
  module: string;
  severity: string;
  confidence: string;      // high | medium | low (low não aparece no relatório)
  title: string;
  cwe?: string;
  cvss?: string;
  layperson_impact?: string;
  layperson_recommendation?: string;
}
```

## Build de produção

```bash
npm run build
```

Artefatos em `frontend/dist/`. O comando `make build` na raiz compila o frontend e depois o binário Go que serve os arquivos estáticos em `serve`.
