# VibeSec

CLI de segurança e recon para aplicações web. Executa fingerprint, análise de headers, bundle JS, descoberta de endpoints, auth/authorization, plugins externos, Nuclei, import Burp, correlação de findings, análise AI e geração de relatórios.

## Requisitos

- Go 1.24+
- Node.js 20+ (apenas para build do dashboard web)
- Ferramentas opcionais no `PATH`: `nmap`, `httpx`, `nuclei`, `katana`, `subfinder`, `naabu`, `dnsx` (se ausentes, o scan continua com aviso)

## Instalação e build

```bash
git clone <repo-url>
cd vibesec
make install   # go mod download + npm install no frontend
make build     # build do frontend + binário vibesec
```

Ou manualmente:

```bash
go build -o vibesec .
```

## Desenvolvimento local

Sobe backend (porta `8080`) e frontend Vite (porta `5173`) com proxy da API:

```bash
make dev        # inicia backend + frontend
make dev-stop   # encerra processos de desenvolvimento
```

- Dashboard dev: [http://localhost:5173](http://localhost:5173)
- API: [http://localhost:8080/api/v1](http://localhost:8080/api/v1)

Comandos úteis:

| Comando | Descrição |
|---------|-----------|
| `make dev-frontend` | Apenas Vite |
| `make dev-backend` | Apenas `go run . serve` |
| `make test` | Testes Go |
| `make lint` | Oxlint no frontend |

## Configuração

Copie o arquivo de exemplo:

```bash
cp configs/vibesec.yaml ./vibesec.yaml
# ou
mkdir -p ~/.config/vibesec
cp configs/vibesec.yaml ~/.config/vibesec/vibesec.yaml
```

O VibeSec procura config nesta ordem:

1. Flag `--config /caminho/vibesec.yaml`
2. `./vibesec.yaml`
3. `~/.config/vibesec/vibesec.yaml`
4. Variável de ambiente `VIBESEC_CONFIG`

Principais seções do `vibesec.yaml`:

| Seção | Descrição |
|-------|-----------|
| `modules` | Liga/desliga cada módulo do scan |
| `report.format` | Saídas: `markdown`, `json`, `html` |
| `plugins` / `nuclei` / `burp` | Integrações externas |
| `enterprise` | Banco SQLite, API REST e persistência |

## Comandos

### `scan` — scan de segurança

Executa todos os módulos habilitados contra o alvo.

```bash
./vibesec scan https://example.com
```

**Flags úteis:**

| Flag | Descrição |
|------|-----------|
| `--config <arquivo>` | Caminho do `vibesec.yaml` |
| `--burp-file <xml>` | Importa issues exportadas do Burp Suite |
| `--save` | Salva o resultado no banco enterprise (`vibesec.db`) |
| `--json` | Imprime resumo JSON no stdout (para pipelines) |
| `--ci` | Retorna exit code `1` se houver findings `high` ou `critical` |

**Exemplos:**

```bash
# Scan completo com config explícita
./vibesec scan --config ./vibesec.yaml https://example.com

# Importar findings do Burp
./vibesec scan https://example.com --burp-file examples/burp-issues.xml

# Persistir no histórico
./vibesec scan https://example.com --save

# CI/CD: JSON + gate de qualidade
./vibesec scan https://example.com --json --ci
echo $?   # 0 = ok, 1 = findings high/critical
```

**Módulos executados (quando todos habilitados):**

`Fingerprint` → `Headers` → `CSP` → `Bundle` → `Endpoints` → `Auth` → `Authorization` → `Plugins` → `Nuclei` → `Burp` → `Correlation` → `AI Analyzer` → `Report`

Após todos os módulos, o pipeline aplica **scoring de confiança** e **suprime findings com `confidence=low`** antes de gerar o relatório (ver seção abaixo).

### `recon` — workflow de reconhecimento

Igual ao `scan`, mas inclui coleta de assets passivos antes do relatório.

```bash
./vibesec recon https://example.com
```

### `report` — último relatório gerado

Mostra os caminhos do último scan (Markdown, JSON e HTML).

```bash
./vibesec report
```

Saída típica:

```
reports/example.com-20260701-153223.md
reports/example.com-20260701-153223.json
reports/example.com-20260701-153223.html
```

O ponteiro `reports/latest.json` sempre aponta para o scan mais recente.

### `doctor` — verificar ambiente

Checa runtime Go, binários externos e conexão com o banco enterprise.

```bash
./vibesec doctor
```

### `version` — versão

```bash
./vibesec version
```

### `update` — auto-update

Placeholder para atualização futura.

```bash
./vibesec update
```

---

## Redução de falsos positivos

O VibeSec atribui `confidence` (`high`, `medium`, `low`) a cada finding e **remove do relatório** os classificados como `low`. Isso reduz ruído de heurísticas passivas sem perder sinais corroborados.

### Mecanismos principais

| Mecanismo | Onde | Efeito |
|-----------|------|--------|
| Validação de secrets | `internal/bundle/secrets.go` | Rejeita placeholders (`changeme`, `your-api-key`, baixa entropia) |
| Detecção de SPA | `internal/endpoint/spa.go` | Ignora admin/swagger quando ≥3 rotas retornam o mesmo shell HTML |
| Path matching estrito | `internal/correlation/correlate.go` | `/admin` não correlaciona com `/api/admin-panel` |
| Headers contextual | `internal/headers/analyzer.go` | HSTS em HTTP → informativo; rate-limit ausente não vira finding |
| Supressão Nuclei/Burp | `internal/finding/nuclei.go`, `burp.go` | Standalone suprimido; sobrevivem via Correlation ou Nuclei `critical` |
| Filtro de confiança | `internal/finding/filter.go` | Scoring pós-módulos + `FilterLowConfidence` |

### Regras de confiança (resumo)

| Condição | Confidence | Resultado |
|----------|------------|-----------|
| Correlação multi-fonte | `high` | Mantido |
| Secret validado no bundle | `high` | Mantido |
| Nuclei/Burp sem confirmação | `low` | Suprimido |
| Admin endpoint em SPA detectado | `low` | Suprimido |
| HSTS ausente em target HTTP | `low` | Suprimido |
| Headers em HTTPS, auth, endpoints isolados | `medium` | Mantido |
| Nuclei `critical` standalone | `medium` | Mantido |

Findings de **Correlation** (`nuclei-confirmed-*`, `burp-corroborated-*`, `admin-exposure-*`) recebem `confidence=high` e têm prioridade na análise AI.

### Risk score

O score numérico considera apenas findings que passaram pelo filtro:

```
score = critical×15 + high×10 + medium×5 + low×2
```

| Score | Nível |
|-------|-------|
| ≥ 30 | `critical` |
| ≥ 15 | `high` |
| ≥ 5 | `medium` |
| < 5 | `low` |

---

## Modo Enterprise

### `serve` — API REST + dashboard web

Sobe o servidor HTTP com fila de scans assíncronos e agendamento.

```bash
./vibesec serve
# ou em dev com hot-reload do frontend:
make dev
```

- Dashboard produção: [http://localhost:8080](http://localhost:8080)
- Dashboard dev: [http://localhost:5173](http://localhost:5173)
- API base: `http://localhost:8080/api/v1`

Configuração em `vibesec.yaml`:

```yaml
enterprise:
  database: vibesec.db      # ou VIBESEC_DATABASE=/caminho/db.sqlite
  api_listen: ":8080"
  persist_scans: true
```

**Endpoints** (sem autenticação):

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/api/v1/health` | Health check |
| `GET` | `/api/v1/scans` | Listar scans |
| `POST` | `/api/v1/scans` | Enfileirar scan `{"target":"https://..."}` → 202 Accepted |
| `GET` | `/api/v1/scans/{id}` | Detalhe do scan + `document_json` |
| `GET` | `/api/v1/scans/{id}/events` | SSE — atualizações de status em tempo real |
| `GET` | `/api/v1/schedules` | Listar agendamentos |
| `POST` | `/api/v1/schedules` | Criar agendamento `{"target":"...","interval_minutes":1440}` |

**SSE (`/events`):** stream `text/event-stream` com eventos `scan` contendo o objeto Scan atualizado. O frontend usa EventSource com fallback de polling a cada 2s.

**Exemplo com curl:**

```bash
# Enfileirar scan
curl -s -X POST http://localhost:8080/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com"}'

# Acompanhar via SSE
curl -N http://localhost:8080/api/v1/scans/{id}/events

# Listar scans
curl -s http://localhost:8080/api/v1/scans
```

### Dashboard web

O frontend React oferece:

- **Home** — iniciar scan por URL
- **Relatório** — duas abas:
  - **Empresarial** — resumo de risco, findings agrupados, recomendações em linguagem acessível
  - **Técnico** — findings completos, headers, bundle, endpoints, auth, priorização AI
- **Exportar JSON** — na aba Técnico, baixa o `document_json` completo (`vibesec-technical-{host}-{data}.json`)

Detalhes do frontend em [`frontend/README.md`](frontend/README.md).

### `scans list` — histórico no banco

```bash
./vibesec scans list
```

### `user create` — criar usuário / API key

```bash
./vibesec user create pipeline-bot
```

---

## Relatórios

Gerados automaticamente ao final do `scan` ou `recon` (módulo `report` habilitado):

| Formato | Arquivo | Uso |
|---------|---------|-----|
| Markdown | `reports/<host>-<timestamp>.md` | Leitura humana, PRs |
| JSON | `reports/<host>-<timestamp>.json` | Integração, automação |
| HTML | `reports/<host>-<timestamp>.html` | Dashboard visual no navegador |
| Executive MD/HTML | `reports/<host>-<timestamp>-executive.{md,html}` | Resumo para stakeholders |

Abrir o HTML localmente:

```bash
xdg-open reports/example.com-*.html    # Linux
open reports/example.com-*.html        # macOS
```

### Estrutura do `document_json`

Objeto principal consumido pela API e pelo dashboard:

| Campo | Descrição |
|-------|-----------|
| `summary` | Target, timestamp, módulos executados, contagem de findings |
| `findings` | Lista unificada (já filtrada por confiança) com `severity`, `confidence`, CWE, CVSS |
| `risk` | `level`, `score`, `counts` por severidade |
| `header_checks` | Resultado da análise de headers |
| `bundle` | Libraries, routes, secrets detectados |
| `endpoints` | Probes HTTP (método, path, status) |
| `auth` | Mecanismos de autenticação detectados |
| `nuclei` / `burp` | Dados brutos dos scanners externos |
| `ai` | Priorização e resumo executivo |
| `recommendations` | Recomendações deduplicadas |

---

## CI/CD

Exemplo de workflow GitHub Actions em `examples/github-actions-scan.yaml`:

```bash
./vibesec scan https://staging.example.com --json --ci
```

- `--json` emite resumo no stdout (`target`, `risk_level`, `finding_count`, paths dos relatórios)
- `--ci` falha o pipeline se existirem findings `high` ou `critical` (após filtro de confiança)

---

## Fluxo rápido (primeiro uso)

```bash
# 1. Instalar dependências e build
make install
make build

# 2. Config
cp configs/vibesec.yaml ./vibesec.yaml

# 3. Verificar ambiente
./vibesec doctor

# 4. Scan
./vibesec scan https://example.com

# 5. Ver relatórios
./vibesec report
xdg-open $(jq -r .html reports/latest.json)

# 6. (Opcional) Modo enterprise com dashboard
make dev
# Abra http://localhost:5173
```

## Licença

Consulte o repositório para informações de licença.
