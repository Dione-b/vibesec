# VibeSec

CLI de segurança e recon para aplicações web. Executa fingerprint, análise de headers, bundle JS, descoberta de endpoints, auth/authorization, plugins externos, Nuclei, import Burp, correlação de findings, análise AI e geração de relatórios.

## Requisitos

- Go 1.24+
- Ferramentas opcionais no `PATH`: `nmap`, `httpx`, `nuclei`, `katana`, `subfinder`, `naabu`, `dnsx` (se ausentes, o scan continua com aviso)

## Instalação e build

```bash
git clone <repo-url>
cd vibesec
go build -o vibesec .
```

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

## Modo Enterprise

### `serve` — API REST + dashboard web

Sobe o servidor HTTP com fila de scans assíncronos e agendamento.

```bash
./vibesec serve
```

- Dashboard: [http://localhost:8080](http://localhost:8080)
- API base: `http://localhost:8080/api/v1`
- Na primeira execução, o terminal exibe a **API key do usuário `admin`**

Configuração em `vibesec.yaml`:

```yaml
enterprise:
  database: vibesec.db      # ou VIBESEC_DATABASE=/caminho/db.sqlite
  api_listen: ":8080"
  persist_scans: true
```

**Autenticação da API:** header `X-API-Key: vs_...` ou `Authorization: Bearer vs_...`

**Endpoints:**

| Método | Rota | Descrição |
|--------|------|-----------|
| `GET` | `/api/v1/health` | Health check (sem auth) |
| `GET` | `/api/v1/scans` | Listar scans |
| `POST` | `/api/v1/scans` | Enfileirar scan `{"target":"https://..."}` |
| `GET` | `/api/v1/scans/{id}` | Detalhe de um scan |
| `GET` | `/api/v1/schedules` | Listar agendamentos |
| `POST` | `/api/v1/schedules` | Criar agendamento `{"target":"...","interval_minutes":1440}` |

**Exemplo com curl:**

```bash
# Enfileirar scan
curl -s -X POST http://localhost:8080/api/v1/scans \
  -H "X-API-Key: vs_SEU_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://example.com"}'

# Listar scans
curl -s http://localhost:8080/api/v1/scans \
  -H "X-API-Key: vs_SEU_TOKEN"
```

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

Abrir o HTML localmente:

```bash
xdg-open reports/example.com-*.html    # Linux
open reports/example.com-*.html        # macOS
```

---

## CI/CD

Exemplo de workflow GitHub Actions em `examples/github-actions-scan.yaml`:

```bash
./vibesec scan https://staging.example.com --json --ci
```

- `--json` emite resumo no stdout (`target`, `risk_level`, `finding_count`, paths dos relatórios)
- `--ci` falha o pipeline se existirem findings `high` ou `critical`

---

## Fluxo rápido (primeiro uso)

```bash
# 1. Build
go build -o vibesec .

# 2. Config
cp configs/vibesec.yaml ./vibesec.yaml

# 3. Verificar ambiente
./vibesec doctor

# 4. Scan
./vibesec scan https://example.com

# 5. Ver relatórios
./vibesec report
xdg-open $(jq -r .html reports/latest.json)

# 6. (Opcional) Modo enterprise
./vibesec serve
```

## Licença

Consulte o repositório para informações de licença.
