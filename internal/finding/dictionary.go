package finding

import "strings"

// LaypersonExplanation returns a simplified, non-technical explanation of a
// finding written for stakeholders who have no security background. The text
// is in Brazilian Portuguese to match the executive report language.
//
// The lookup uses the finding ID first (exact match), then falls back to
// prefix matching, title heuristics, and finally severity-based fallback.
func LaypersonExplanation(f Finding) string {
	if msg, ok := explanationByID[f.ID]; ok {
		return msg
	}
	lowerID := strings.ToLower(f.ID)
	for prefix, msg := range prefixExplanations {
		if strings.HasPrefix(lowerID, prefix) {
			return msg
		}
	}
	if msg, ok := explanationByTitle[strings.ToLower(f.Title)]; ok {
		return msg
	}
	return fallbackBySeverity(f.Severity)
}

var explanationByID = map[string]string{
	// ── Headers (module: headers) ────────────────────────────────────────
	"headers/hsts": "Seu site nao informa ao navegador que so deve ser acessado " +
		"por HTTPS. Isso permite que um atacante redirecione visitantes para " +
		"uma versao falsa do site e intercepte senhas e dados sensiveis.",

	"headers/csp": "Seu site nao possui uma politica de seguranca que controla " +
		"quais recursos (scripts, imagens, estilos) podem ser carregados. Sem " +
		"isso, um atacante pode injetar codigo malicioso que roda no navegador " +
		"dos seus usuarios.",

	"headers/xfo": "Seu site nao protege contra ser exibido dentro de um iframe " +
		"em outro site. Um atacante pode enquadrar sua pagina em um site falso " +
		"para roubar dados dos usuarios (cliquejacking).",

	"headers/referrer-policy": "Seu site nao controla quais informacoes sao " +
		"enviadas para outros sites quando um usuario clica em um link. Isso " +
		"pode vazar enderecos de paginas internas, parametros secretos ou " +
		"estrutura do sistema para sites de terceiros.",

	"headers/permissions-policy": "Seu site nao restringe quais recursos do " +
		"navegador (camera, microfone, geolocalizacao) podem ser acessados. " +
		"Isso permite que scripts maliciosos usem esses recursos sem o " +
		"conhecimento do usuario.",

	"headers/cache-control": "Seu site nao controla como os navegadores e " +
		"proxys armazenam as paginas. Isso pode fazer com que informacoes " +
		"sensiveis fiquem salvas em cache e sejam acessadas por outra pessoa " +
		"no mesmo computador ou rede.",

	"headers/rate-limit": "Seu site nao possui limitacao de requisicoes. Um " +
		"atacante pode fazer milhares de pedidos por segundo para sobrecarregar " +
		"o servidor ou tentar adivinhar senhas em escala.",

	"headers/cors": "Seu site permite que qualquer sitio da web acesse seus " +
		"dados atraves de requisicoes cross-origin. Um atacante pode criar um " +
		"site malicioso que rouba informacoes dos seus usuarios logados.",

	"headers/cookies-secure": "Seus cookies nao possuem a flag Secure, o que " +
		"significa que podem ser enviados em conexoes normais (HTTP). Um " +
		"atacante na mesma rede pode interceptar esses cookies e se passar " +
		"pelo usuario.",

	"headers/cookies-httponly": "Seus cookies nao possuem a flag HttpOnly, o que " +
		"permite que scripts maliciosos (injetados via XSS) acessem diretamente " +
		"os cookies de sessao e roube a sessao do usuario.",

	"headers/cookies-samesite": "Seus cookies nao possuem uma protecao SameSite " +
		"adequada. Isso facilita ataques CSRF, onde um site falso pode fazer " +
		"acoes em nome do usuario logado sem o seu conhecimento.",

	// ── CSP deep analysis (module: csp) ──────────────────────────────────
	"csp/missing": "Seu site nao possui uma politica de seguranca de conteudo. " +
		"Isso permite que scripts maliciosos sejam executados no navegador " +
		"dos seus usuarios, facilitando roubo de dados e sequestro de sessao.",

	"csp/unsafe-inline": "A politica de seguranca do seu site permite a execucao " +
		"de scripts embutidos diretamente nas paginas. Isso reduz " +
		"significativamente a protecao contra injecao de codigo malicioso.",

	"csp/unsafe-eval": "A politica de seguranca do seu site permite a execucao " +
		"de codigo dinamico (eval). Isso pode ser explorado por atacantes " +
		"para executar qualquer comando no navegador dos usuarios.",

	"csp/wildcard-default": "A politica de seguranca do seu site usa um coringa " +
		"(*) como padrao, permitindo recursos de qualquer origem. Isso anula " +
		"a protecao que a politica deveria fornecer.",

	// ── Fingerprint (module: fingerprint) ────────────────────────────────
	"fingerprint/stack": "Tecnologias utilizadas no site foram identificadas. " +
		"Embora isso nao seja uma vulnerabilidade, atacantes podem usar " +
		"essas informacoes para encontrar falhas conhecidas nas versoes " +
		"detectadas.",

	"fingerprint/weak-tls": "Seu servidor utiliza uma versao antiga e insegura " +
		"do protocolo de criptografia (TLS). Um atacante pode interceptar " +
		"as comunicacoes entre o site e os usuarios para roubar dados " +
		"sensiveis como senhas e cartao de credito.",

	// ── Endpoint (module: endpoint) ──────────────────────────────────────
	"endpoint/api-doc-openapi-json": "A documentacao da API (OpenAPI) esta " +
		"acessivel publicamente. Isso revela todos os endpoints, parametros " +
		"e estrutura do seu sistema para atacantes.",

	"endpoint/api-doc-swagger": "A documentacao da API (Swagger) esta " +
		"acessivel publicamente. Isso revela todos os endpoints, parametros " +
		"e estrutura do seu sistema para atacantes.",

	// ── Correlation (module: correlation) ────────────────────────────────
	"correlation/secret-near-auth": "Existem segredos expostos no codigo do " +
		"site e ao mesmo tempo uma pagina de login esta acessivel. Um atacante " +
		"pode usar os segredos encontrados para contornar a autenticacao " +
		"e assumir o controle da conta de qualquer usuario.",

	"correlation/weak-transport-login": "A pagina de login do seu site nao " +
		"possui protecoes de transportes adequadas (HTTPS forca, cookies " +
		"seguros). Isso permite que um atacante na mesma rede intercepte " +
		"as credenciais durante o login.",
}

// prefixExplanations maps finding ID prefixes to explanations. This handles
// dynamic findings where the ID contains a variable suffix (e.g., slug or number).
var prefixExplanations = map[string]string{
	// ── Bundle secrets ───────────────────────────────────────────────────
	"bundle/secret-": "Foi encontrado um possivel segredo (chave, token ou " +
		"senha) escondido no codigo JavaScript do seu site. Um atacante " +
		"pode copiar essa chave e usar para acessar sistemas internos, " +
		"banco de dados ou servicos de terceiros.",

	"bundle/admin-page-": "O codigo JavaScript do seu site referencia uma pagina " +
		"administrativa. Isso indica que existe um painel de administracao " +
		"que pode ser alvo de ataques se nao estiver adequadamente protegido.",

	// ── Endpoint exposed admin ───────────────────────────────────────────
	"endpoint/exposed-": "Uma pagina administrativa esta acessivel pela internet " +
		"e respondeu normalmente. Um atacante pode tentar acessar o painel " +
		"administrativo para comprometer o sistema.",

	"endpoint/api-doc-": "A documentacao da API (Swagger/OpenAPI) esta acessivel " +
		"publicamente. Isso revela todos os endpoints, parametros e " +
		"estrutura do seu sistema para atacantes.",

	// ── Authorization ────────────────────────────────────────────────────
	"authorization/admin-pages-": "Foram encontradas paginas administrativas que " +
		"podem estar acessiveis sem autenticacao adequada. Um atacante pode " +
		"acessar funcionalidades restritas e comprometer o sistema.",

	"authorization/idor-": "Foram encontrados endpoints que acessam recursos por " +
		"ID sem verificacao de autorizacao. Um atacante pode trocar o ID e " +
		"acessar dados de outros usuarios (IDOR).",

	"authorization/mass-assignment-": "O seu sistema aceita campos extras nas " +
		"requisicoes que sao salvos direto no banco de dados. Um atacante " +
		"pode enviar campos adicionais para alterar dados que nao deveria " +
		"ter acesso.",

	"authorization/role-bypass-": "A verificacao de permissoes esta sendo feita " +
		"no navegador. Um atacante pode ignorar essa verificacao e acessar " +
		"areas restritas do sistema.",

	"authorization/vertical-escalation-": "Um usuario comum pode acessar " +
		"funcionalidades de administrador. Isso permite que qualquer pessoa " +
		"assume o controle completo do sistema.",

	// ── Correlation ──────────────────────────────────────────────────────
	"correlation/admin-exposure-": "Uma rota administrativa que aparece no " +
		"codigo do frontend esta acessivel pela internet. Um atacante pode " +
		"tentar acessar o painel administrativo e comprometer todo o sistema.",

	"correlation/nuclei-confirmed-": "Um problema de seguranca foi confirmado " +
		"por mais de uma ferramenta de analise. Quando multiplos scanners " +
		"apontam o mesmo problema, a chance de ser uma vulnerabilidade " +
		"real e muito alta.",

	"correlation/burp-corroborated-": "Um problema detectado pelo Burp Suite " +
		"foi confirmado por outra ferramenta. A convergencia de resultados " +
		"indica que este e um problema real que precisa ser corrigido.",

	"correlation/insecure-session-": "Os cookies de sessao nas paginas sensiveis " +
		"(login, admin) nao possuem protecoes adequadas. Um atacante pode " +
		"roubar a sessao de um usuario e assumir sua identidade.",

	// ── Auth ─────────────────────────────────────────────────────────────
	"auth/cookies-": "Os cookies de sessao do seu site nao possuem todas as " +
		"protecoes necessarias (Secure, HttpOnly, SameSite). Isso facilita " +
		"o roubo de sessoes e ataques CSRF.",

	"auth/jwt-": "O token JWT esta sendo armazenado de forma insegura (por " +
		"exemplo, no localStorage). Um atacante que consiga injetar codigo " +
		"malicioso pode roubar o token e assumir a sessao do usuario.",

	"auth/csrf-": "Seu site nao possui protecao contra ataques CSRF. Um site " +
		"falso pode fazer requisicoes em nome do usuario logado, alterando " +
		"dados ou realizando acoes sem o seu conhecimento.",

	"auth/roles-": "A verificacao de permissoes esta sendo feita apenas no " +
		"lado do cliente (navegador). Um atacante pode ignorar essas " +
		"verificacoes e acessar funcionalidades restritas.",

	"auth/session-": "A sessao do usuario nao e renovada apos o login e pode " +
		"ser armazenada em cache. Isso permite que outra pessoa acesse " +
		"a sessao anterior do usuario.",

	"auth/refresh-": "O endpoint de renovacao de tokens nao esta adequadamente " +
		"protegido. Um atacante pode renovar tokens de usuarios sem " +
		"autorizacao.",

	// ── Plugins ──────────────────────────────────────────────────────────
	"plugins-nuclei-error": "A ferramenta Nuclei nao conseguiu executar a " +
		"analise. Pode ser necessario instalar ou configurar a ferramenta " +
		"corretamente.",
	"plugins-httpx-error": "A ferramenta httpx nao conseguiu executar a " +
		"analise. Verifique a conexao de rede e a URL alvo.",
	"plugins-nmap-error": "A ferramenta nmap nao conseguiu escanear as portas. " +
		"Pode ser necessario ajustar as configuracoes de rede.",
	"plugins-katana-error": "A ferramenta Katana nao conseguiu rastrear as " +
		"paginas do site. Verifique se a URL alvo esta acessivel.",
	"plugins-subfinder-error": "A ferramenta Subfinder nao conseguiu encontrar " +
		"subdominios. Verifique as configuracoes de DNS.",
	"plugins-naabu-error": "A ferramenta naabu nao conseguiu escanear portas. " +
		"Verifique a conexao de rede.",
	"plugins-dnsx-error": "A ferramenta dnsx nao conseguiu resolver os " +
		"dominios. Verifique as configuracoes de DNS.",
}

var explanationByTitle = map[string]string{
	// ── Headers (from header check titles) ───────────────────────────────
	"hsts": "Seu site nao informa ao navegador que so deve ser acessado por " +
		"HTTPS. Isso permite que um atacante redirecione visitantes para " +
		"uma versao falsa do site e intercepte senhas e dados sensiveis.",

	"csp": "Seu site nao possui uma politica de seguranca que controla quais " +
		"recursos podem ser carregados. Sem isso, um atacante pode injetar " +
		"codigo malicioso que roda no navegador dos seus usuarios.",

	"xfo": "Seu site nao protege contra ser exibido dentro de um iframe em " +
		"outro site. Um atacante pode enquadrar sua pagina em um site falso " +
		"para roubar dados dos usuarios (cliquejacking).",

	"referrer policy": "Seu site nao controla quais informacoes sao enviadas " +
		"para outros sites quando um usuario clica em um link. Isso pode " +
		"vazar enderecos de paginas internas, parametros secretos ou " +
		"estrutura do sistema para sites de terceiros.",

	"permissions policy": "Seu site nao restringe quais recursos do navegador " +
		"(camera, microfone, geolocalizacao) podem ser acessados. Isso " +
		"permite que scripts maliciosos usem esses recursos sem o " +
		"conhecimento do usuario.",

	"cache control": "Seu site nao controla como os navegadores e proxys " +
		"armazenam as paginas. Isso pode fazer com que informacoes sensiveis " +
		"fiquem salvas em cache e sejam acessadas por outra pessoa no mesmo " +
		"computador ou rede.",

	"rate limit": "Seu site nao possui limitacao de requisicoes. Um atacante " +
		"pode fazer milhares de pedidos por segundo para sobrecarregar o " +
		"servidor ou tentar adivinhar senhas em escala.",

	"cookies secure": "Seus cookies de sessao podem ser enviados em conexoes " +
		"inseguras. Um atacante na mesma rede pode interceptar esses dados " +
		"e se passar pelo usuario.",

	"cookies httponly": "Os cookies de sessao podem ser lidos por codigo " +
		"malicioso injetado no site. Isso facilita o roubo de sessoes de " +
		"usuarios logados.",

	"cookies samesite": "Os cookies de sessao nao possuem protecao adequada " +
		"contra sites falsos. Um atacante pode fazer acoes em nome do usuario " +
		"sem o conhecimento dele.",

	// ── CSP titles ───────────────────────────────────────────────────────
	"content-security-policy missing": "Seu site nao possui uma politica de " +
		"seguranca que controla quais recursos podem ser carregados. Sem " +
		"isso, um atacante pode injetar codigo malicioso que roda no " +
		"navegador dos seus usuarios.",

	"csp allows unsafe-inline": "A politica de seguranca do seu site permite a " +
		"execucao de scripts embutidos diretamente nas paginas. Isso reduz " +
		"significativamente a protecao contra injecao de codigo malicioso.",

	"csp allows unsafe-eval": "A politica de seguranca do seu site permite a " +
		"execucao de codigo dinamico (eval). Isso pode ser explorado por " +
		"atacantes para executar qualquer comando no navegador dos usuarios.",

	"csp wildcard in default-src": "A politica de seguranca do seu site usa um " +
		"coringa (*) como padrao, permitindo recursos de qualquer origem. " +
		"Isso anula a protecao que a politica deveria fornecer.",

	// ── Fingerprint ──────────────────────────────────────────────────────
	"weak tls version": "Seu servidor utiliza uma versao antiga e insegura do " +
		"protocolo de criptografia (TLS). Um atacante pode interceptar as " +
		"comunicacoes entre o site e os usuarios para roubar dados sensiveis.",

	// ── Bundle ───────────────────────────────────────────────────────────
	"possible secret in bundle": "Foi encontrado um possivel segredo (chave, " +
		"token ou senha) escondido no codigo JavaScript do seu site. Um " +
		"atacante pode copiar essa chave e usar para acessar sistemas " +
		"internos, banco de dados ou servicos de terceiros.",

	"admin page referenced in bundle": "O codigo JavaScript do seu site " +
		"referencia uma pagina administrativa. Isso indica que existe um " +
		"painel de administracao que pode ser alvo de ataques se nao estiver " +
		"adequadamente protegido.",

	// ── Endpoint ─────────────────────────────────────────────────────────
	"admin endpoint reachable": "Uma pagina administrativa esta acessivel pela " +
		"internet e respondeu normalmente. Um atacante pode tentar acessar " +
		"o painel administrativo para comprometer o sistema.",

	"api documentation exposed": "A documentacao da API (Swagger/OpenAPI) esta " +
		"acessivel publicamente. Isso revela todos os endpoints, parametros " +
		"e estrutura do seu sistema para atacantes.",

	// ── Auth ─────────────────────────────────────────────────────────────
	"cookies issue": "Os cookies de sessao do seu site nao possuem todas as " +
		"protecoes necessarias (Secure, HttpOnly, SameSite). Isso facilita " +
		"o roubo de sessoes e ataques CSRF.",

	"jwt issue": "O token JWT esta sendo armazenado de forma insegura (por " +
		"exemplo, no localStorage). Um atacante que consiga injetar codigo " +
		"malicioso pode roubar o token e assumir a sessao do usuario.",

	"csrf issue": "Seu site nao possui protecao contra ataques CSRF. Um site " +
		"falso pode fazer requisicoes em nome do usuario logado, alterando " +
		"dados ou realizando acoes sem o seu conhecimento.",

	"roles issue": "A verificacao de permissoes esta sendo feita apenas no " +
		"lado do cliente (navegador). Um atacante pode ignorar essas " +
		"verificacoes e acessar funcionalidades restritas.",

	"session issue": "A sessao do usuario nao e renovada apos o login e pode " +
		"ser armazenada em cache. Isso permite que outra pessoa acesse " +
		"a sessao anterior do usuario.",

	"refresh issue": "O endpoint de renovacao de tokens nao esta adequadamente " +
		"protegido. Um atacante pode renovar tokens de usuarios sem " +
		"autorizacao.",

	// ── Authorization ────────────────────────────────────────────────────
	"admin pages": "Foram encontradas paginas administrativas que podem estar " +
		"acessiveis sem autenticacao adequada. Um atacante pode acessar " +
		"funcionalidades restritas e comprometer o sistema.",

	"idor": "Foram encontrados endpoints que acessam recursos por ID sem " +
		"verificacao de autorizacao. Um atacante pode trocar o ID e " +
		"acessar dados de outros usuarios (IDOR).",

	"mass assignment": "O seu sistema aceita campos extras nas requisicoes que " +
		"sao salvos direto no banco de dados. Um atacante pode enviar " +
		"campos adicionais para alterar dados que nao deveria ter acesso.",

	"role bypass": "A verificacao de permissoes esta sendo feita no navegador. " +
		"Um atacante pode ignorar essa verificacao e acessar areas " +
		"restritas do sistema.",

	"vertical escalation": "Um usuario comum pode acessar funcionalidades de " +
		"administrador. Isso permite que qualquer pessoa assume o controle " +
		"completo do sistema.",

	// ── Correlation ──────────────────────────────────────────────────────
	"confirmed admin surface exposure": "Uma rota administrativa que aparece no " +
		"codigo do frontend esta acessivel pela internet. Um atacante pode " +
		"tentar acessar o painel administrativo e comprometer todo o " +
		"sistema.",

	"secret material exposed near authentication surface": "Existem segredos " +
		"expostos no codigo do site e ao mesmo tempo uma pagina de login " +
		"esta acessivel. Um atacante pode usar os segredos encontrados " +
		"para contornar a autenticacao e assumir o controle da conta de " +
		"qualquer usuario.",

	"authentication surface without transport protections": "A pagina de login " +
		"do seu site nao possui protecoes de transportes adequadas (HTTPS " +
		"forca, cookies seguros). Isso permite que um atacante na mesma " +
		"rede intercepte as credenciais durante o login.",

	"nuclei finding confirmed by endpoint probe": "Um problema de seguranca " +
		"foi confirmado por mais de uma ferramenta de analise. Quando " +
		"multiplos scanners apontam o mesmo problema, a chance de ser uma " +
		"vulnerabilidade real e muito alta.",

	"burp issue corroborated by active scan": "Um problema detectado pelo Burp " +
		"Suite foi confirmado por outra ferramenta. A convergencia de " +
		"resultados indica que este e um problema real que precisa ser " +
		"corrigido.",

	"insecure session cookies on sensitive route": "Os cookies de sessao nas " +
		"paginas sensiveis (login, admin) nao possuem protecoes adequadas. " +
		"Um atacante pode roubar a sessao de um usuario e assumir sua " +
		"identidade.",

	// ── Plugins ──────────────────────────────────────────────────────────
	"multiple open ports detected": "Foram detectadas muitas portas abertas no " +
		"servidor. Portas desnecessarias aumentam a superficie de ataque " +
		"e podem ser exploradas por atacantes.",
}

func fallbackBySeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "Esta falha pode permitir que invasores acessem dados confidenciais, " +
			"assumam o controle do sistema ou causem danos graves ao seu negocio."
	case "high":
		return "Esta vulnerabilidade pode ser explorada para comprometer dados de " +
			"usuarios, roubar informacoes sensiveis ou causar indisponibilidade do servico."
	case "medium":
		return "Este problema pode expor informacoes internas do sistema ou facilitar " +
			"ataques mais avancados se combinado com outras vulnerabilidades."
	case "low":
		return "Este item representa uma melhoria de seguranca recomendada que reduz " +
			"a superficie de ataque do sistema."
	default:
		return "Observacao tecnica sem impacto direto na seguranca, mas que pode " +
			"fornecer informacoes uteis sobre a configuracao do sistema."
	}
}

// LaypersonRecommendation returns a plain-language action item in Brazilian
// Portuguese for non-technical stakeholders.
func LaypersonRecommendation(f Finding) string {
	if msg, ok := recommendationByID[f.ID]; ok {
		return msg
	}
	lowerID := strings.ToLower(f.ID)
	for prefix, msg := range prefixRecommendations {
		if strings.HasPrefix(lowerID, prefix) {
			return msg
		}
	}
	if msg, ok := recommendationByTitle[strings.ToLower(f.Title)]; ok {
		return msg
	}
	return fallbackRecommendationBySeverity(f.Severity)
}

var recommendationByID = map[string]string{
	"headers/hsts": "Peca a equipe tecnica para forcar o site a usar apenas conexoes seguras (HTTPS).",
	"headers/csp": "Peca a equipe tecnica para configurar regras que bloqueiem scripts nao autorizados no site.",
	"headers/xfo": "Peca a equipe tecnica para impedir que o site seja exibido dentro de paginas de terceiros.",
	"headers/referrer-policy": "Peca a equipe tecnica para limitar quais informacoes o site envia ao sair para outros enderecos.",
	"headers/permissions-policy": "Peca a equipe tecnica para restringir o uso de camera, microfone e localizacao no navegador.",
	"headers/cache-control": "Peca a equipe tecnica para evitar que paginas sensiveis fiquem salvas no navegador.",
	"headers/rate-limit": "Peca a equipe tecnica para limitar quantas tentativas um visitante pode fazer em pouco tempo.",
	"headers/cors": "Peca a equipe tecnica para permitir acesso aos dados apenas de origens confiaveis.",
	"headers/cookies-secure": "Peca a equipe tecnica para marcar os cookies de sessao como seguros em conexoes protegidas.",
	"headers/cookies-httponly": "Peca a equipe tecnica para impedir que scripts maliciosos leiam os cookies de sessao.",
	"headers/cookies-samesite": "Peca a equipe tecnica para reforcar a protecao dos cookies contra sites falsos.",
	"csp/missing": "Peca a equipe tecnica para definir regras que controlem o que pode ser executado no navegador.",
	"csp/unsafe-inline": "Peca a equipe tecnica para remover a permissao de scripts embutidos nas paginas.",
	"csp/unsafe-eval": "Peca a equipe tecnica para desativar a execucao de codigo dinamico no navegador.",
	"csp/wildcard-default": "Peca a equipe tecnica para restringir de quais enderecos o site pode carregar recursos.",
	"fingerprint/stack": "Mantenha as tecnologias do site atualizadas e monitore avisos de seguranca publicados.",
	"fingerprint/weak-tls": "Peca a equipe tecnica para atualizar a criptografia do servidor para um padrao atual.",
	"endpoint/api-doc-openapi-json": "Peca a equipe tecnica para restringir o acesso publico a documentacao interna da API.",
	"endpoint/api-doc-swagger": "Peca a equipe tecnica para restringir o acesso publico a documentacao interna da API.",
	"correlation/secret-near-auth": "Remova senhas e chaves do codigo visivel e troque imediatamente as credenciais expostas.",
	"correlation/weak-transport-login": "Peca a equipe tecnica para proteger a pagina de login com HTTPS e cookies seguros.",
}

var prefixRecommendations = map[string]string{
	"bundle/secret-": "Remova senhas e chaves do codigo publico e troque as credenciais que possam ter vazado.",
	"bundle/admin-page-": "Garanta que o painel administrativo exija autenticacao forte e nao seja facil de encontrar.",
	"endpoint/exposed-": "Restrinja o acesso ao painel administrativo e exija autenticacao para areas sensiveis.",
	"endpoint/api-doc-": "Bloqueie o acesso publico a documentacao detalhada da API.",
	"authorization/admin-pages-": "Exija login e permissoes adequadas para todas as areas administrativas.",
	"authorization/idor-": "Garanta que cada usuario so acesse os proprios dados, validando permissoes no servidor.",
	"authorization/mass-assignment-": "Permita apenas os campos esperados nas formas e requisicoes enviadas pelos usuarios.",
	"authorization/role-bypass-": "Valide permissoes no servidor, nao apenas no navegador do usuario.",
	"authorization/vertical-escalation-": "Impeca que usuarios comuns acessem funcoes de administrador.",
	"correlation/admin-exposure-": "Proteja rotas administrativas com autenticacao e monitoramento.",
	"correlation/nuclei-confirmed-": "Priorize a correcao deste item, pois foi confirmado por mais de uma analise.",
	"correlation/burp-corroborated-": "Priorize a correcao deste item com base na confirmacao cruzada das ferramentas.",
	"correlation/insecure-session-": "Reforce a protecao dos cookies de sessao nas paginas de login e administracao.",
	"auth/cookies-": "Peca a equipe tecnica para aplicar todas as protecoes recomendadas nos cookies de sessao.",
	"auth/jwt-": "Armazene tokens de acesso de forma segura e com tempo de expiracao curto.",
	"auth/csrf-": "Peca a equipe tecnica para adicionar protecao contra acoes feitas por sites falsos.",
	"auth/roles-": "Valide permissoes no servidor em todas as acoes sensiveis.",
	"auth/session-": "Renove a sessao apos o login e evite reutilizacao de sessoes antigas.",
	"auth/refresh-": "Proteja o fluxo de renovacao de acesso com validacoes adicionais.",
}

var recommendationByTitle = map[string]string{
	"hsts":                     "Peca a equipe tecnica para forcar o site a usar apenas conexoes seguras (HTTPS).",
	"csp":                      "Peca a equipe tecnica para configurar regras que bloqueiem scripts nao autorizados no site.",
	"xfo":                      "Peca a equipe tecnica para impedir que o site seja exibido dentro de paginas de terceiros.",
	"referrer policy":          "Peca a equipe tecnica para limitar quais informacoes o site envia ao sair para outros enderecos.",
	"permissions policy":       "Peca a equipe tecnica para restringir o uso de camera, microfone e localizacao no navegador.",
	"cache control":            "Peca a equipe tecnica para evitar que paginas sensiveis fiquem salvas no navegador.",
	"rate limit":               "Peca a equipe tecnica para limitar quantas tentativas um visitante pode fazer em pouco tempo.",
	"cookies secure":           "Peca a equipe tecnica para marcar os cookies de sessao como seguros em conexoes protegidas.",
	"cookies httponly":         "Peca a equipe tecnica para impedir que scripts maliciosos leiam os cookies de sessao.",
	"cookies samesite":         "Peca a equipe tecnica para reforcar a protecao dos cookies contra sites falsos.",
	"possible secret in bundle": "Remova senhas e chaves do codigo publico e troque as credenciais que possam ter vazado.",
	"secret material exposed near authentication surface": "Remova senhas e chaves do codigo visivel e troque imediatamente as credenciais expostas.",
	"authentication surface without transport protections": "Proteja a pagina de login com HTTPS e cookies seguros.",
	"insecure session cookies on sensitive route": "Reforce a protecao dos cookies de sessao nas paginas de login e administracao.",
}

func fallbackRecommendationBySeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return "Trate este item com prioridade e envolva a equipe tecnica para corrigir o mais rapido possivel."
	case "medium":
		return "Planeje a correcao deste item com a equipe tecnica nas proximas semanas."
	case "low":
		return "Inclua este item no backlog de melhorias de seguranca da equipe tecnica."
	default:
		return "Revise este item com a equipe tecnica para confirmar se alguma acao e necessaria."
	}
}
