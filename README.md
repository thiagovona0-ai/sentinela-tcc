# Sentinela

Aplicação acadêmica independente para consultar reputação de URLs, hashes, domínios e endereços IP, além de enviar arquivos para análise via API v3 do VirusTotal. A chave da API permanece no servidor. O projeto não é afiliado ao VirusTotal/Google e não substitui antivírus.

## Rodar localmente

Requisitos: Node.js 20 ou superior. Não há dependências de terceiros.

PowerShell:

```powershell
$env:VT_API_KEY = "SUA_CHAVE_DO_VIRUSTOTAL"
npm start
```

Abra `http://localhost:3000`. A chave pode ser obtida na conta VirusTotal Community. Nunca a coloque no HTML, JavaScript do navegador ou em um repositório público.

## Publicar no Render

O arquivo `render.yaml` descreve um serviço web com implantação pelo Git. Coloque esta pasta na raiz de um repositório Git e envie para um provedor Git conectado ao Render. No painel do Render, crie um **Blueprint** a partir desse repositório e configure o segredo `VT_API_KEY` quando solicitado. O serviço usa o plano Free configurado no Blueprint.

Você também pode criar um Web Service manualmente com:

- Root Directory: `sentinela` (se a pasta estiver dentro de um repositório maior)
- Build Command: `npm install`
- Start Command: `npm start`
- Environment: `VT_API_KEY` com a chave privada
- Health Check Path: `/health`

O processo escuta em `0.0.0.0` e usa a porta fornecida pelo provedor. Para outro host, use o `Dockerfile` incluído ou um serviço Node.js que aceite `PORT` e configure `VT_API_KEY` como segredo.

O nível Free do Render pode suspender a aplicação após inatividade, levando cerca de um minuto para voltar ao receber uma nova visita. O provedor também informa limites mensais e armazenamento efêmero. Consulte as [limitações atuais do plano Free](https://render.com/docs/free) antes de publicar. Hospedagem gratuita não significa disponibilidade contínua garantida.

## Funcionalidades

- Consultas de URL, hash MD5/SHA-1/SHA-256, domínio e endereço IP.
- Envio de arquivo e acompanhamento da análise, com limite de 32 MB imposto pela API pública.
- Envio explícito de URLs que ainda não possuem relatório.
- Exibição de todos os mecanismos retornados, com filtro, busca, dados completos da resposta e atalho para o relatório do VirusTotal.
- Tratamento de erros de chave, permissões, limites, ausência de dados e indisponibilidade.
- Limite de solicitações por endereço e fila global para respeitar a cota da chave.
- Cabeçalhos básicos de segurança e verificação de saúde em `/health`.

## Configuração opcional

- `PORT`: porta HTTP (padrão `3000`)
- `VT_API_KEY`: chave privada usada pelo backend (obrigatória para consultar)
- `MAX_UPLOAD_MB`: tamanho máximo de upload em MB (padrão `32`)
- `APP_RATE_LIMIT`: máximo de solicitações por endereço a cada minuto (padrão `20`)

## Dados, privacidade e limites

Arquivos enviados são encaminhados ao VirusTotal e podem ser compartilhados sob os termos do serviço. Não envie dados confidenciais ou conteúdo sem autorização. URLs podem conter tokens e informações privadas; considere hashes para consultas de arquivos já conhecidos. Este protótipo não mantém banco de dados nem histórico próprio.

A API pública documenta 4 requisições por minuto e até 500 por dia, além de restrições de uso. A aplicação organiza as consultas para não ultrapassar 4 solicitações por minuto por processo, mas a cota diária continua sendo compartilhada por todos os visitantes. A disponibilidade de determinados endpoints depende do nível de acesso da chave. Consultar e enviar indicadores ao VirusTotal pode adicioná-los ao conjunto de dados público; não envie dados confidenciais. A API pública não disponibiliza todos os recursos premium do VirusTotal, então esta aplicação apresenta todos os campos e mecanismos retornados pelos endpoints utilizados e oferece um atalho para abrir o relatório completo no próprio VirusTotal. Leia os [termos e limites da API](https://docs.virustotal.com/reference/public-vs-premium-api) e [visão geral da API](https://docs.virustotal.com/reference/overview) antes de colocar o serviço à disposição de outras pessoas.

Esta é uma base pronta para implantação acadêmica e demonstração. Para uso público com múltiplos usuários, acrescente autenticação, monitoramento, proteção contra abuso distribuído, políticas de privacidade e análise das exigências de licença aplicáveis.

