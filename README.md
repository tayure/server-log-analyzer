# Analisador-de-Logs-de-Servidor-e-Monitor-de-Segurança

Descrição do Projeto

Esta ferramenta foi desenvolvida em Python para automatizar o processamento e a análise técnica de arquivos de log de servidores web. O sistema realiza a extração de metadados, validação de protocolos de rede e detecção de padrões maliciosos, consolidando os resultados em um relatório detalhado de integridade e segurança.

Arquitetura e Implementação Técnica

1. Extração de Dados (Parsing): O processamento utiliza Expressões Regulares (Regex) para a tokenização eficiente de strings brutas. O padrão implementado permite a identificação precisa de grupos de captura, como endereços IPv4, carimbos de data/hora (timestamps), métodos HTTP, URIs de recursos e códigos de estado (status codes).

2. Validação e Inteligência de Rede

   O projeto integra o módulo nativo ipaddress para realizar a validação lógica dos dados extraídos:

° Discriminação de Escopo: Identificação automática entre endereços de redes privadas (RFC 1918) e redes públicas.

° Tratamento de Anomalias: Implementação de tratamento de exceções para descartar entradas malformadas, garantindo a integridade das métricas estatísticas.

3. Detecção de Intrusão (IDS Passivo)

O software confronta os recursos requisitados contra uma blacklist de diretórios sensíveis (ex: .env, /admin, /backup, /config). Tentativas de acesso a estes recursos disparam alertas imediatos e isolam os respectivos endereços IP para análise forense ou bloqueio em firewall.

4. Análise Estatística e Métricas de Saúde

Utilizando a estrutura collections.Counter, o sistema agrega indicadores de performance (KPIs):

° Distribuição Temporal: Agrupamento de acessos por hora para identificação de janelas de tráfego atípico ou ataques de força bruta.

° Métricas de Erro: Cálculo da taxa de erro combinada (4xx e 5xx) em relação ao volume total de requisições, monitorando a estabilidade do serviço.

Performance e Escalabilidade

O sistema foi projetado sob o princípio de baixo consumo de recursos:

° Processamento em Fluxo (Streaming): O arquivo é lido linha por linha, evitando o carregamento total na memória RAM. Isso permite processar arquivos de múltiplos gigabytes (GB) com consumo de memória constante e reduzido.

° Complexidade Algorítmica: As operações de agregação possuem complexidade linear $O(n)$, garantindo alta velocidade de processamento mesmo em grandes volumes de dados.

Especificações de Entrada

O analisador é compatível com arquivos de texto plano (.txt ou .log) que sigam os padrões:

1. Common Log Format (CLF)
2. Combined Log Format
3. Padrões de saída de servidores Apache e Nginx
4. Microsoft IIS (Desde que configurado para o formato W3C com as colunas na ordem compatível).

Exemplo de linha suportada: 127.0.0.1 - - [25/Dec/2025:14:30:00 +0000] "GET /admin HTTP/1.1" 401 522

Tecnologias Utilizadas

1. Linguagem: Python 3.x
2. Bibliotecas: re, ipaddress, collections, argparse, os.

Como Executar

O script deve ser executado via linha de comando, passando o caminho do arquivo de log como argumento:

python analyzer.py [caminho_do_arquivo_de_log]











