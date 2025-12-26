import argparse
import ipaddress
import re
import os
from collections import Counter

# Gabarito Regex: Define como extrair IP, Data, Método, Recurso e Status de cada linha
LOG_PATTERN = re.compile(
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # Grupo 1: Endereço IP
    r'.*?'                                   # Texto ignorado
    r'\[(.*?)]'                              # Grupo 2: Data e Hora
    r'.*?'                                   # Texto ignorado
    r'"(GET|POST|PUT|DELETE|HEAD) (\S+).*?"' # Grupo 3 e 4: Método HTTP e URL/Recurso
    r'\s(\d{3})'                             # Grupo 5: Código de Status HTTP
    r'\s(\d+|-)'                             # Grupo 6: Tamanho da resposta
)

def analyze_log(file_path):
    """Lê o arquivo de log e processa as estatísticas de segurança."""
    print(f"--- Iniciando leitura do: {file_path} ---")

    # Configuração da Blacklist: caminhos que indicam tentativa de invasão.
    blacklist = ['/admin', '/config', '/.env', 'wp-login', '/setup', '/config.php', '/web.config',
                 '/index.php.bak', '/robots.txt', '/.git/', '/temp/', '/backup/']

    # Inicialização dos contadores e listas
    ip_counts = Counter()           # Conta acessos por IP
    resource_counts = Counter()     # Conta acessos por página/recurso
    status_counts = Counter()       # Conta códigos HTTP (200, 404, etc)
    hourly_counts = Counter()       # Conta acessos por hora do dia
    suspicious_ips = []             # Armazena IPs que tocaram na blacklist

    total_lines = 0                 # Contador de linhas totais
    matches_found = 0               # Contador de linhas que o Regex entendeu
    intrusion_attempts = 0          # Contador de alertas de segurança

    try:
        # Abre o arquivo para leitura linha por linha (eficiente para arquivos grandes)
        with open(file_path, 'r') as f:
            for line in f:
                total_lines += 1
                match = LOG_PATTERN.search(line)

                if match:
                    matches_found += 1
                    full_timestamp = match.group(2)    # Ex: 25/Dec/2025:14:30:00
                    ip, _, _, resource, status_code, _ = match.groups()

                    # Validação de IP: Verifica se é um endereço real e se é Interno ou Externo
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if ip_obj.is_private:
                            ip_counts[f"{ip} (Interno)"] += 1
                        else:
                            ip_counts[f"{ip} (Externo)"] += 1
                    except ValueError:
                        print(f"Aviso: O texto {ip} não é um IP válido.")
                        continue     # Pula para a próxima linha se o IP for inválido

                    # Processamento de Tempo: Divide a data para extrair apenas a HORA
                    time_segments = full_timestamp.split(':')
                    hour = time_segments[1]
                    hourly_counts[hour] += 1

                    # Contagem de recursos e status
                    resource_counts[resource] += 1
                    status_counts[status_code] += 1

                    # Verificação de Segurança: Compara o recurso acessado com a Blacklist
                    if any(item in resource for item in blacklist):
                        print(f"ALERTA DE SEGURANÇA: Tentativa de acesso proibido ao recurso: {resource} pelo IP: {ip}")
                        intrusion_attempts += 1
                        if ip not in suspicious_ips:
                            suspicious_ips.append(ip)    # Adiciona à lista de investigação sem repetir

        print(f"--- Fim da leitura. Linhas lidas: {total_lines}, válidas: {matches_found} ---")

        # Verificação básica se o arquivo continha dados aproveitáveis
        if total_lines == 0:
            print("AVISO: O arquivo de log está vazio!")
            return
        elif matches_found == 0:
            print("AVISO: Nenhuma linha capturada. Verifique o padrão do log.")
            return

    except FileNotFoundError:
        print(f'\n ERRO FATAL: Arquivo não encontrado em {file_path}.')
        return

    # Envia todos os dados processados para a função que gera o visual do relatório
    generate_report(total_lines, ip_counts, resource_counts, status_counts, hourly_counts, intrusion_attempts,
                    suspicious_ips)

def generate_report(total_lines, ip_counts, resource_counts, status_counts, hourly_counts, intrusion_attempts,
                    suspicious_ips):
    """Formata e imprime o relatório final no terminal."""
    print('\n' + '='*50)
    print('             RELATÓRIO DE SEGURANÇA ')
    print('='*50)

    # Seção de Alertas Críticos
    if intrusion_attempts > 0:
        print(f"ATENÇÃO: {intrusion_attempts} tentativas em áreas críticas!")

        print("\n Lista de IPs Suspeitos:")
        if suspicious_ips:
            for suspect in suspicious_ips:
                print(f" -> {suspect} Verificar Firewall")
        else:
            print("Nenhum IP suspeito identificado!")

    # Seção Visual: Gráfico de barras simples para tráfego por hora
    print("\n[>] ACESSOS POR HORA (Linha do Tempo):")
    for hour in sorted(hourly_counts.keys()):
        count = hourly_counts[hour]
        bar = "#" * count     # Desenha uma barra proporcional ao número de acessos
        print(f" Hora {hour}h: {bar} ({count} reqs)")

    if not ip_counts:
        print("Não há dados processados para exibir.")
        return

    # Estatísticas de Acessos
    print(f'Total de linhas processadas: {total_lines}')
    print(f'IPs únicos identificados: {len(ip_counts)}')

    print("\n Quem mais acessou:")
    for ip, count in ip_counts.most_common(5):
        print(f' - {ip}: {count} vezes')

    print("\n Recursos Mais Acessados:")
    for resource, count in resource_counts.most_common(5):
        print(f' - {resource}: {count}')

    # Cálculos de Métricas de Erro (Fundamento de Confiabilidade de Sistemas)
    total_requests = sum(status_counts.values())
    errors_4xx = sum(count for status, count in status_counts.items() if status.startswith('4'))
    errors_5xx = sum(count for status, count in status_counts.items() if status.startswith('5'))
    total_errors = errors_4xx + errors_5xx
    error_rate = (total_errors / total_requests) * 100 if total_requests > 0 else 0

    print("\n RESUMO GERAL DE STATUS HTTP:")
    for status, count in sorted(status_counts.items()):
        print(f"  - Status {status}: {count} requisições")

    print("\n ANÁLISE DE SAÚDE DO SERVIDOR:")
    print(f"  Total de requisições válidas: {total_requests}")
    print(f"  Erros de Cliente (4xx): {errors_4xx}")
    print(f"  Erros de Servidor (5xx): {errors_5xx}")
    print(f"  **TAXA DE ERRO TOTAL: {error_rate:.2f}%**")
    print('='*40)

def main():
    """Configura a interface de linha de comando."""
    parser = argparse.ArgumentParser(description='Log Analyzer Professional')
    parser.add_argument('file_path', type=str,
                        help='O caminho para o arquivo de log do servidor a ser analisado.')
    args = parser.parse_args()

    # Verifica se o arquivo existe fisicamente antes de começar
    if os.path.exists(args.file_path):
        analyze_log(args.file_path)
    else:
        print(f"ERRO: O arquivo {args.file_path} não existe no diretório atual. ")

# Ponto de entrada oficial do script
if __name__ == '__main__':
    main()
