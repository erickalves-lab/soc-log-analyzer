#!/usr/bin/env python3
"""
SOC Log Analyzer - Monitora tentativas de autenticação suspeitas
"""

import re
import json
from datetime import datetime
from collections import defaultdict

# Carregar configurações
def load_config():
    with open('config/config.json', 'r') as f:
        return json.load(f)

# Ler o arquivo de log
def read_log_file(log_path):
    try:
        with open(log_path, 'r') as f:
            return f.readlines()
    except PermissionError:
        print(f"Erro: Sem permissão para ler {log_path}")
        print("Execute com sudo: sudo python3 log_analyzer.py")
        exit(1)

# Extrair informações de tentativas falhadas
def parse_failed_attempts(log_lines):
    failed_attempts = []
    
    # Padrão regex para detectar "Failed password"
    pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Failed password for (\w+) from ([\d.]+)'
    
    for line in log_lines:
        match = re.search(pattern, line)
        if match:
            timestamp_str = match.group(1)
            username = match.group(2)
            ip_address = match.group(3)
            
            failed_attempts.append({
                'timestamp': timestamp_str,
                'username': username,
                'ip': ip_address
            })
    
    return failed_attempts

# Contar tentativas por IP
def count_attempts_by_ip(failed_attempts):
    ip_count = defaultdict(lambda: {'count': 0, 'users': set()})
    
    for attempt in failed_attempts:
        ip = attempt['ip']
        ip_count[ip]['count'] += 1
        ip_count[ip]['users'].add(attempt['username'])
    
    return ip_count

# Exibir resultados
def display_results(ip_count, config):
    threshold = config['thresholds']['failed_login_attempts']
    
    print("\n" + "="*60)
    print("SOC LOG ANALYZER - RELATÓRIO DE TENTATIVAS FALHADAS")
    print("="*60 + "\n")
    
    suspicious_ips = []
    
    for ip, data in sorted(ip_count.items(), key=lambda x: x[1]['count'], reverse=True):
        count = data['count']
        users = ', '.join(data['users'])
        
        # Verificar se está na whitelist
        if ip in config['whitelist_ips']:
            status = "✅ WHITELIST"
        elif count >= threshold:
            status = "🚨 SUSPEITO"
            suspicious_ips.append(ip)
        else:
            status = "⚠️  ATENÇÃO"
        
        print(f"{status} | IP: {ip:15} | Tentativas: {count:3} | Usuários: {users}")
    
    print("\n" + "="*60)
    print(f"RESUMO:")
    print(f"   Total de IPs únicos: {len(ip_count)}")
    print(f"   IPs suspeitos (>={threshold} tentativas): {len(suspicious_ips)}")
    print("="*60 + "\n")

# Função principal
def main():
    print("Iniciando SOC Log Analyzer...\n")
    
    # Carregar configurações
    config = load_config()
    print(f"Configurações carregadas")
    
    # Ler logs
    log_path = config['log_file']
    print(f"Lendo arquivo: {log_path}")
    log_lines = read_log_file(log_path)
    print(f"{len(log_lines)} linhas lidas\n")
    
    # Analisar tentativas falhadas
    failed_attempts = parse_failed_attempts(log_lines)
    print(f"{len(failed_attempts)} tentativas falhadas detectadas")
    
    # Contar por IP
    ip_count = count_attempts_by_ip(failed_attempts)
    
    # Exibir resultados
    display_results(ip_count, config)

if __name__ == "__main__":
    main()
