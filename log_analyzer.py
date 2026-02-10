#!/usr/bin/env python3
"""
SOC Log Analyzer - Monitora tentativas de autenticação suspeitas
Versão 2.0 
"""

import re
import json
from datetime import datetime, timedelta
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
            
            # Converter timestamp para objeto datetime
            try:
                timestamp = datetime.fromisoformat(timestamp_str)
            except:
                continue
            
            failed_attempts.append({
                'timestamp': timestamp,
                'username': username,
                'ip': ip_address
            })
    
    return failed_attempts

# Contar tentativas por IP com análise temporal
def analyze_by_ip(failed_attempts, config):
    ip_data = defaultdict(lambda: {
        'count': 0, 
        'users': set(), 
        'timestamps': [],
        'severity': 'LOW'
    })
    
    for attempt in failed_attempts:
        ip = attempt['ip']
        ip_data[ip]['count'] += 1
        ip_data[ip]['users'].add(attempt['username'])
        ip_data[ip]['timestamps'].append(attempt['timestamp'])
    
    # Analisar cada IP
    for ip, data in ip_data.items():
        data['severity'] = calculate_severity(data, config)
    
    return ip_data

# Calcular severidade baseado em múltiplos fatores
def calculate_severity(data, config):
    count = data['count']
    num_users = len(data['users'])
    timestamps = sorted(data['timestamps'])
    
    threshold = config['thresholds']['failed_login_attempts']
    time_window = config['thresholds']['time_window_minutes']
    
    # Verificar tentativas em janela de tempo curta
    rapid_attempts = check_time_window(timestamps, time_window)
    
    # Verificar horário comercial
    off_hours = check_off_hours(timestamps, config)
    
    # Lógica de severidade
    if count >= threshold * 2:  # 10+ tentativas
        return 'CRITICAL'
    elif count >= threshold and (rapid_attempts or off_hours or num_users > 3):
        return 'HIGH'
    elif count >= threshold or num_users > 2:
        return 'MEDIUM'
    else:
        return 'LOW'

# Verificar se tentativas ocorreram em janela de tempo curta
def check_time_window(timestamps, window_minutes):
    if len(timestamps) < 3:
        return False
    
    for i in range(len(timestamps) - 2):
        time_diff = (timestamps[i+2] - timestamps[i]).total_seconds() / 60
        if time_diff <= window_minutes:
            return True
    
    return False

# Verificar se houve tentativas fora do horário comercial
def check_off_hours(timestamps, config):
    business_start = datetime.strptime(config['thresholds']['business_hours_start'], '%H:%M').time()
    business_end = datetime.strptime(config['thresholds']['business_hours_end'], '%H:%M').time()
    
    for ts in timestamps:
        if ts.time() < business_start or ts.time() > business_end:
            return True
    
    return False

# Detectar enumeração de usuários
def detect_user_enumeration(ip_data):
    enumeration_ips = []
    
    for ip, data in ip_data.items():
        # Se tentou 3+ usuários diferentes = possível enumeração
        if len(data['users']) >= 3:
            enumeration_ips.append({
                'ip': ip,
                'users': data['users'],
                'count': len(data['users'])
            })
    
    return enumeration_ips

# Exibir resultados com detecção avançada
def display_results(ip_data, enumeration_ips, config):
    threshold = config['thresholds']['failed_login_attempts']
    
    print("\n" + "="*70)
    print("🔍 SOC LOG ANALYZER - RELATÓRIO AVANÇADO DE TENTATIVAS FALHADAS")
    print("="*70 + "\n")
    
    # Organizar por severidade
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_ips = sorted(ip_data.items(), 
                       key=lambda x: (severity_order[x[1]['severity']], -x[1]['count']))
    
    # Contadores
    stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'WHITELISTED': 0}
    
    for ip, data in sorted_ips:
        count = data['count']
        users = ', '.join(list(data['users'])[:3])  # Mostrar até 3 usuários
        if len(data['users']) > 3:
            users += f" (+{len(data['users'])-3} mais)"
        
        severity = data['severity']
        
        # Verificar whitelist
        if ip in config['whitelist_ips']:
            status = "WHITELIST"
            stats['WHITELISTED'] += 1
        else:
            if severity == 'CRITICAL':
                status = "🔴 CRÍTICO"
                stats['CRITICAL'] += 1
            elif severity == 'HIGH':
                status = "🟠 ALTO    "
                stats['HIGH'] += 1
            elif severity == 'MEDIUM':
                status = "🟡 MÉDIO  "
                stats['MEDIUM'] += 1
            else:
                status = "🟢 BAIXO     "
                stats['LOW'] += 1
        
        print(f"{status} | IP: {ip:15} | Tent: {count:3} | Usuários: {users}")
    
    # Detecção de enumeração
    if enumeration_ips:
        print("\n" + "-"*70)
        print("⚠️  POSSÍVEL ENUMERAÇÃO DE USUÁRIOS DETECTADA:")
        print("-"*70)
        for enum in enumeration_ips:
            users_list = ', '.join(list(enum['users'])[:5])
            print(f"   IP: {enum['ip']:15} | Testou {enum['count']} usuários: {users_list}")
    
    # Resumo
    print("\n" + "="*70)
    print(f"📊 RESUMO POR SEVERIDADE:")
    print(f"   🔴 CRÍTICO:    {stats['CRITICAL']:2} IPs")
    print(f"   🟠 ALTO:        {stats['HIGH']:2} IPs")
    print(f"   🟡 MÉDIO:      {stats['MEDIUM']:2} IPs")
    print(f"   🟢 BAIXO:         {stats['LOW']:2} IPs")
    print(f"   ✅ SEGURO: {stats['WHITELISTED']:2} IPs")
    print(f"\n   📍 Total de IPs únicos: {len(ip_data)}")
    print(f"   🎯 IPs suspeitos (>={threshold} tentativas): {stats['CRITICAL'] + stats['HIGH'] + stats['MEDIUM']}")
    print("="*70 + "\n")

# Função principal
def main():
    print("🚀 Iniciando SOC Log Analyzer v2.0...\n")
    
    # Carregar configurações
    config = load_config()
    print(f"✅ Configurações carregadas")
    
    # Ler logs
    log_path = config['log_file']
    print(f"📂 Lendo arquivo: {log_path}")
    log_lines = read_log_file(log_path)
    print(f"✅ {len(log_lines)} linhas lidas\n")
    
    # Analisar tentativas falhadas
    failed_attempts = parse_failed_attempts(log_lines)
    print(f"🔎 {len(failed_attempts)} tentativas falhadas detectadas")
    
    # Análise por IP
    ip_data = analyze_by_ip(failed_attempts, config)
    
    # Detectar enumeração
    enumeration_ips = detect_user_enumeration(ip_data)
    if enumeration_ips:
        print(f"⚠️  {len(enumeration_ips)} IP(s) com possível enumeração de usuários")
    
    # Exibir resultados
    display_results(ip_data, enumeration_ips, config)

if __name__ == "__main__":
    main()
