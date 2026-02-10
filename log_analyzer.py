#!/usr/bin/env python3
"""
SOC Log Analyzer - Security Operations Center Analytics
Versão 4.0 - Integração com fail2ban + Análise Avançada
"""

import re
import json
import csv
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
import os

# Carregar configurações
def load_config():
    with open('config/config.json', 'r') as f:
        return json.load(f)

# Configurar logging
def setup_logging():
    log_dir = 'logs'
    os.makedirs(log_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = f"{log_dir}/analyzer_{timestamp}.log"
    
    return log_file

# Escrever no log de auditoria
def write_log(log_file, message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(log_file, 'a') as f:
        f.write(f"[{timestamp}] {message}\n")

# Ler arquivo de log
def read_log_file(log_path):
    try:
        with open(log_path, 'r') as f:
            return f.readlines()
    except PermissionError:
        print(f"Erro: Sem permissão para ler {log_path}")
        print("Execute com sudo: sudo python3 log_analyzer.py")
        exit(1)
    except FileNotFoundError:
        return []

# Analisar logs do fail2ban
def parse_fail2ban_logs():
    """Extrai informações de banimentos do fail2ban"""
    f2b_log = '/var/log/fail2ban.log'
    
    try:
        lines = read_log_file(f2b_log)
    except:
        return []
    
    banned_ips = []
    
    # Padrão: 2024-02-09 17:30:45,123 fail2ban.actions[123]: NOTICE [sshd] Ban 192.168.122.30
    pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*\[sshd\] Ban ([\d.]+)'
    
    for line in lines:
        match = re.search(pattern, line)
        if match:
            timestamp_str = match.group(1)
            ip_address = match.group(2)
            
            try:
                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                banned_ips.append({
                    'timestamp': timestamp,
                    'ip': ip_address,
                    'action': 'banned'
                })
            except:
                continue
    
    return banned_ips

# Obter IPs atualmente banidos
def get_currently_banned():
    """Obtém lista de IPs atualmente banidos pelo fail2ban"""
    try:
        result = subprocess.run(
            ['sudo', 'fail2ban-client', 'status', 'sshd'],
            capture_output=True,
            text=True,
            check=True
        )
        
        # Procurar linha "Banned IP list:"
        for line in result.stdout.split('\n'):
            if 'Banned IP list:' in line:
                ips_str = line.split('Banned IP list:')[1].strip()
                if ips_str:
                    return ips_str.split()
                return []
        
        return []
    except:
        return []

# Extrair tentativas falhadas do auth.log
def parse_failed_attempts(log_lines):
    failed_attempts = []
    
    pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Failed password for (\w+) from ([\d.]+)'
    
    for line in log_lines:
        match = re.search(pattern, line)
        if match:
            timestamp_str = match.group(1)
            username = match.group(2)
            ip_address = match.group(3)
            
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

# Analisar por IP
def analyze_by_ip(failed_attempts, config):
    ip_data = defaultdict(lambda: {
        'count': 0, 
        'users': set(), 
        'timestamps': [],
        'severity': 'LOW',
        'banned_by_f2b': False
    })
    
    for attempt in failed_attempts:
        ip = attempt['ip']
        ip_data[ip]['count'] += 1
        ip_data[ip]['users'].add(attempt['username'])
        ip_data[ip]['timestamps'].append(attempt['timestamp'])
    
    for ip, data in ip_data.items():
        data['severity'] = calculate_severity(data, config)
    
    return ip_data

# Calcular severidade
def calculate_severity(data, config):
    count = data['count']
    num_users = len(data['users'])
    timestamps = sorted(data['timestamps'])
    
    threshold = config['thresholds']['failed_login_attempts']
    time_window = config['thresholds']['time_window_minutes']
    
    rapid_attempts = check_time_window(timestamps, time_window)
    off_hours = check_off_hours(timestamps, config)
    
    if count >= threshold * 2:
        return 'CRITICAL'
    elif count >= threshold and (rapid_attempts or off_hours or num_users > 3):
        return 'HIGH'
    elif count >= threshold or num_users > 2:
        return 'MEDIUM'
    else:
        return 'LOW'

# Verificar janela de tempo
def check_time_window(timestamps, window_minutes):
    if len(timestamps) < 3:
        return False
    
    for i in range(len(timestamps) - 2):
        time_diff = (timestamps[i+2] - timestamps[i]).total_seconds() / 60
        if time_diff <= window_minutes:
            return True
    
    return False

# Verificar horário comercial
def check_off_hours(timestamps, config):
    business_start = datetime.strptime(config['thresholds']['business_hours_start'], '%H:%M').time()
    business_end = datetime.strptime(config['thresholds']['business_hours_end'], '%H:%M').time()
    
    for ts in timestamps:
        if ts.time() < business_start or ts.time() > business_end:
            return True
    
    return False

# Detectar enumeração
def detect_user_enumeration(ip_data):
    enumeration_ips = []
    
    for ip, data in ip_data.items():
        if len(data['users']) >= 3:
            enumeration_ips.append({
                'ip': ip,
                'users': data['users'],
                'count': len(data['users'])
            })
    
    return enumeration_ips

# Detectar ataques distribuídos
def detect_distributed_attack(ip_data, time_window=300):
    """
    Detecta quando múltiplos IPs atacam num curto período
    (possível botnet ou ataque coordenado)
    """
    all_timestamps = []
    
    for ip, data in ip_data.items():
        for ts in data['timestamps']:
            all_timestamps.append((ts, ip))
    
    all_timestamps.sort()
    
    # Procurar janelas com muitos IPs diferentes
    distributed_attacks = []
    
    for i in range(len(all_timestamps)):
        window_start = all_timestamps[i][0]
        window_end = window_start + timedelta(seconds=time_window)
        
        ips_in_window = set()
        attempts_in_window = 0
        
        for ts, ip in all_timestamps[i:]:
            if ts <= window_end:
                ips_in_window.add(ip)
                attempts_in_window += 1
            else:
                break
        
        # Se 3+ IPs diferentes em 5 minutos = distribuído
        if len(ips_in_window) >= 3 and attempts_in_window >= 10:
            distributed_attacks.append({
                'start_time': window_start,
                'ip_count': len(ips_in_window),
                'attempt_count': attempts_in_window,
                'ips': list(ips_in_window)
            })
            break  # Reportar só o primeiro para não poluir
    
    return distributed_attacks

# Correlacionar dados
def correlate_data(ip_data, f2b_bans, currently_banned):
    """Marca quais IPs foram banidos pelo fail2ban"""
    
    for ip in ip_data:
        if ip in currently_banned:
            ip_data[ip]['banned_by_f2b'] = True
        else:
            # Verificar se foi banido no passado
            for ban in f2b_bans:
                if ban['ip'] == ip:
                    ip_data[ip]['was_banned'] = True
                    ip_data[ip]['ban_time'] = ban['timestamp']
                    break

# Gerar relatório JSON
def generate_json_report(ip_data, enumeration_ips, f2b_bans, distributed_attacks):
    report_dir = 'reports'
    os.makedirs(report_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{report_dir}/report_{timestamp}.json"
    
    report_data = {}
    for ip, data in ip_data.items():
        report_data[ip] = {
            'count': data['count'],
            'users': list(data['users']),
            'severity': data['severity'],
            'banned_by_fail2ban': data.get('banned_by_f2b', False),
            'first_attempt': data['timestamps'][0].isoformat() if data['timestamps'] else None,
            'last_attempt': data['timestamps'][-1].isoformat() if data['timestamps'] else None
        }
    
    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'total_attempts': sum(d['count'] for d in ip_data.values()),
            'unique_ips': len(ip_data),
            'fail2ban_bans': len(f2b_bans),
            'distributed_attacks_detected': len(distributed_attacks)
        },
        'ip_analysis': report_data,
        'enumeration_detected': [
            {'ip': e['ip'], 'users': list(e['users']), 'count': e['count']} 
            for e in enumeration_ips
        ],
        'fail2ban_bans': [
            {'ip': b['ip'], 'timestamp': b['timestamp'].isoformat()}
            for b in f2b_bans
        ],
        'distributed_attacks': distributed_attacks
    }
    
    with open(filename, 'w') as f:
        json.dump(report, f, indent=2)
    
    return filename

# Gerar relatório CSV
def generate_csv_report(ip_data):
    report_dir = 'reports'
    os.makedirs(report_dir, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"{report_dir}/report_{timestamp}.csv"
    
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'IP', 'Tentativas', 'Usuários', 'Severidade', 
            'Banido pelo fail2ban', 'Primeira Tentativa', 'Última Tentativa'
        ])
        
        for ip, data in sorted(ip_data.items(), key=lambda x: x[1]['count'], reverse=True):
            users = ', '.join(list(data['users'])[:5])
            first = data['timestamps'][0].strftime('%Y-%m-%d %H:%M:%S') if data['timestamps'] else 'N/A'
            last = data['timestamps'][-1].strftime('%Y-%m-%d %H:%M:%S') if data['timestamps'] else 'N/A'
            banned = 'SIM' if data.get('banned_by_f2b', False) else 'NÃO'
            
            writer.writerow([ip, data['count'], users, data['severity'], banned, first, last])
    
    return filename

# Exibir resultados
def display_results(ip_data, enumeration_ips, f2b_bans, distributed_attacks, config):
    threshold = config['thresholds']['failed_login_attempts']
    
    print("\n" + "="*75)
    print("SOC LOG ANALYZER v4.0 - INTEGRADO COM FAIL2BAN")
    print("="*75 + "\n")
    
    # Estatísticas do fail2ban
    currently_banned = get_currently_banned()
    
    print(f"🛡️  FAIL2BAN STATUS:")
    print(f"    Total de banimentos históricos: {len(f2b_bans)}")
    print(f"    IPs atualmente banidos: {len(currently_banned)}")
    if currently_banned:
        print(f"   └─ {', '.join(currently_banned)}")
    print()
    
    # Ataques distribuídos
    if distributed_attacks:
        print("🌐 ATAQUE DISTRIBUÍDO DETECTADO:")
        print("-" * 75)
        for attack in distributed_attacks:
            print(f"   ⚠️  {attack['ip_count']} IPs diferentes | "
                  f"{attack['attempt_count']} tentativas em 5 minutos")
            print(f"   └─ Início: {attack['start_time'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"   └─ IPs: {', '.join(attack['ips'][:5])}")
        print()
    
    # Análise por IP
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_ips = sorted(ip_data.items(), 
                       key=lambda x: (severity_order[x[1]['severity']], -x[1]['count']))
    
    stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'WHITELISTED': 0}
    
    print("📊 ANÁLISE POR IP:")
    print("-" * 75)
    
    for ip, data in sorted_ips:
        count = data['count']
        users = ', '.join(list(data['users'])[:3])
        if len(data['users']) > 3:
            users += f" (+{len(data['users'])-3})"
        
        severity = data['severity']
        
        # Marcadores
        f2b_marker = " 🛡️ BANIDO" if data.get('banned_by_f2b', False) else ""
        
        if ip in config['whitelist_ips']:
            status = "✅ PERMITIDO"
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
        
        print(f"{status} | IP: {ip:15} | Tent: {count:3} | Usuários: {users}{f2b_marker}")
    
    # Enumeração
    if enumeration_ips:
        print("\n" + "-" * 75)
        print("⚠️  ENUMERAÇÃO DE USUÁRIOS DETECTADA:")
        print("-" * 75)
        for enum in enumeration_ips:
            users_list = ', '.join(list(enum['users'])[:5])
            print(f"   IP: {enum['ip']:15} | {enum['count']} usuários: {users_list}")
    
    # Resumo
    print("\n" + "=" * 75)
    print(f"RESUMO:")
    print(f"   🔴 CRÍTICO:        {stats['CRITICAL']:2} IPs")
    print(f"   🟠 ALTO:            {stats['HIGH']:2} IPs")
    print(f"   🟡 MÉDIO:          {stats['MEDIUM']:2} IPs")
    print(f"   🟢 BAIXO:             {stats['LOW']:2} IPs")
    print(f"   ✅ PERMITIDO:     {stats['WHITELISTED']:2} IPs")
    print(f"\n    Total de IPs únicos: {len(ip_data)}")
    print(f"   🎯 IPs suspeitos (>={threshold} tentativas): {stats['CRITICAL'] + stats['HIGH'] + stats['MEDIUM']}")
    print(f"   🛡️  Proteção ativa: fail2ban HABILITADO")
    print("=" * 75 + "\n")

# Função principal
def main():
    print("🚀 Iniciando SOC Log Analyzer v4.0...\n")
    
    # Setup logging
    log_file = setup_logging()
    write_log(log_file, "=== SOC Log Analyzer v4.0 iniciado ===")
    
    # Carregar configurações
    config = load_config()
    print(f"Configurações carregadas")
    
    # Analisar logs do fail2ban
    print(f"Analisando logs do fail2ban...")
    f2b_bans = parse_fail2ban_logs()
    currently_banned = get_currently_banned()
    print(f"✅ {len(f2b_bans)} banimentos históricos encontrados")
    
    # Ler auth.log
    log_path = config['log_file']
    print(f"Lendo arquivo: {log_path}")
    log_lines = read_log_file(log_path)
    print(f"✅ {len(log_lines)} linhas lidas\n")
    
    # Analisar tentativas falhadas
    failed_attempts = parse_failed_attempts(log_lines)
    print(f"🔎 {len(failed_attempts)} tentativas falhadas detectadas")
    write_log(log_file, f"{len(failed_attempts)} tentativas falhadas detectadas")
    
    # Análise por IP
    ip_data = analyze_by_ip(failed_attempts, config)
    
    # Correlacionar com fail2ban
    correlate_data(ip_data, f2b_bans, currently_banned)
    
    # Detectar enumeração
    enumeration_ips = detect_user_enumeration(ip_data)
    if enumeration_ips:
        print(f"⚠️  {len(enumeration_ips)} IP(s) com enumeração de usuários")
    
    # Detectar ataques distribuídos
    distributed_attacks = detect_distributed_attack(ip_data)
    if distributed_attacks:
        print(f"🌐 {len(distributed_attacks)} ataque(s) distribuído(s) detectado(s)")
    
    # Gerar relatórios
    json_report = generate_json_report(ip_data, enumeration_ips, f2b_bans, distributed_attacks)
    csv_report = generate_csv_report(ip_data)
    
    write_log(log_file, f"Relatório JSON: {json_report}")
    write_log(log_file, f"Relatório CSV: {csv_report}")
    
    # Exibir resultados
    display_results(ip_data, enumeration_ips, f2b_bans, distributed_attacks, config)
    
    print(f"📄 Relatórios gerados:")
    print(f"   JSON: {json_report}")
    print(f"   CSV:  {csv_report}")
    print(f"   Log:  {log_file}\n")
    
    write_log(log_file, "=== Análise concluída ===")

if __name__ == "__main__":
    main()
