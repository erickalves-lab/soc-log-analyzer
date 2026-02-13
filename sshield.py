#!/usr/bin/env python3
"""
SSHield - Monitoramento contínuo de logs SSH
Detecta ataques, logins bem-sucedidos e gera alertas instantâneos
Integrado com VirusTotal + Geolocalização + Bloqueio Automático via Fail2Ban
"""

import time
import os
import json
import subprocess
import requests
from datetime import datetime
from collections import defaultdict
import re

class SOCMonitor:
    def __init__(self):
        self.config = self.load_config()
        self.log_file = self.config['log_file']
        self.alert_file = 'alerts/live_alerts.log'
        self.state_file = 'state/monitor_state.json'
        
        # Cache VirusTotal e Geolocalização
        self.vt_cache = {}
        self.geo_cache = {}
        
        # IPs bloqueados
        self.blocked_ips = set()
        
        # Criar diretórios
        os.makedirs('alerts', exist_ok=True)
        os.makedirs('state', exist_ok=True)
        
        # Limpar estado anterior
        if os.path.exists(self.state_file):
            os.remove(self.state_file)
        
        # Estado do monitor
        self.ip_attempts = defaultdict(lambda: {
            'failed_count': 0,
            'success_count': 0,
            'invalid_user_count': 0,
            'users': set(),
            'first_seen': None,
            'last_seen': None,
            'vt_checked': False,
            'vt_malicious': 0,
            'vt_categories': [],
            'vt_info_displayed': False,
            'geo_checked': False,
            'country': None,
            'city': None,
            'isp': None,
            'blocked': False
        })
        
        # Status
        vt_status = "✅ HABILITADO" if self.config.get('virustotal', {}).get('enabled', False) else "❌ DESABILITADO"
        
        print("🖲️  SSHield v6.0 iniciado")
        print(f"📂 Monitorando: {self.log_file}")
        print(f"🚨 Alertas em: {self.alert_file}")
        print(f"⏰ Threshold: {self.config['thresholds']['failed_login_attempts']} tentativas")
        print(f"🔍 VirusTotal: {vt_status}")
        print(f"🌍 Geolocalização: ✅ ATIVO")
        print(f"🛡️  Bloqueio automático: ✅ ATIVO")
        print(f"🔄 Modo: SESSÃO NOVA (contadores resetados)")
        print("\n" + "="*70)
        print("🔍 MONITORANDO AUTENTICAÇÕES SSH EM TEMPO REAL...")
        print("="*70 + "\n")
    
    def load_config(self):
        with open('config/config.json', 'r') as f:
            return json.load(f)
    
    def save_state(self):
        data = {}
        for ip, info in self.ip_attempts.items():
            data[ip] = {
                'failed_count': info['failed_count'],
                'success_count': info['success_count'],
                'invalid_user_count': info['invalid_user_count'],
                'users': list(info['users']),
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen'],
                'vt_checked': info['vt_checked'],
                'vt_malicious': info['vt_malicious'],
                'vt_categories': info['vt_categories'],
                'vt_info_displayed': info['vt_info_displayed'],
                'geo_checked': info['geo_checked'],
                'country': info['country'],
                'city': info['city'],
                'isp': info['isp'],
                'blocked': info['blocked']
            }
        
        with open(self.state_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def block_ip_iptables(self, ip, reason="Manual block"):
        try:
            check = subprocess.run(
                ['sudo', 'iptables', '-C', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True
            )
            
            if check.returncode == 0:
                return True
            
            subprocess.run(
                ['sudo', 'iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True
            )
            
            self.blocked_ips.add(ip)
            self.ip_attempts[ip]['blocked'] = True
            
            return True
            
        except:
            return False
    
    def get_geolocation(self, ip):
        """Obtém geolocalização do IP via ip-api.com"""
        
        # Verificar cache
        if ip in self.geo_cache:
            return self.geo_cache[ip]
        
        # IPs privados não têm geolocalização
        if ip.startswith(('192.168.', '10.', '172.16.', '127.')):
            result = {
                'country': 'LAN',
                'city': 'Local',
                'isp': 'Rede Privada'
            }
            self.geo_cache[ip] = result
            return result
        
        try:
            # API gratuita ip-api.com
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp,org"
            
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    result = {
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'XX'),
                        'city': data.get('city', 'Unknown'),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', '')
                    }
                    
                    self.geo_cache[ip] = result
                    return result
            
            return None
        
        except:
            return None
    
    def check_virustotal(self, ip):
        if not self.config.get('virustotal', {}).get('enabled', False):
            return None
        
        if ip in self.vt_cache:
            return self.vt_cache[ip]
        
        if ip.startswith(('192.168.', '10.', '172.16.', '127.')):
            return None
        
        try:
            api_key = self.config['virustotal']['api_key']
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                malicious_count = stats.get('malicious', 0)
                suspicious_count = stats.get('suspicious', 0)
                
                categories = data.get('data', {}).get('attributes', {}).get('categories', {})
                category_list = list(set(categories.values()))[:3]
                
                result = {
                    'malicious': malicious_count,
                    'suspicious': suspicious_count,
                    'categories': category_list,
                    'total_vendors': sum(stats.values())
                }
                
                self.vt_cache[ip] = result
                return result
            
            return None
        
        except:
            return None
    
    def write_to_alert_file(self, message):
        """Escreve no arquivo de alertas"""
        with open(self.alert_file, 'a') as f:
            f.write(message + '\n')
    
    def get_location_string(self, ip):
        """Retorna string formatada com localização"""
        data = self.ip_attempts[ip]
        
        if data['country']:
            city = data['city'] if data['city'] != 'Unknown' else ''
            country = data['country']
            
            if city:
                return f"📍 {city}, {country}"
            else:
                return f"📍 {country}"
        
        return ""
    
    def get_vt_info_string(self, ip):
        """Retorna string formatada com info VT"""
        data = self.ip_attempts[ip]
        
        if data['vt_malicious'] > 0:
            categories = ', '.join(data['vt_categories'][:2]) if data['vt_categories'] else 'N/A'
            return f"[VT: {data['vt_malicious']} malicious | {categories}]"
        
        return ""
    
    def check_ip_info_on_first_contact(self, ip):
        """Verifica VT e Geo na primeira vez que IP aparece"""
        
        # Geolocalização
        if not self.ip_attempts[ip]['geo_checked']:
            self.ip_attempts[ip]['geo_checked'] = True
            
            geo_result = self.get_geolocation(ip)
            
            if geo_result:
                self.ip_attempts[ip]['country'] = geo_result.get('country')
                self.ip_attempts[ip]['city'] = geo_result.get('city')
                self.ip_attempts[ip]['isp'] = geo_result.get('isp')
        
        # VirusTotal
        if self.ip_attempts[ip]['vt_checked']:
            return
        
        self.ip_attempts[ip]['vt_checked'] = True
        
        vt_result = self.check_virustotal(ip)
        
        if vt_result and 'error' not in vt_result:
            malicious = vt_result['malicious']
            suspicious = vt_result['suspicious']
            total = vt_result['total_vendors']
            categories = ', '.join(vt_result['categories']) if vt_result['categories'] else 'N/A'
            
            self.ip_attempts[ip]['vt_malicious'] = malicious
            self.ip_attempts[ip]['vt_categories'] = vt_result['categories']
            
            # Mostrar info VT
            if malicious > 0 or suspicious > 0:
                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                location = self.get_location_string(ip)
                msg = f"🔍 [{timestamp}] VirusTotal: IP {ip} {location} | {malicious}/{total} malicious, {suspicious} suspicious | Categorias: {categories}"
                print(f"\033[93m{msg}\033[0m")
                self.write_to_alert_file(msg)
                self.ip_attempts[ip]['vt_info_displayed'] = True
                
                # Bloqueio automático se >= 5 malicious
                if malicious >= 5:
                    msg_block = f"🚫 [{timestamp}] BLOQUEIO AUTOMÁTICO: IP {ip} {location} é malicioso conhecido (VT: {malicious} vendors)"
                    print(f"\033[91m{msg_block}\033[0m")
                    self.write_to_alert_file(msg_block)
                    
                    if self.block_ip_iptables(ip, f"VirusTotal: {malicious} malicious"):
                        msg_success = f"🛡️  [{timestamp}] IP {ip} bloqueado com sucesso via iptables"
                        print(f"\033[91m{msg_success}\033[0m")
                        self.write_to_alert_file(msg_success)
    
    def handle_failed_attempt(self, ip, username, timestamp_str):
        """Processa tentativa falhada"""
        
        # Atualizar contadores
        self.ip_attempts[ip]['failed_count'] += 1
        self.ip_attempts[ip]['users'].add(username)
        self.ip_attempts[ip]['last_seen'] = timestamp_str
        
        if not self.ip_attempts[ip]['first_seen']:
            self.ip_attempts[ip]['first_seen'] = timestamp_str
            # Verificar VT e Geo na primeira vez
            self.check_ip_info_on_first_contact(ip)
        
        count = self.ip_attempts[ip]['failed_count']
        
        # Verificar whitelist
        if ip in self.config['whitelist_ips']:
            return
        
        # LOG DE TODA TENTATIVA COM LOCALIZAÇÃO
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        location = self.get_location_string(ip)
        vt_info = self.get_vt_info_string(ip)
        
        msg = f"❌ [{timestamp}] Tentativa #{count} de login FALHADO do IP {ip} {location} (usuário: {username}) {vt_info}"
        print(msg)
        self.write_to_alert_file(msg)
        
        # Alertas especiais
        threshold = self.config['thresholds']['failed_login_attempts']
        
        # Threshold atingido
        if count == threshold:
            msg_threshold = f"⚠️  [{timestamp}] IP {ip} {location} atingiu THRESHOLD! {count} tentativas falhadas - fail2ban deve banir"
            print(f"\033[93m{msg_threshold}\033[0m")
            self.write_to_alert_file(msg_threshold)
            
            # Verificar fail2ban após 2 seg
            time.sleep(2)
            if self.check_fail2ban_status(ip):
                msg_banned = f"🚫 [{timestamp}] IP {ip} {location} BANIDO pelo fail2ban!"
                print(f"\033[91m{msg_banned}\033[0m")
                self.write_to_alert_file(msg_banned)
        
        # Enumeração
        num_users = len(self.ip_attempts[ip]['users'])
        if num_users >= 3 and count == num_users:
            msg_enum = f"⚠️  [{timestamp}] ENUMERAÇÃO: IP {ip} {location} testou {num_users} usuários diferentes: {', '.join(list(self.ip_attempts[ip]['users']))}"
            print(f"\033[93m{msg_enum}\033[0m")
            self.write_to_alert_file(msg_enum)
        
        # Ataque persistente
        if count > threshold * 2 and count % 10 == 0:
            msg_persist = f"🔥 [{timestamp}] ATAQUE PERSISTENTE: IP {ip} {location} - {count} tentativas e contando!"
            print(f"\033[91m{msg_persist}\033[0m")
            self.write_to_alert_file(msg_persist)
        
        # Salvar estado periodicamente
        if count % 5 == 0:
            self.save_state()
    
    def handle_invalid_user(self, ip, username, timestamp_str):
        """Processa tentativa com usuário inválido"""
        
        self.ip_attempts[ip]['invalid_user_count'] += 1
        self.ip_attempts[ip]['users'].add(username)
        self.ip_attempts[ip]['last_seen'] = timestamp_str
        
        if not self.ip_attempts[ip]['first_seen']:
            self.ip_attempts[ip]['first_seen'] = timestamp_str
            self.check_ip_info_on_first_contact(ip)
        
        count = self.ip_attempts[ip]['invalid_user_count']
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        location = self.get_location_string(ip)
        vt_info = self.get_vt_info_string(ip)
        
        msg = f"⚠️  [{timestamp}] Tentativa #{count} com USUÁRIO INVÁLIDO do IP {ip} {location} (usuário: {username}) {vt_info}"
        print(f"\033[93m{msg}\033[0m")
        self.write_to_alert_file(msg)
    
    def handle_successful_login(self, ip, username, timestamp_str):
        """Processa login bem-sucedido"""
        
        self.ip_attempts[ip]['success_count'] += 1
        self.ip_attempts[ip]['users'].add(username)
        self.ip_attempts[ip]['last_seen'] = timestamp_str
        
        if not self.ip_attempts[ip]['first_seen']:
            self.ip_attempts[ip]['first_seen'] = timestamp_str
            self.check_ip_info_on_first_contact(ip)
        
        count = self.ip_attempts[ip]['success_count']
        
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        location = self.get_location_string(ip)
        vt_info = self.get_vt_info_string(ip)
        
        # Verificar se é suspeito
        failed = self.ip_attempts[ip]['failed_count']
        
        if failed > 0:
            msg = f"⚠️  [{timestamp}] LOGIN BEM-SUCEDIDO do IP {ip} {location} (usuário: {username}) - ATENÇÃO: {failed} tentativas falhadas anteriores! {vt_info}"
            print(f"\033[93m{msg}\033[0m")
        else:
            msg = f"✅ [{timestamp}] Login bem-sucedido do IP {ip} {location} (usuário: {username}) {vt_info}"
            print(f"\033[92m{msg}\033[0m")
        
        self.write_to_alert_file(msg)
    
    def check_fail2ban_status(self, ip):
        try:
            result = subprocess.run(
                ['sudo', 'fail2ban-client', 'status', 'sshd'],
                capture_output=True,
                text=True,
                timeout=2
            )
            return ip in result.stdout
        except:
            return False
    
    def parse_log_line(self, line):
        """Extrai informações da linha de log"""
        
        timestamp_match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})', line)
        if not timestamp_match:
            return None
        
        timestamp = timestamp_match.group(1)
        
        # Failed password
        match = re.search(r'Failed password for (\w+) from ([\d.]+)', line)
        if match:
            return {
                'type': 'failed',
                'timestamp': timestamp,
                'username': match.group(1),
                'ip': match.group(2)
            }
        
        # Invalid user
        match = re.search(r'Invalid user (\w+) from ([\d.]+)', line)
        if match:
            return {
                'type': 'invalid_user',
                'timestamp': timestamp,
                'username': match.group(1),
                'ip': match.group(2)
            }
        
        # Accepted password
        match = re.search(r'Accepted password for (\w+) from ([\d.]+)', line)
        if match:
            return {
                'type': 'success',
                'timestamp': timestamp,
                'username': match.group(1),
                'ip': match.group(2)
            }
        
        # Accepted publickey
        match = re.search(r'Accepted publickey for (\w+) from ([\d.]+)', line)
        if match:
            return {
                'type': 'success_key',
                'timestamp': timestamp,
                'username': match.group(1),
                'ip': match.group(2)
            }
        
        return None
    
    def process_event(self, event):
        """Processa evento detectado"""
        
        event_type = event['type']
        ip = event['ip']
        username = event['username']
        timestamp = event['timestamp']
        
        if event_type == 'failed':
            self.handle_failed_attempt(ip, username, timestamp)
        
        elif event_type == 'invalid_user':
            self.handle_invalid_user(ip, username, timestamp)
        
        elif event_type in ['success', 'success_key']:
            self.handle_successful_login(ip, username, timestamp)
    
    def follow_log(self):
        """Monitora log em tempo real"""
        
        f = open(self.log_file, 'r')
        f.seek(0, 2)
        
        try:
            while True:
                line = f.readline()
                
                if not line:
                    time.sleep(0.5)
                    
                    try:
                        current_size = os.path.getsize(self.log_file)
                        current_pos = f.tell()
                        
                        if current_pos > current_size:
                            f.close()
                            f = open(self.log_file, 'r')
                            f.seek(0, 2)
                    except:
                        pass
                    
                    continue
                
                event = self.parse_log_line(line)
                
                if event:
                    self.process_event(event)
        
        finally:
            f.close()
    
    def run(self):
        """Inicia monitoramento contínuo"""
        try:
            self.follow_log()
        except KeyboardInterrupt:
            print("\n\n🛑 Monitor interrompido pelo usuário")
            self.save_state()
            
            print(f"\n💾 Estado salvo em: {self.state_file}")
            print(f"📊 Total de IPs monitorados: {len(self.ip_attempts)}")
            print(f"🛡️  IPs bloqueados pelo monitor: {len(self.blocked_ips)}")
            
            if self.ip_attempts:
                print("\n" + "="*80)
                print("📈 RESUMO DA SESSÃO:")
                print("="*80)
                
                for ip, data in sorted(self.ip_attempts.items(), 
                                      key=lambda x: x[1]['failed_count'], 
                                      reverse=True)[:15]:
                    
                    failed = data['failed_count']
                    success = data['success_count']
                    invalid = data['invalid_user_count']
                    users = len(data['users'])
                    
                    # Localização
                    if data['city'] and data['city'] != 'Unknown':
                        location = f"{data['city']}, {data['country']}"
                    elif data['country']:
                        location = data['country']
                    else:
                        location = "Unknown"
                    
                    vt = f"VT:{data['vt_malicious']}" if data['vt_malicious'] > 0 else ""
                    blocked = "🚫BLOQ" if data['blocked'] else ""
                    
                    print(f"{ip:15} {location:25} | ❌{failed:3} ✅{success:2} ⚠️{invalid:2} | {users} users | {vt:8} {blocked}")
                
                print("="*80)
            
            print("\n✅ Monitor encerrado com sucesso\n")

def main():
    monitor = SOCMonitor()
    monitor.run()

if __name__ == "__main__":
    main()
