#!/usr/bin/env python3
"""
SOC Monitor - Monitoramento contínuo de logs
Detecta ataques em tempo real e gera alertas instantâneos
"""

import time
import os
import json
import subprocess
from datetime import datetime
from collections import defaultdict
import re

class SOCMonitor:
    def __init__(self):
        self.config = self.load_config()
        self.log_file = self.config['log_file']
        self.alert_file = 'alerts/live_alerts.log'
        self.state_file = 'state/monitor_state.json'
        
        # Criar diretórios necessários
        os.makedirs('alerts', exist_ok=True)
        os.makedirs('state', exist_ok=True)
        
        # Estado do monitor (contador de tentativas por IP)
        self.ip_attempts = defaultdict(lambda: {
            'count': 0,
            'users': set(),
            'first_seen': None,
            'last_seen': None
        })
        
        # Carregar estado anterior (se existir)
        self.load_state()
        
        print("SOC Real-Time Monitor iniciado")
        print(f"Monitorando: {self.log_file}")
        print(f"Alertas em: {self.alert_file}")
        print(f"Threshold: {self.config['thresholds']['failed_login_attempts']} tentativas")
        print("\n" + "="*60)
        print("🔍 AGUARDANDO EVENTOS... (Ctrl+C para parar)")
        print("="*60 + "\n")
    
    def load_config(self):
        with open('config/config.json', 'r') as f:
            return json.load(f)
    
    def load_state(self):
        """Carrega estado anterior do monitor"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    # Reconstruir defaultdict
                    for ip, info in data.items():
                        self.ip_attempts[ip] = {
                            'count': info['count'],
                            'users': set(info['users']),
                            'first_seen': info['first_seen'],
                            'last_seen': info['last_seen']
                        }
                print(f"✅ Estado anterior carregado: {len(data)} IPs em memória")
            except:
                pass
    
    def save_state(self):
        """Salva estado atual do monitor"""
        data = {}
        for ip, info in self.ip_attempts.items():
            data[ip] = {
                'count': info['count'],
                'users': list(info['users']),
                'first_seen': info['first_seen'],
                'last_seen': info['last_seen']
            }
        
        with open(self.state_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def write_alert(self, severity, message):
        """Escreve alerta no arquivo e exibe no terminal"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        alert_line = f"[{timestamp}] [{severity}] {message}\n"
        
        # Escrever no arquivo
        with open(self.alert_file, 'a') as f:
            f.write(alert_line)
        
        # Exibir no terminal com cores
        color_map = {
            'CRÍTICO': '\033[91m🔴',  # Vermelho
            'ALTO': '\033[93m🟠',      # Amarelo
            'MÉDIO': '\033[94m🟡',    # Azul
            'INFO': '\033[92m🟢'       # Verde
        }
        
        color = color_map.get(severity, '')
        reset = '\033[0m'
        
        print(f"{color} [{timestamp}] [{severity}] {message}{reset}")
    
    def check_fail2ban_status(self, ip):
        """Verifica se IP foi banido pelo fail2ban"""
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
    
    def analyze_attempt(self, ip, username, timestamp_str):
        """Analisa tentativa falhada em tempo real"""
        threshold = self.config['thresholds']['failed_login_attempts']
        
        # Atualizar contador
        self.ip_attempts[ip]['count'] += 1
        self.ip_attempts[ip]['users'].add(username)
        self.ip_attempts[ip]['last_seen'] = timestamp_str
        
        if self.ip_attempts[ip]['first_seen'] is None:
            self.ip_attempts[ip]['first_seen'] = timestamp_str
        
        count = self.ip_attempts[ip]['count']
        num_users = len(self.ip_attempts[ip]['users'])
        
        # Verificar whitelist
        if ip in self.config['whitelist_ips']:
            if count == threshold:  # Alertar só uma vez
                self.write_alert('INFO', f"IP {ip} (WHITELIST) atingiu {count} tentativas")
            return
        
        # Detecção de padrões
        
        # Primeira tentativa
        if count == 1:
            self.write_alert('INFO', f"Nova origem detectada: {ip} (usuário: {username})")
        
        # Enumeração de usuários (3+ usuários diferentes)
        if num_users >= 3 and count == num_users:
            self.write_alert('HIGH', 
                f"ENUMERAÇÃO detectada! IP {ip} testou {num_users} usuários: {', '.join(list(self.ip_attempts[ip]['users']))}")
        
        # Atingiu metade do threshold
        if count == threshold // 2:
            self.write_alert('MEDIUM', 
                f"IP {ip} com {count} tentativas (usuário: {username})")
        
        # Atingiu threshold (provável bloqueio do fail2ban)
        if count == threshold:
            self.write_alert('HIGH', 
                f"⚠️  IP {ip} atingiu THRESHOLD! {count} tentativas falhadas")
            
            # Aguardar 2 segundos e verificar se foi banido
            time.sleep(2)
            if self.check_fail2ban_status(ip):
                self.write_alert('CRITICAL', 
                    f"🚫 IP {ip} BANIDO pelo fail2ban!")
        
        # Passou muito do threshold (possível ataque persistente)
        if count > threshold * 2:
            if count % 10 == 0:  # Alertar a cada 10 tentativas
                self.write_alert('CRITICAL', 
                    f"🔥 ATAQUE PERSISTENTE! IP {ip} - {count} tentativas e contando...")
        
        # Salvar estado periodicamente
        if count % 5 == 0:
            self.save_state()
    
    def parse_log_line(self, line):
        """Extrai informações de uma linha de log"""
        # Padrão: Failed password for USER from IP
        pattern = r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Failed password for (\w+) from ([\d.]+)'
        
        match = re.search(pattern, line)
        if match:
            timestamp = match.group(1)
            username = match.group(2)
            ip = match.group(3)
            return {
                'timestamp': timestamp,
                'username': username,
                'ip': ip
            }
        
        return None
    
    def follow_log(self):
        """Monitora log em tempo real (similar ao 'tail -f')"""
        # Abrir arquivo e ir para o final
        with open(self.log_file, 'r') as f:
            # Ir para o final do arquivo
            f.seek(0, 2)
            
            while True:
                line = f.readline()
                
                if not line:
                    # Não há novas linhas, aguardar
                    time.sleep(0.1)
                    continue
                
                # Analisar linha
                attempt = self.parse_log_line(line)
                
                if attempt:
                    self.analyze_attempt(
                        attempt['ip'],
                        attempt['username'],
                        attempt['timestamp']
                    )
    
    def run(self):
        """Inicia monitoramento contínuo"""
        try:
            self.follow_log()
        except KeyboardInterrupt:
            print("\n\n🛑 Monitor interrompido pelo usuário")
            self.save_state()
            print(f"💾 Estado salvo em: {self.state_file}")
            print(f"📊 Total de IPs monitorados: {len(self.ip_attempts)}")
            
            # Mostrar resumo
            if self.ip_attempts:
                print("\n📈 RESUMO DA SESSÃO:")
                print("-" * 60)
                for ip, data in sorted(self.ip_attempts.items(), 
                                      key=lambda x: x[1]['count'], 
                                      reverse=True)[:10]:
                    print(f"   {ip:15} - {data['count']:3} tentativas - "
                          f"{len(data['users'])} usuários")
                print("-" * 60)
            
            print("\n✅ Monitor encerrado com sucesso\n")

def main():
    monitor = SOCMonitor()
    monitor.run()

if __name__ == "__main__":
    main()
