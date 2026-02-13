# 🖲️  SSHield - Proteção SSH & Inteligência de Ameaças

**Monitoramento de segurança SSH em tempo real com resposta automatizada a ameaças**

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-success.svg)]()

---

## 📋 Índice

- [Sobre o Projeto](#-sobre-o-projeto)
- [Funcionalidades](#-funcionalidades)
- [Arquitetura](#-arquitetura)
- [Instalação](#-instalação)
- [Configuração](#-configuração)
- [Uso](#-uso)
- [Exemplos de Saída](#-exemplos-de-saída)
- [Testes Realizados](#-testes-realizados)
- [Estrutura do Projeto](#-estrutura-do-projeto)
- [Roadmap](#-roadmap)
- [Autor](#-autor)
- [Licença](#-licença)

---

## 🎯 Sobre o Projeto

**SSHield** é uma ferramenta de monitoramento de segurança desenvolvida para ambientes SOC (Security Operations Center) que detecta e responde automaticamente a tentativas de invasão SSH.

O projeto integra múltiplas camadas de defesa, incluindo análise de logs em tempo real, integração com VirusTotal para threat intelligence, geolocalização de IPs atacantes e bloqueio automático de ameaças conhecidas.

### Desenvolvido para:
- ✅ Demonstração de habilidades em cibersegurança
- ✅ Ambiente de laboratório e aprendizado
- ✅ Portfólio profissional
- ✅ Preparação para carreira em SOC

---

## ⚡ Funcionalidades

### Detecção e Monitoramento
- 🔍 **Monitoramento em tempo real** - Detecta cada tentativa de autenticação instantaneamente
- 📊 **Múltiplos padrões de log** - Identifica logins falhados, usuários inválidos e sucessos
- 🌍 **Geolocalização de IPs** - Rastreia localização geográfica dos atacantes
- 🔎 **Integração VirusTotal** - Consulta reputação de IPs em bases de ameaças

### Detecção de Padrões Avançados
- 👤 **Enumeração de usuários** - Identifica tentativas de descoberta de contas
- 🔥 **Ataques persistentes** - Detecta brute-force continuado
- ⏰ **Análise temporal** - Identifica atividades fora do horário comercial
- 📈 **Correlação de eventos** - Relaciona múltiplas tentativas do mesmo IP

### Resposta Automatizada
- 🚫 **Bloqueio automático via iptables** - IPs maliciosos conhecidos bloqueados instantaneamente
- 🛡️ **Integração com fail2ban** - Dupla camada de proteção
- 📝 **Logs de auditoria completos** - Trilha detalhada para análise forense
- 💾 **Relatórios em múltiplos formatos** - JSON, CSV e TXT

---

## 🏗️ Arquitetura
```
┌─────────────────────────────────────────────────────────┐
│              SSHield - Arquitetura de Defesa            │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  🛡️ Camada 1: fail2ban (Defesa Imediata)                 │
│  └─ Bloqueio automático após 5 tentativas falhadas      │
│  └─ Proteção em tempo real                              │
│                                                         │
│  🔍 Camada 2: SSHield (Threat Intelligence)             │
│  ├─ Monitoramento contínuo de /var/log/auth.log         │
│  ├─ Consulta VirusTotal (reputação de IPs)              │
│  ├─ Geolocalização via ip-api.com                       │
│  ├─ Detecção de padrões avançados                       │
│  │  ├─ Enumeração de usuários                           │
│  │  ├─ Ataques distribuídos                             │
│  │  └─ Análise de horários                              │
│  └─ Bloqueio automático de IPs maliciosos               │
│                                                         │
│  📊 Camada 3: Logging & Reporting                       │
│  ├─ Logs de auditoria detalhados                        │
│  ├─ Alertas em tempo real                               │
│  └─ Relatórios executivos (JSON/CSV)                    │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📦 Instalação

### Pré-requisitos
- Ubuntu Server 20.04+ ou similar
- Python 3.8+
- Acesso sudo
- Conexão com internet

### Passo a Passo
```bash
# 1. Atualizar sistema
sudo apt update && sudo apt upgrade -y

# 2. Instalar dependências
sudo apt install fail2ban python3-pip git openssh-server -y

# 3. Instalar bibliotecas Python
pip3 install requests --break-system-packages

# 4. Clonar repositório
git clone https://github.com/erickalves-lab/sshield.git
cd sshield

# 5. Criar arquivo de configuração
cp config/config.example.json config/config.json

# 6. Editar configurações
nano config/config.json
# Configure sua chave de API do VirusTotal (opcional mas recomendado)
```

### Configurar fail2ban
```bash
# Criar configuração local do fail2ban
sudo nano /etc/fail2ban/jail.local
```

Cole o seguinte conteúdo:
```ini
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
banaction = iptables-multiport

[sshd]
enabled = true
port = ssh
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
```

Reinicie o fail2ban:
```bash
sudo systemctl restart fail2ban
sudo systemctl enable fail2ban
```

---

## ⚙️ Configuração

### Arquivo config/config.json
```json
{
  "thresholds": {
    "failed_login_attempts": 5,        // Tentativas antes de alertar
    "time_window_minutes": 10,         // Janela de tempo para contagem
    "business_hours_start": "08:00",   // Início horário comercial
    "business_hours_end": "18:00"      // Fim horário comercial
  },
  "whitelist_ips": [
    "127.0.0.1",                       // IPs confiáveis (não bloqueados)
    "192.168.1.100"                    // Adicione seus IPs aqui
  ],
  "log_file": "/var/log/auth.log",
  "virustotal": {
    "enabled": true,                   // Ativar integração VirusTotal
    "api_key": "SUA_CHAVE_AQUI"       // Obtenha em: virustotal.com/gui/join-us
  }
}
```

### Obter Chave VirusTotal (Gratuita)

1. Acesse: https://www.virustotal.com/gui/join-us
2. Crie conta gratuita
3. Acesse: https://www.virustotal.com/gui/my-apikey
4. Copie sua chave de API
5. Cole no arquivo `config/config.json`

**Limites da API gratuita:**
- 500 requisições/dia
- 4 requisições/minuto
- Suficiente para uso em laboratório

---

## 🚀 Uso

### Iniciar o Monitor
```bash
cd ~/sshield
sudo python3 sshield.py
```

### Saída Esperada
```
🖲️  SSHield v6.0 - Real-Time SSH Security Monitor
📂 Monitorando: /var/log/auth.log
🚨 Alertas em: alerts/live_alerts.log
⏰ Threshold: 5 tentativas
🔍 VirusTotal: ✅ HABILITADO
🌍 Geolocalização: ✅ ATIVO
🛡️  Bloqueio automático: ✅ ATIVO
🔄 Modo: SESSÃO NOVA (contadores resetados)

======================================================================
🔍 MONITORANDO AUTENTICAÇÕES SSH EM TEMPO REAL...
======================================================================
```

### Parar o Monitor

Pressione `Ctrl+C` para parar. Um resumo da sessão será exibido.

---

## 📊 Exemplos de Saída

### Tentativa Falhada (IP Local)
```
❌ [2026-02-10 19:15:23] Tentativa #1 de login FALHADO do IP 192.168.122.30 📍 Local, LAN (usuário: admin)
❌ [2026-02-10 19:15:25] Tentativa #2 de login FALHADO do IP 192.168.122.30 📍 Local, LAN (usuário: admin)
❌ [2026-02-10 19:15:27] Tentativa #3 de login FALHADO do IP 192.168.122.30 📍 Local, LAN (usuário: root)
```

### Ataque de IP Público Malicioso
```
❌ [2026-02-10 19:20:15] Tentativa #1 de login FALHADO do IP 45.142.212.61 📍 Moscow, Russia (usuário: root)

🔍 [2026-02-10 19:20:16] VirusTotal: IP 45.142.212.61 📍 Moscow, Russia | 15/94 malicious, 3 suspicious | Categorias: Spam, Bruteforce

🚫 [2026-02-10 19:20:16] BLOQUEIO AUTOMÁTICO: IP 45.142.212.61 📍 Moscow, Russia é malicioso conhecido (VT: 15 vendors)

🛡️  [2026-02-10 19:20:17] IP 45.142.212.61 bloqueado com sucesso via iptables
```

### Threshold Atingido (fail2ban)
```
❌ [2026-02-10 19:25:30] Tentativa #5 de login FALHADO do IP 185.220.101.5 📍 Berlin, Germany (usuário: admin)

⚠️  [2026-02-10 19:25:30] IP 185.220.101.5 📍 Berlin, Germany atingiu THRESHOLD! 5 tentativas falhadas - fail2ban deve banir

🚫 [2026-02-10 19:25:32] IP 185.220.101.5 📍 Berlin, Germany BANIDO pelo fail2ban!
```

### Enumeração de Usuários Detectada
```
⚠️  [2026-02-10 19:30:45] ENUMERAÇÃO: IP 203.0.113.45 📍 Singapore, Singapore testou 5 usuários diferentes: admin, root, ubuntu, user, test
```

### Login Bem-Sucedido Suspeito
```
⚠️  [2026-02-10 19:35:12] LOGIN BEM-SUCEDIDO do IP 198.51.100.23 📍 New York, United States (usuário: admin) - ATENÇÃO: 8 tentativas falhadas anteriores!
```

### Resumo ao Encerrar (Ctrl+C)
```
🛑 Monitor interrompido pelo usuário

💾 Estado salvo em: state/monitor_state.json
📊 Total de IPs monitorados: 5
🛡️  IPs bloqueados pelo monitor: 2

================================================================================
📈 RESUMO DA SESSÃO:
================================================================================
45.142.212.61   Moscow, Russia            | ❌  1 ✅ 0 ⚠️ 0 | 1 users | VT:15    🚫BLOQ
192.168.122.30  Local, LAN                | ❌ 28 ✅ 1 ⚠️ 0 | 3 users |          
185.220.101.5   Berlin, Germany           | ❌  5 ✅ 0 ⚠️ 0 | 1 users |          
203.0.113.45    Singapore, Singapore      | ❌  5 ✅ 0 ⚠️ 5 | 5 users |          
198.51.100.23   New York, United States   | ❌  8 ✅ 1 ⚠️ 0 | 1 users |          
================================================================================

✅ Monitor encerrado com sucesso
```

---

## 🧪 Testes Realizados

O SSHield foi testado contra ferramentas reais de pentest:

### Ferramentas Utilizadas
- ✅ **Hydra** - Brute-force SSH
- ✅ **Medusa** - Password spraying
- ✅ **Scripts customizados** - Rotação de IP via Tor/Proxychains
- ✅ **Enumeração manual** - Tentativas com múltiplos usuários

### Cenários Testados
1. **Ataque de força bruta simples** - 128 tentativas, bloqueio após 5 tentativas
2. **Enumeração de usuários** - Detecção de 4+ usuários diferentes testados
3. **Ataques persistentes** - Alertas a cada 10 tentativas após threshold
4. **IPs maliciosos conhecidos** - Bloqueio automático baseado em VirusTotal
5. **Logins bem-sucedidos suspeitos** - Alerta quando login ocorre após tentativas falhadas

### Resultados
- ✅ **100% de detecção** de tentativas falhadas
- ✅ **Bloqueio automático** em <2 segundos (IPs maliciosos conhecidos)
- ✅ **Integração perfeita** com fail2ban
- ✅ **Geolocalização precisa** para IPs públicos
- ✅ **Zero falsos positivos** em testes controlados

---

## 📁 Estrutura do Projeto
```
sshield/
├── sshield.py                    # Script principal de monitoramento
├── config/
│   ├── config.json              # Configurações (GITIGNORED - contém API keys)
│   └── config.example.json      # Template de configuração
├── logs/                        # Logs de auditoria do próprio SSHield
├── reports/                     # Relatórios gerados (JSON/CSV)
├── alerts/
│   └── live_alerts.log         # Alertas em tempo real
├── state/
│   └── monitor_state.json      # Estado atual do monitor
├── requirements.txt             # Dependências Python
├── README.md                    # Este arquivo
└── .gitignore                   # Arquivos ignorados pelo Git
```

---

## 🛡️ Recursos de Segurança

### Defesa em Camadas
1. **fail2ban** - Primeira linha de defesa (bloqueio após threshold)
2. **SSHield** - Camada de inteligência (VirusTotal + Geo + Padrões)
3. **iptables** - Bloqueio permanente de IPs maliciosos

### Threat Intelligence
- **VirusTotal API** - Consulta reputação em 94+ antivírus/vendors
- **Geolocalização** - Identifica origem geográfica dos ataques
- **Detecção de padrões** - Enumeração, brute-force, ataques distribuídos

### Auditoria e Compliance
- **Logs completos** - Trilha de auditoria para análise forense
- **Timestamps precisos** - Todos os eventos com data/hora
- **Relatórios estruturados** - Formato JSON/CSV para integração

---

## 🚧 Roadmap

### Versão 2.0 (Planejado)
- [ ] Dashboard web com visualização em tempo real
- [ ] Notificações via email/Telegram/Discord
- [ ] Integração com Elasticsearch/Kibana (SIEM)
- [ ] Machine Learning para detecção de anomalias

### Versão 3.0 (Futuro)
- [ ] Suporte multi-servidor (monitoramento centralizado)
- [ ] API REST para integração com outras ferramentas
- [ ] Deployment via Docker/Kubernetes
- [ ] Detecção de ataques DDoS SSH

---

## 👨‍💻 Autor

**Desenvolvido por:** [Erick Alves]  
**LinkedIn:** [https://www.linkedin.com/in/erick-alves-sec/]  

### Contexto
Este projeto foi desenvolvido como parte do meu portfólio de cibersegurança, demonstrando habilidades práticas em:
- Análise de logs e detecção de intrusão
- Automação com Python
- Integração de APIs (VirusTotal)
- Resposta a incidentes
- Defesa em profundidade
- Threat Intelligence

---

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo `LICENSE` para mais detalhes.
```
MIT License

Copyright (c) 2026 [Seu Nome]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## ⚠️ Aviso Legal

**Este projeto é destinado EXCLUSIVAMENTE para:**
- Fins educacionais
- Ambientes de laboratório controlados
- Monitoramento de sistemas próprios
- Demonstração de portfólio profissional

**Importante:**
- ✅ Sempre obtenha autorização antes de monitorar sistemas
- ✅ Use apenas em ambientes que você possui ou tem permissão
- ✅ Respeite leis de privacidade e regulamentações locais
- ❌ Não use para atividades maliciosas ou ilegais

O autor não se responsabiliza pelo uso indevido desta ferramenta.

---

**⭐ Se este projeto foi útil para você, considere dar uma estrela.**
