# 🛡️ Automatización de Blue Team y Respuesta a Incidentes

Sistema de análisis de logs, forense de memoria con Volatility3, y correlación de eventos para detección y respuesta de amenazas.

## ✨ Características

- **🔍 Análisis de Logs**: Parseo de syslog y Apache con detección de amenazas
- **🔗 Correlación de Eventos**: Identifica patrones de ataque en múltiples fuentes
- **🧠 Forense de Memoria**: Integración con Volatility3 para análisis de dumps
- **📋 Playbooks**: Respuesta automatizada basada en el tipo de incidente
- **🎯 IOC Extraction**: Extracción automática de Indicators of Compromise

## 🚀 Instalación

```bash
cd blue-team-respuesta-incidentes
pip install -r requirements.txt

# Instalar Volatility3 (opcional, para análisis de memoria)
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
pip install -r requirements.txt
```

## 📋 Requisitos

```
python 3.8+
volatility3 (opcional)
```

## 🎯 Uso

### Análisis de Logs

```bash
# Analizar syslog
python blue-team-monitor.py logs --type syslog -f /var/log/syslog

# Analizar logs de Apache
python blue-team-monitor.py logs --type apache -f /var/log/apache/access.log
```

### Análisis Forense de Memoria

```bash
python blue-team-monitor.py memory --memory-dump /path/to/memory.dmp
```

## 🔍 Detecciones Implementadas

| ID | Detección | Severidad | Categoría |
|----|-----------|-----------|-----------|
| BT-001 | Multiple Failed Logins | Medium | Brute Force |
| BT-002 | Suspicious Process Execution | Critical | C&C |
| BT-003 | Privilege Escalation | High | Privilege Escalation |
| BT-004 | Data Exfiltration Attempt | High | Exfiltration |
| BT-005 | Persistence Mechanism | High | Persistence |
| BT-006 | Lateral Movement | High | Lateral Movement |

## 📊 Formatos Soportados

### Syslog
```
Apr 15 14:30:45 server sshd[1234]: Failed password for user from 192.168.1.100 port 54321
```

### Apache Combined Log
```
192.168.1.100 - - [15/Apr/2024:14:30:45 +0000] "GET /admin/config.php HTTP/1.1" 404 123
```

## 📄 Ejemplo de Output

```
🔍 Analizando: /var/log/syslog
✅ 1543 eventos parseados
🚨 3 incidente(s) detectado(s)

  ID: abc123def456
  Descripción: Multiple Failed Logins desde 192.168.1.100
  Severidad: medium
  Eventos: 8

  ID: xyz789abc012
  Descripción: Suspicious Process Execution desde 192.168.1.100
  Severidad: critical
  Eventos: 2

📊 Resultados del análisis de memoria:

PROCESSES:
[
  {"pid": 1234, "name": "svchost.exe", "suspicious": false},
  {"pid": 9999, "name": "malware.exe", "suspicious": true,
   "indicators": ["Parent Process ID anómalo", "Nombre sospechoso"]}
]

🚨 1 proceso(s) malicioso(s) detectado(s):
  - malware.exe (PID: 9999)
```

## 🛠️ Playbooks de Respuesta

### Brute Force Response
1. Block source IP at firewall
2. Review authentication logs
3. Check for successful logins
4. Reset compromised accounts
5. Enable MFA if not already
6. Notify security team

### Malware Response
1. Isolate affected system
2. Capture memory dump
3. Block malicious IPs/domains
4. Scan with updated signatures
5. Remove malicious files
6. Restore from backup if needed
7. Document IOCs

## 🔧 Integración con SIEM

```python
from blue-team-monitor import LogAnalyzer, IncidentResponse

# Enviar incidentes a SIEM
analyzer = LogAnalyzer()
events = analyzer.analyze_file("/var/log/syslog")
incidents = analyzer.correlate_events(events)

# Generar IOCs para bloqueo
responder = IncidentResponse()
iocs = responder.generate_ioc_report(incidents)

# Enviar a firewall/EDR
for ip in iocs["ips"]:
    block_ip_at_firewall(ip)
```

## 📊 Reportes

El sistema genera:
- **Incident Report**: Detalles de cada incidente detectado
- **IOC Report**: Indicators of Compromise para bloqueo
- **Timeline**: Cronología de eventos correlacionados
- **Memory Analysis**: Resultados del análisis forense

## 🔒 Seguridad

- Los análisis se realizan offline cuando es posible
- Los volcados de memoria se manejan con confidencialidad
- Los IOCs se comparten de forma segura con equipos de seguridad

## 📄 Licencia

MIT License - Uso defensivo y educativo de seguridad.
