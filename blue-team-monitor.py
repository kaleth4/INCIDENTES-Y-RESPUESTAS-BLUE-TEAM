#!/usr/bin/env python3
"""
Automatización de Blue Team y Respuesta a Incidentes
Análisis de logs, forense de memoria y correlación de eventos
"""

import re
import json
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import argparse
import asyncio


@dataclass
class SecurityEvent:
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: Optional[str]
    user: Optional[str]
    action: str
    details: Dict[str, Any]
    raw_log: str


@dataclass
class Incident:
    id: str
    created_at: datetime
    events: List[SecurityEvent]
    severity: str
    status: str
    description: str
    indicators: List[str]


class LogAnalyzer:
    """Analizador de logs para detección de amenazas"""

    def __init__(self):
        self.threat_patterns = self._load_threat_patterns()
        self.events = []

    def _load_threat_patterns(self) -> List[Dict]:
        """Carga patrones de detección de amenazas"""
        return [
            {
                "id": "BT-001",
                "name": "Multiple Failed Logins",
                "pattern": r"Failed password|authentication failed",
                "severity": "medium",
                "category": "brute_force",
                "threshold": 5,
                "time_window": 300  # 5 minutos
            },
            {
                "id": "BT-002",
                "name": "Suspicious Process Execution",
                "pattern": r"bash -i|nc -e|python -c.*socket|curl.*\|.*bash",
                "severity": "critical",
                "category": "command_and_control",
                "threshold": 1,
                "time_window": 0
            },
            {
                "id": "BT-003",
                "name": "Privilege Escalation",
                "pattern": r"sudo.*-u.*root|sudo su|su root",
                "severity": "high",
                "category": "privilege_escalation",
                "threshold": 1,
                "time_window": 60
            },
            {
                "id": "BT-004",
                "name": "Data Exfiltration Attempt",
                "pattern": r"scp.*@.*:|rsync.*@.*:|curl.*-X POST.*http",
                "severity": "high",
                "category": "exfiltration",
                "threshold": 1,
                "time_window": 0
            },
            {
                "id": "BT-005",
                "name": "Persistence Mechanism",
                "pattern": r"crontab|systemctl.*enable|chmod.*\+s",
                "severity": "high",
                "category": "persistence",
                "threshold": 1,
                "time_window": 60
            },
            {
                "id": "BT-006",
                "name": "Lateral Movement",
                "pattern": r"ssh.*from|smbclient|psexec",
                "severity": "high",
                "category": "lateral_movement",
                "threshold": 3,
                "time_window": 300
            }
        ]

    def parse_syslog(self, log_line: str) -> Optional[SecurityEvent]:
        """Parsea una línea de syslog"""
        # Patrón syslog estándar
        pattern = r'(<\w+>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+):\s+(.*)'
        match = re.match(pattern, log_line)

        if not match:
            return None

        timestamp_str = match.group(2)
        hostname = match.group(3)
        process = match.group(4)
        message = match.group(5)

        # Parsear timestamp
        try:
            timestamp = datetime.strptime(
                f"{datetime.now().year} {timestamp_str}",
                "%Y %b %d %H:%M:%S"
            )
        except ValueError:
            timestamp = datetime.now()

        # Extraer IP
        ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_line)
        source_ip = ip_match.group(0) if ip_match else None

        # Extraer usuario
        user_match = re.search(r'user[\s=]+(\S+)|for (\S+) from', log_line)
        user = user_match.group(1) or user_match.group(2) if user_match else None

        return SecurityEvent(
            timestamp=timestamp,
            event_type="syslog",
            severity="info",
            source_ip=source_ip,
            user=user,
            action=process,
            details={"hostname": hostname, "process": process},
            raw_log=log_line
        )

    def parse_apache_log(self, log_line: str) -> Optional[SecurityEvent]:
        """Parsea logs de Apache"""
        # Formato Combined Log
        pattern = r'([\d.]+) - - \[(.*?)\] "(\w+) (.*?) (HTTP/[\d.]+)" (\d{3}) (\d+) "(.*?)" "(.*?)"'
        match = re.match(pattern, log_line)

        if not match:
            return None

        ip = match.group(1)
        timestamp_str = match.group(2)
        method = match.group(3)
        path = match.group(4)
        status = match.group(6)

        # Detectar actividad sospechosa en paths
        suspicious_patterns = ['../', 'etc/passwd', 'admin', 'wp-login', '.env']
        is_suspicious = any(p in path.lower() for p in suspicious_patterns)

        return SecurityEvent(
            timestamp=datetime.now(),
            event_type="http_access",
            severity="warning" if is_suspicious else "info",
            source_ip=ip,
            user=None,
            action=f"{method} {path}",
            details={
                "status_code": status,
                "suspicious": is_suspicious,
                "path": path
            },
            raw_log=log_line
        )

    def analyze_file(self, file_path: Path, log_type: str = "syslog") -> List[SecurityEvent]:
        """Analiza un archivo de logs completo"""
        events = []

        parser = self.parse_syslog if log_type == "syslog" else self.parse_apache_log

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                event = parser(line)
                if event:
                    events.append(event)

        self.events.extend(events)
        return events

    def correlate_events(self, events: List[SecurityEvent]) -> List[Incident]:
        """Correlaciona eventos para identificar incidentes"""
        incidents = []

        # Agrupar eventos por IP y patrón
        events_by_ip = defaultdict(list)
        for event in events:
            if event.source_ip:
                events_by_ip[event.source_ip].append(event)

        for ip, ip_events in events_by_ip.items():
            for pattern in self.threat_patterns:
                matched_events = []

                for event in ip_events:
                    if re.search(pattern["pattern"], event.raw_log, re.IGNORECASE):
                        matched_events.append(event)

                if len(matched_events) >= pattern["threshold"]:
                    # Verificar ventana temporal
                    if pattern["time_window"] > 0:
                        time_window = timedelta(seconds=pattern["time_window"])
                        first_event = matched_events[0].timestamp
                        last_event = matched_events[-1].timestamp

                        if (last_event - first_event) <= time_window:
                            incident = self._create_incident(
                                pattern, matched_events, ip
                            )
                            incidents.append(incident)
                    else:
                        incident = self._create_incident(
                            pattern, matched_events, ip
                        )
                        incidents.append(incident)

        return incidents

    def _create_incident(self, pattern: Dict, events: List[SecurityEvent],
                        ip: str) -> Incident:
        """Crea un objeto Incident a partir de eventos correlacionados"""
        incident_id = hashlib.md5(
            f"{pattern['id']}_{ip}_{events[0].timestamp}".encode()
        ).hexdigest()[:12]

        return Incident(
            id=incident_id,
            created_at=datetime.now(),
            events=events,
            severity=pattern["severity"],
            status="detected",
            description=f"{pattern['name']} desde {ip}",
            indicators=[ip, pattern["category"]]
        )


class MemoryForensics:
    """Análisis forense de volcados de memoria (integración con Volatility3)"""

    def __init__(self, memory_dump_path: str):
        self.memory_dump = Path(memory_dump_path)
        self.artifacts = []

    async def analyze_with_volatility(self) -> Dict[str, Any]:
        """Analiza memoria usando Volatility3"""
        print(f"🔬 Analizando volcado de memoria: {self.memory_dump}")

        # Comandos Volatility3
        commands = {
            "processes": "windows.pslist",
            "network": "windows.netstat",
            "registry": "windows.registry.hivelist",
            "malware": "windows.malfind"
        }

        results = {}

        for name, plugin in commands.items():
            print(f"  📊 Ejecutando plugin: {plugin}")

            # Simular ejecución (en producción, ejecutar vol real)
            results[name] = self._simulate_volatility_output(plugin)

        return results

    def _simulate_volatility_output(self, plugin: str) -> List[Dict]:
        """Simula output de Volatility para demostración"""
        if plugin == "windows.pslist":
            return [
                {"pid": 1234, "name": "svchost.exe", "ppid": 456, "suspicious": False},
                {"pid": 5678, "name": "notepad.exe", "ppid": 1234, "suspicious": False},
                {"pid": 9999, "name": "malware.exe", "ppid": 1, "suspicious": True,
                 "indicators": ["Parent Process ID anómalo", "Nombre sospechoso"]}
            ]
        elif plugin == "windows.netstat":
            return [
                {"local_addr": "192.168.1.100", "local_port": 80,
                 "remote_addr": "10.0.0.5", "remote_port": 4444,
                 "suspicious": True, "indicators": ["Puerto C&C conocido"]},
                {"local_addr": "192.168.1.100", "local_port": 443,
                 "remote_addr": "8.8.8.8", "remote_port": 443,
                 "suspicious": False}
            ]
        elif plugin == "windows.malfind":
            return [
                {"pid": 9999, "address": "0x7f123456000",
                 "indicators": ["MZ header en memoria", "Memoria ejecutable"]}
            ]
        else:
            return []

    def detect_malware(self, process_list: List[Dict]) -> List[Dict]:
        """Detecta procesos maliciosos basado en heurísticas"""
        suspicious = []

        for proc in process_list:
            if proc.get("suspicious"):
                suspicious.append(proc)
                continue

            # Heurísticas adicionales
            name = proc.get("name", "").lower()

            # Nombres sospechosos
            suspicious_names = ['mimikatz', 'mimilib', 'pwdump', 'fgdump',
                              'procdump', 'gsecdump', 'cache_dump']
            if any(s in name for s in suspicious_names):
                proc["suspicious"] = True
                proc["indicators"] = ["Nombre de herramienta de hacking conocida"]
                suspicious.append(proc)

            # PPID anómalos
            if proc.get("ppid") in [0, 1] and name not in ['system', 'smss.exe', 'csrss.exe']:
                proc["suspicious"] = True
                proc["indicators"] = ["PPID anómalo"]
                suspicious.append(proc)

        return suspicious


class IncidentResponse:
    """Orquestación de respuesta a incidentes"""

    def __init__(self):
        self.playbooks = self._load_playbooks()

    def _load_playbooks(self) -> Dict[str, Dict]:
        """Carga playbooks de respuesta"""
        return {
            "brute_force": {
                "name": "Brute Force Response",
                "steps": [
                    "Block source IP at firewall",
                    "Review authentication logs",
                    "Check for successful logins",
                    "Reset compromised accounts",
                    "Enable MFA if not already",
                    "Notify security team"
                ],
                "severity": "medium"
            },
            "malware": {
                "name": "Malware Response",
                "steps": [
                    "Isolate affected system",
                    "Capture memory dump",
                    "Block malicious IPs/domains",
                    "Scan with updated signatures",
                    "Remove malicious files",
                    "Restore from backup if needed",
                    "Document IOCs"
                ],
                "severity": "critical"
            },
            "data_exfiltration": {
                "name": "Data Exfiltration Response",
                "steps": [
                    "Block egress traffic",
                    "Identify data accessed",
                    "Capture network traffic",
                    "Notify legal/compliance",
                    "Preserve logs",
                    "Start forensic investigation"
                ],
                "severity": "critical"
            }
        }

    def get_response_plan(self, incident: Incident) -> Dict:
        """Obtiene plan de respuesta para un incidente"""
        category = incident.indicators[1] if len(incident.indicators) > 1 else "generic"

        playbook = self.playbooks.get(category, {
            "name": "Generic Response",
            "steps": ["Analyze incident", "Contain threat", "Eradicate", "Recover"],
            "severity": "medium"
        })

        return {
            "incident_id": incident.id,
            "playbook": playbook["name"],
            "severity": incident.severity,
            "steps": playbook["steps"],
            "estimated_time": "2-4 hours"
        }

    def generate_ioc_report(self, incidents: List[Incident]) -> Dict:
        """Genera reporte de Indicators of Compromise"""
        iocs = {
            "ips": set(),
            "domains": set(),
            "files": set(),
            "registry_keys": set()
        }

        for incident in incidents:
            for indicator in incident.indicators:
                if re.match(r'\d+\.\d+\.\d+\.\d+', indicator):
                    iocs["ips"].add(indicator)

        return {
            "generated_at": datetime.now().isoformat(),
            "total_incidents": len(incidents),
            "iocs": {k: list(v) for k, v in iocs.items()}
        }


def main():
    parser = argparse.ArgumentParser(
        description="Blue Team y Respuesta a Incidentes"
    )
    parser.add_argument("command", choices=["logs", "memory", "respond"],
                       help="Comando a ejecutar")
    parser.add_argument("--file", "-f", help="Archivo a analizar")
    parser.add_argument("--type", choices=["syslog", "apache"],
                       default="syslog", help="Tipo de log")
    parser.add_argument("--memory-dump", help="Ruta al volcado de memoria")

    args = parser.parse_args()

    if args.command == "logs":
        if not args.file:
            print("❌ Error: --file requerido para análisis de logs")
            return

        analyzer = LogAnalyzer()
        print(f"🔍 Analizando: {args.file}")

        events = analyzer.analyze_file(Path(args.file), args.type)
        print(f"✅ {len(events)} eventos parseados")

        incidents = analyzer.correlate_events(events)
        print(f"🚨 {len(incidents)} incidente(s) detectado(s)")

        for incident in incidents:
            print(f"\n  ID: {incident.id}")
            print(f"  Descripción: {incident.description}")
            print(f"  Severidad: {incident.severity}")
            print(f"  Eventos: {len(incident.events)}")

    elif args.command == "memory":
        if not args.memory_dump:
            print("❌ Error: --memory-dump requerido")
            return

        forensics = MemoryForensics(args.memory_dump)
        results = asyncio.run(forensics.analyze_with_volatility())

        print("\n📊 Resultados del análisis de memoria:")
        for category, data in results.items():
            print(f"\n{category.upper()}:")
            print(json.dumps(data, indent=2))

        if "processes" in results:
            malware = forensics.detect_malware(results["processes"])
            if malware:
                print(f"\n🚨 {len(malware)} proceso(s) malicioso(s) detectado(s):")
                for proc in malware:
                    print(f"  - {proc['name']} (PID: {proc['pid']})")

    elif args.command == "respond":
        print("🛡️ Sistema de Respuesta a Incidentes")
        print("Usar: --file para cargar incidentes y generar planes de respuesta")


if __name__ == "__main__":
    main()
