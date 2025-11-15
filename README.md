# Vallanx Universal Blocklist System

Ein umfassendes Network Traffic Monitoring System mit integriertem Vallanx Universal Blocklist Management für erweiterte Bedrohungsabwehr.

## 🚀 Features

### Vallanx Universal Blocklist
- **Multi-Format Unterstützung**: IP, Domain, URL, Email, Hash, CIDR, ASN, Regex, Port, User-Agent, JA3, SSL-Fingerprints
- **Threat Categories**: 20+ vordefinierte Bedrohungskategorien (Malware, Phishing, Ransomware, Botnet, C2, etc.)
- **Severity Levels**: 5-stufiges Severity-System (Critical, High, Medium, Low, Info)
- **Flexible Actions**: Block, Allow, Monitor, Redirect, Quarantine, Alert, Log, Rate Limit, Challenge, Sandbox
- **Auto-Expiration**: Automatisches Entfernen veralteter Einträge
- **False Positive Handling**: Automatisches Tracking und Entfernung bei zu vielen Fehlmeldungen

### Network Monitoring
- **Real-time Packet Capture**: Echtzeit-Überwachung mit Scapy
- **Suricata IDS Integration**: Vollständige Integration mit Suricata für IDS/IPS
- **Protocol Analysis**: Automatische Erkennung und Analyse von TCP, UDP, DNS, HTTP
- **Traffic Direction Detection**: Intelligent Inbound/Outbound/Internal Traffic Classification
- **WebSocket Dashboard**: Real-time Updates über WebSocket

### Export-Formate
- **Suricata Rules**: Native Suricata-Regeln für IDS/IPS
- **iptables**: Linux Firewall-Regeln
- **Nginx**: Nginx deny-Direktiven
- **BIND RPZ**: DNS Response Policy Zones
- **JSON**: Strukturierte Daten für API-Integration
- **Native Vallanx (.vbx)**: Eigenes Format für Backup/Restore

## 📋 Systemanforderungen

### Minimum
- **OS**: Ubuntu 20.04+ / Debian 11+ / CentOS 8+
- **Python**: 3.8 oder höher
- **RAM**: 2 GB
- **Disk**: 10 GB freier Speicher
- **Network**: Zugriff auf zu überwachendes Interface

### Empfohlen
- **OS**: Ubuntu 22.04 LTS
- **Python**: 3.10+
- **RAM**: 4 GB
- **Disk**: 20 GB (SSD)
- **CPU**: 2+ Cores

### Erforderliche Berechtigungen
- Root-Zugriff für Packet Capture
- Schreibrechte in `/etc/vallanx` und `/var/log/network-monitor`

## 🔧 Installation

### Schnellinstallation (empfohlen)

```bash
# Repository klonen oder Dateien herunterladen
git clone https://github.com/yourusername/vallanx-network-monitor.git
cd vallanx-network-monitor

# Installation mit Setup-Script
sudo chmod +x install.sh
sudo ./install.sh
```

### Manuelle Installation

#### 1. System-Abhängigkeiten installieren

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
    python3 python3-pip python3-dev \
    build-essential libssl-dev libffi-dev \
    libpcap-dev tcpdump net-tools \
    mysql-client postgresql-client sqlite3

# Optional: Suricata IDS
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install -y suricata suricata-update
```

#### 2. Python-Abhängigkeiten installieren

```bash
sudo pip3 install -r requirements.txt
```

#### 3. Verzeichnisse erstellen

```bash
sudo mkdir -p /etc/vallanx
sudo mkdir -p /var/log/network-monitor
sudo mkdir -p /var/lib/network-monitor
sudo mkdir -p /var/backups/network-monitor
```

#### 4. Konfigurationsdateien kopieren

```bash
# Vallanx Blocklist Manager
sudo cp vallanx_blocklist_manager.py /opt/network-monitor/

# Network Monitor
sudo cp vallanx_integrated_network_monitor.py /opt/network-monitor/

# Datenbank-Credentials
sudo cp db-credentials.json /etc/network-monitor/
sudo chmod 600 /etc/network-monitor/db-credentials.json
```

#### 5. Datenbank einrichten

**MySQL:**
```sql
CREATE DATABASE network_monitor;
CREATE USER 'monitor_user'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON network_monitor.* TO 'monitor_user'@'localhost';
FLUSH PRIVILEGES;
```

**PostgreSQL:**
```sql
CREATE DATABASE network_monitor;
CREATE USER monitor_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE network_monitor TO monitor_user;
```

**SQLite (Fallback):**
```bash
# Automatisch, keine Konfiguration erforderlich
```

#### 6. Datenbank-Credentials konfigurieren

Bearbeite `/etc/network-monitor/db-credentials.json`:

```json
{
    "type": "mysql",
    "host": "localhost",
    "port": 3306,
    "user": "monitor_user",
    "password": "secure_password",
    "database": "network_monitor",
    "ssl": {
        "enabled": false
    },
    "pool_size": 5
}
```

## 🚀 Verwendung

### Als Systemd Service

```bash
# Service erstellen
sudo systemctl enable network-monitor
sudo systemctl start network-monitor

# Status prüfen
sudo systemctl status network-monitor

# Logs anzeigen
sudo journalctl -u network-monitor -f
```

### Manueller Start

```bash
# Als Root ausführen (erforderlich für Packet Capture)
sudo python3 /opt/network-monitor/vallanx_integrated_network_monitor.py
```

### Web-Interface

Nach dem Start ist das Dashboard verfügbar unter:
- **URL**: `http://<server-ip>:5000`
- **WebSocket**: Port 5000

## 📚 API-Dokumentation

### Vallanx Blocklist Management

#### Eintrag hinzufügen
```bash
curl -X POST http://localhost:5000/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.0.2.1",
    "type": "ip",
    "category": "malware",
    "severity": 5,
    "action": "block",
    "tags": ["zeus", "trojan"],
    "metadata": {"source": "threatfeed1"}
  }'
```

#### Eintrag prüfen
```bash
curl -X POST http://localhost:5000/api/vallanx/check \
  -H "Content-Type: application/json" \
  -d '{"value": "192.0.2.1"}'
```

#### Statistiken abrufen
```bash
curl http://localhost:5000/api/vallanx/stats
```

#### Export (Suricata Rules)
```bash
curl http://localhost:5000/api/vallanx/export/suricata > vallanx.rules
```

#### Export (iptables)
```bash
curl http://localhost:5000/api/vallanx/export/iptables > vallanx-iptables.sh
chmod +x vallanx-iptables.sh
```

#### Bulk Import
```bash
curl -X POST http://localhost:5000/api/vallanx/bulk-add \
  -H "Content-Type: application/json" \
  -d '{
    "entries": [
      {"value": "evil1.com", "type": "domain", "category": "phishing", "severity": 4},
      {"value": "203.0.113.0/24", "type": "cidr", "category": "botnet", "severity": 5}
    ]
  }'
```

### Blacklist/Whitelist API (Legacy)

#### Blacklist abrufen
```bash
curl http://localhost:5000/api/blacklist
```

#### IP zur Blacklist hinzufügen
```bash
curl -X POST http://localhost:5000/api/blacklist/add \
  -H "Content-Type: application/json" \
  -d '{"ip": "192.0.2.1"}'
```

#### Domain zur Blacklist hinzufügen
```bash
curl -X POST http://localhost:5000/api/blacklist/add \
  -H "Content-Type: application/json" \
  -d '{"domain": "evil.com"}'
```

## 🗂️ Vallanx Format Specification

### Native Vallanx Format (.vbx)

```
# Vallanx Universal Blocklist Format
# Format: type:value|category|severity|action|tags|metadata

# Beispiele:
ip:192.0.2.1|malware|5|block|zeus,trojan|{"source":"threatfeed1"}
domain:evil.com|phishing|4|block|credential_harvesting|{"target":"banking"}
cidr:192.0.2.0/24|botnet|5|block|mirai|{"country":"XX"}
url:http://evil.com/malware.exe|malware|5|block|dropper|{"md5":"abc123"}
hash:d41d8cd98f00b204e9800998ecf8427e|malware|5|block|ransomware|{"family":"wannacry"}
```

### Unterstützte Typen

| Typ | Beschreibung | Beispiel |
|-----|--------------|----------|
| `ip` | IPv4/IPv6 Adresse | `192.0.2.1` |
| `cidr` | IP-Netzwerk | `192.0.2.0/24` |
| `domain` | Domain-Name | `evil.com` |
| `wildcard` | Wildcard-Domain | `*.evil.com` |
| `url` | Vollständige URL | `http://evil.com/path` |
| `email` | E-Mail-Adresse | `spammer@evil.com` |
| `hash` | File Hash (MD5/SHA1/SHA256/SHA512) | `d41d8cd98f00...` |
| `asn` | Autonomous System Number | `AS12345` |
| `port` | TCP/UDP Port | `4444` |
| `user_agent` | HTTP User-Agent | `BadBot/1.0` |
| `regex` | Regular Expression | `.*\.exe$` |
| `ja3` | JA3 TLS Fingerprint | `769,47-53,0-35-16...` |
| `ssl_fingerprint` | SSL Certificate Fingerprint | `aa:bb:cc:dd:ee:ff` |

### Kategorien

| Kategorie | Beschreibung |
|-----------|--------------|
| `malware` | Malware Distribution |
| `phishing` | Phishing/Credential Harvesting |
| `ransomware` | Ransomware |
| `botnet` | Botnet Infrastructure |
| `command_control` | C2 Server |
| `cryptominer` | Cryptomining |
| `exploit` | Exploit Attempts |
| `spam` | Spam/Unsolicited Email |
| `scam` | Scam/Fraud |
| `pup` | Potentially Unwanted Program |
| `adware` | Adware |
| `tracking` | Tracking/Analytics |
| `pornography` | Adult Content |
| `gambling` | Gambling |
| `piracy` | Pirated Content |
| `drugs` | Drug-Related |
| `violence` | Violence/Gore |
| `hate_speech` | Hate Speech |
| `ddos` | DDoS Attack |
| `apt` | Advanced Persistent Threat |

## 🔒 Security Best Practices

### 1. Datenbank-Sicherheit
- Verwende starke Passwörter (min. 16 Zeichen)
- Aktiviere SSL/TLS für Datenbankverbindungen
- Begrenze Datenbankzugriff auf localhost
- Regelmäßige Backups

### 2. Netzwerk-Sicherheit
- Firewall-Regeln für Port 5000
- Reverse Proxy (Nginx/Apache) mit SSL
- Rate Limiting implementieren
- IP-Whitelisting für Admin-Interface

### 3. System-Härtung
- Regelmäßige Updates
- Minimal-Installation (nur erforderliche Pakete)
- SELinux/AppArmor aktivieren
- Log-Rotation konfigurieren

### 4. Vallanx-Sicherheit
- Regelmäßige Cleanup-Jobs
- Validierung aller Einträge
- False-Positive Monitoring
- Backup der Blocklists

## 📊 Performance Tuning

### Für hohe Traffic-Volumes

```python
# In vallanx_blocklist_manager.py
class VallanxBlocklistManager:
    def __init__(self, base_path: str = '/etc/vallanx'):
        # Erhöhe Cache-Größen
        self.cache_ttl = 600  # 10 Minuten
        
        # Optimiere Datenstrukturen
        self.use_bloom_filter = True  # Für sehr große Listen
```

### Datenbank-Optimierung

```sql
-- MySQL Indizes
CREATE INDEX idx_src_ip_timestamp ON traffic_stats(src_ip, timestamp);
CREATE INDEX idx_severity ON suricata_alerts(severity, alert_time);

-- Query-Cache aktivieren
SET GLOBAL query_cache_size = 67108864;  -- 64MB
SET GLOBAL query_cache_type = 1;
```

## 🐛 Troubleshooting

### Problem: Packet Capture funktioniert nicht

**Lösung:**
```bash
# Prüfe Berechtigungen
sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/python3

# Oder als Root ausführen
sudo python3 vallanx_integrated_network_monitor.py
```

### Problem: Datenbank-Verbindungsfehler

**Lösung:**
```bash
# Prüfe Datenbank-Service
sudo systemctl status mysql

# Teste Verbindung
mysql -u monitor_user -p -h localhost network_monitor

# Prüfe Credentials
cat /etc/network-monitor/db-credentials.json
```

### Problem: Vallanx Rules werden nicht geladen

**Lösung:**
```bash
# Prüfe Verzeichnisrechte
ls -la /etc/vallanx/

# Prüfe Log
tail -f /var/log/network-monitor/network_monitor.log

# Manuelles Neuladen
curl -X POST http://localhost:5000/api/vallanx/cleanup
```

### Problem: High CPU Usage

**Lösung:**
```python
# Reduziere Packet Capture Rate
def packet_callback(self, packet):
    if random.random() > 0.1:  # Sample 10%
        return
    # ... rest of processing
```

## 📈 Monitoring & Metrics

### Prometheus Integration

```python
from prometheus_client import Counter, Histogram, Gauge

# Metrics definieren
packets_processed = Counter('packets_processed_total', 'Total packets processed')
blocked_ips = Gauge('blocked_ips_current', 'Currently blocked IPs')
vallanx_checks = Histogram('vallanx_check_duration_seconds', 'Vallanx check duration')
```

### Log-Aggregation

```bash
# Mit ELK Stack
# Logstash Config
input {
  file {
    path => "/var/log/network-monitor/*.log"
    type => "network-monitor"
  }
}

filter {
  json {
    source => "message"
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "network-monitor-%{+YYYY.MM.dd}"
  }
}
```

## 🤝 Contributing

Beiträge sind willkommen! Bitte beachte:

1. Fork das Repository
2. Erstelle einen Feature-Branch (`git checkout -b feature/AmazingFeature`)
3. Commit deine Änderungen (`git commit -m 'Add AmazingFeature'`)
4. Push zum Branch (`git push origin feature/AmazingFeature`)
5. Öffne einen Pull Request

## 📝 License

Dieses Projekt ist unter der MIT License lizenziert - siehe [LICENSE](LICENSE) Datei für Details.

## 👥 Authors

- **Dein Name** - *Initial work* - [GitHub](https://github.com/yourusername)

## 🙏 Acknowledgments

- Suricata IDS/IPS Team
- Scapy Community
- Flask & SocketIO Entwickler
- Open Source Threat Intelligence Feeds

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/yourusername/vallanx-network-monitor/issues)
- **Email**: support@example.com
- **Dokumentation**: [Wiki](https://github.com/yourusername/vallanx-network-monitor/wiki)

## 🗺️ Roadmap

### Version 2.0 (geplant)
- [ ] Machine Learning basierte Anomalie-Erkennung
- [ ] Multi-Tenant Support
- [ ] GraphQL API
- [ ] Kubernetes Deployment
- [ ] GeoIP-basierte Filterung
- [ ] Advanced Reporting Dashboard
- [ ] Integration mit SIEM-Systemen
- [ ] Distributed Deployment Support

### Version 1.5 (in Entwicklung)
- [ ] REST API v2
- [ ] Enhanced Web Dashboard
- [ ] Docker Container
- [ ] Automated Testing Suite
- [ ] Performance Optimizations

---

**⚠️ Wichtiger Hinweis**: Dieses System sollte nur in autorisierten Netzwerken verwendet werden. Stelle sicher, dass du alle rechtlichen Anforderungen und Compliance-Richtlinien einhältst.
