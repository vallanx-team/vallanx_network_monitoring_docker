# Vallanx Network Monitor - Standalone Version

Eine vollständig eigenständige Python-Anwendung für Network Traffic Monitoring mit integriertem Vallanx Universal Blocklist Management.

## ✨ Features

### Eigenständig & Einfach
- **Eine einzige Python-Datei** - Alle Komponenten integriert
- **Keine externe Datenbank** - SQLite inklusive
- **Minimale Abhängigkeiten** - Nur Python-Pakete
- **Einfacher Start** - Ein Befehl genügt

### Vallanx Universal Blocklist
- Multi-Format Unterstützung (IP, Domain, URL, CIDR, etc.)
- 20+ Bedrohungskategorien
- 5-stufiges Severity-System
- Flexible Aktionen (Block, Monitor, Alert, etc.)
- Auto-Expiration & False-Positive Tracking

### Network Monitoring
- Real-time Packet Capture mit Scapy
- Automatische Protokollerkennung (TCP, UDP, DNS, ICMP)
- Traffic Direction Detection (Inbound/Outbound/Internal)
- WebSocket Dashboard für Live-Updates

### Web-Interface
- Real-time Dashboard
- Vallanx Blocklist Management
- Traffic Statistiken
- Threat Detection Alerts

## 🚀 Schnellstart

### 1. Voraussetzungen

- **Python 3.8+**
- **Root-Rechte** (für Packet Capture)
- Linux/macOS (Windows mit Anpassungen)

### 2. Installation

```bash
# Repository klonen oder herunterladen
git clone <repository-url>
cd vallnax_network_monitoring

# Dependencies installieren
pip3 install -r requirements-standalone.txt

# ODER: Vollständige requirements für erweiterte Features
pip3 install -r requirements.txt
```

### 3. Starten

**Einfachster Weg:**
```bash
sudo ./start.sh
```

Das Skript fragt nach:
- Network Interface (z.B. eth0, wlan0)
- Web Port (Standard: 5000)

**Manueller Start:**
```bash
sudo python3 standalone_monitor.py --interface eth0 --port 5000
```

**Mit Custom Data Directory:**
```bash
sudo python3 standalone_monitor.py \
    --interface eth0 \
    --port 5000 \
    --data-dir /var/lib/vallanx
```

### 4. Zugriff

Nach dem Start:
- **Web Dashboard**: http://localhost:5000
- **API Stats**: http://localhost:5000/api/stats
- **Vallanx API**: http://localhost:5000/api/vallanx/stats

## 📖 Verwendung

### Web Interface

Öffne http://localhost:5000 im Browser für:
- Live Traffic Monitoring
- Vallanx Blocklist Management
- Statistiken & Charts
- Threat Alerts

### API Endpoints

#### Stats abrufen
```bash
curl http://localhost:5000/api/stats
```

#### Vallanx Entry hinzufügen
```bash
curl -X POST http://localhost:5000/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.0.2.1",
    "type": "ip",
    "category": "malware",
    "severity": 5,
    "action": "block",
    "tags": ["example"]
  }'
```

#### Value überprüfen
```bash
curl -X POST http://localhost:5000/api/vallanx/check \
  -H "Content-Type: application/json" \
  -d '{"value": "192.0.2.1"}'
```

#### Statistiken
```bash
curl http://localhost:5000/api/vallanx/stats
```

#### Recent Packets
```bash
curl http://localhost:5000/api/packets/recent
```

### Kommandozeilen-Optionen

```bash
python3 standalone_monitor.py --help

Optionen:
  --interface INTERFACE  Network interface (default: eth0)
  --port PORT           Web interface port (default: 5000)
  --data-dir DIR        Data directory (default: ./data)
```

## 📁 Dateistruktur

Nach dem ersten Start:

```
vallnax_network_monitoring/
├── standalone_monitor.py          # Hauptanwendung (alles in einer Datei)
├── start.sh                       # Schnellstart-Skript
├── requirements-standalone.txt    # Minimale Dependencies
├── README-STANDALONE.md          # Diese Datei
├── data/                         # Automatisch erstellt
│   ├── network_monitor.db       # SQLite Datenbank
│   └── vallanx/                 # Vallanx Blocklists
│       ├── ip.json
│       ├── domain.json
│       └── ...
├── templates/                    # Web-Templates (optional)
└── static/                      # CSS/JS (optional)
```

## 🔧 Konfiguration

### Vallanx Blocklist

Einträge werden automatisch in JSON-Dateien gespeichert unter `data/vallanx/`.

**Manuelle Bearbeitung:**
```bash
# IP Blocklist anzeigen
cat data/vallanx/ip.json

# Domain Blocklist anzeigen
cat data/vallanx/domain.json
```

### Datenbank

SQLite-Datenbank unter `data/network_monitor.db`:
- `traffic_stats` - Traffic Logs
- `threats` - Detected Threats
- `blacklist` - Legacy Blacklist

**Datenbank ansehen:**
```bash
sqlite3 data/network_monitor.db "SELECT * FROM threats LIMIT 10;"
```

## 🛠️ Troubleshooting

### Problem: "Permission denied" beim Packet Capture

**Lösung:**
```bash
# Muss als Root laufen
sudo python3 standalone_monitor.py

# ODER: Capabilities setzen
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

### Problem: "Interface not found"

**Lösung:**
```bash
# Verfügbare Interfaces anzeigen
ip link show

# Oder
ifconfig

# Dann korrektes Interface verwenden
sudo python3 standalone_monitor.py --interface wlan0
```

### Problem: "Port already in use"

**Lösung:**
```bash
# Anderen Port verwenden
sudo python3 standalone_monitor.py --port 8080

# ODER: Prozess auf Port 5000 beenden
sudo lsof -ti:5000 | xargs kill
```

### Problem: Dependencies fehlen

**Lösung:**
```bash
# Dependencies installieren
pip3 install -r requirements-standalone.txt

# ODER: System-Pakete installieren (Ubuntu/Debian)
sudo apt-get install python3-pip python3-dev libpcap-dev
pip3 install -r requirements-standalone.txt
```

## 🔒 Sicherheit

### Best Practices

1. **Firewall konfigurieren**
```bash
# Port 5000 nur lokal zugänglich
sudo iptables -A INPUT -p tcp --dport 5000 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 5000 -j DROP
```

2. **Reverse Proxy verwenden** (für Production)
```nginx
# Nginx Reverse Proxy
server {
    listen 80;
    server_name monitor.example.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

3. **Logs regelmäßig rotieren**
```bash
# Logrotate config
cat > /etc/logrotate.d/vallanx <<EOF
/path/to/network_monitor.log {
    daily
    rotate 7
    compress
    missingok
    notifempty
}
EOF
```

## 📊 Performance

### Für hohe Traffic-Volumes

Die Standalone-Version ist optimiert für:
- Bis zu **10.000 Pakete/Sekunde**
- Bis zu **100.000 Blocklist-Einträge**
- Minimaler Memory Footprint (~100 MB)

**Optimierungen:**
- Fast Lookup Caches für IPs und Domains
- SQLite mit Indizes
- Deque für Recent Packets (max 100)

## 📝 Unterschiede zur Original-Version

### Standalone Version:
- ✅ Alles in einer Datei
- ✅ SQLite statt MySQL/PostgreSQL
- ✅ Keine Suricata-Abhängigkeit
- ✅ Einfacher Start
- ✅ Minimale Dependencies

### Original Version:
- MySQL/PostgreSQL Support
- Suricata IDS Integration
- Mehr Features
- Produktions-ready

## 🤝 Beitragen

Verbesserungen willkommen! Erstelle einen Pull Request oder Issue.

## 📄 Lizenz

MIT License - siehe LICENSE-Datei

## 💡 Beispiele

### Eigene Blocklist importieren

```python
import json

# IP-Liste erstellen
ips = ["192.0.2.1", "198.51.100.5", "203.0.113.10"]

for ip in ips:
    data = {
        "value": ip,
        "type": "ip",
        "category": "malware",
        "severity": 5,
        "action": "block"
    }

    # API Call
    import requests
    requests.post("http://localhost:5000/api/vallanx/add", json=data)
```

### Threat Feeds integrieren

```bash
#!/bin/bash
# Threat Feed importieren (z.B. von abuse.ch)

curl https://feodotracker.abuse.ch/downloads/ipblocklist.txt | \
while read ip; do
    [[ "$ip" =~ ^#.*$ ]] && continue  # Skip comments
    [[ -z "$ip" ]] && continue        # Skip empty lines

    curl -X POST http://localhost:5000/api/vallanx/add \
        -H "Content-Type: application/json" \
        -d "{\"value\":\"$ip\",\"type\":\"ip\",\"category\":\"malware\",\"severity\":4,\"action\":\"block\",\"source\":\"feodotracker\"}"
done
```

### Backup erstellen

```bash
#!/bin/bash
# Backup Script

BACKUP_DIR="/backup/vallanx/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Datenbank
cp data/network_monitor.db "$BACKUP_DIR/"

# Vallanx Lists
cp -r data/vallanx "$BACKUP_DIR/"

# Logs
cp network_monitor.log "$BACKUP_DIR/"

echo "Backup created at $BACKUP_DIR"
```

## 🆘 Support

Bei Problemen:
1. Logs prüfen: `tail -f network_monitor.log`
2. Debug Mode: `FLASK_DEBUG=1 sudo python3 standalone_monitor.py`
3. Issue erstellen mit Log-Ausgabe

---

**Happy Monitoring! 🚀**
