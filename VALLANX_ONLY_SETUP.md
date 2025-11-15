# 🚀 Network Monitor - Vallanx-Only Setup (OHNE Suricata)

## ✨ Was ist neu?

Dieses vereinfachte Setup entfernt **alle Suricata-Abhängigkeiten** und nutzt ausschließlich die **Vallanx Universal Blocklist** für:

- ✅ IP-Blocking
- ✅ Domain-Blocking
- ✅ URL-Filtering
- ✅ User-Agent Checking
- ✅ Threat Detection
- ✅ IDS-ähnliche Funktionen
- ✅ Automatische iptables-Integration

**Vorteile:**
- 🎯 Einfachere Installation (keine PPA-Probleme)
- ⚡ Schnellerer Docker Build
- 🪶 Kleineres Image (~500MB statt ~1.2GB)
- 🔧 Einfachere Wartung
- 🎨 Einheitliche Syntax über Vallanx

## 📋 Voraussetzungen

- Docker Desktop (Windows) oder Docker Engine (Linux)
- Docker Compose
- Mindestens 1GB RAM (statt 2GB)
- 5GB freier Speicher (statt 10GB)

## 🎯 Schnellstart (3 Minuten)

### Schritt 1: Dateien vorbereiten

```powershell
# Im Projektverzeichnis (C:\Repositories\sat_7_d)

# Verzeichnisse erstellen
New-Item -ItemType Directory -Path "templates","static" -Force

# Dateien verschieben
Copy-Item "index.html" "templates/" -Force
Copy-Item "style.css" "static/" -Force
Copy-Item "app.js" "static/" -Force

# dockerignore umbenennen
if (Test-Path "dockerignore") {
    Rename-Item "dockerignore" ".dockerignore" -Force
}

# Version-Zeile entfernen
$content = Get-Content "docker-compose.yaml"
if ($content[0] -match "^version:") {
    $content | Select-Object -Skip 1 | Set-Content "docker-compose.yaml"
}
```

### Schritt 2: Neue Dateien herunterladen

**Laden Sie diese 3 Dateien herunter und ersetzen Sie die alten:**

1. **Dockerfile** (Suricata-frei)
2. **docker-compose.yaml** (vereinfacht)
3. **docker-entrypoint.sh** (Vallanx-only)

### Schritt 3: .env konfigurieren

```powershell
# .env erstellen falls nicht vorhanden
if (-not (Test-Path ".env")) {
    Copy-Item ".env.example" ".env"
}

# Bearbeiten
notepad .env
```

**Minimale Änderungen:**
```bash
MYSQL_ROOT_PASSWORD=IhrSicheresPasswort123!
MYSQL_PASSWORD=IhrSicheresUserPasswort456!
MONITOR_INTERFACE=eth0  # Ihr Netzwerk-Interface
```

### Schritt 4: Build und Start

```powershell
# Build (sollte jetzt ohne Fehler durchlaufen)
docker-compose build

# Starten
docker-compose up -d

# Status prüfen
docker-compose ps

# Logs anschauen
docker-compose logs -f network-monitor
```

### Schritt 5: Zugriff

- **Web-Interface**: http://localhost:5000
- **Vallanx API**: http://localhost:8089
- **Vallanx Dashboard**: http://localhost:5000/vallanx

## 🎨 Vallanx Universal Blocklist Syntax

Die Vallanx Universal Blocklist ersetzt Suricata vollständig und bietet eine einfachere, einheitliche Syntax:

### Eintrag hinzufügen (via API)

```bash
# IP blockieren
curl -X POST http://localhost:8089/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.0.2.100",
    "type": "ip",
    "category": "malware",
    "severity": 5,
    "action": "block",
    "confidence": 0.95,
    "source": "manual",
    "tags": ["malicious", "c2"],
    "metadata": {"reason": "Command & Control Server"}
  }'

# Domain blockieren
curl -X POST http://localhost:8089/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "malicious-site.com",
    "type": "domain",
    "category": "phishing",
    "severity": 4,
    "action": "block"
  }'

# URL blockieren
curl -X POST http://localhost:8089/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "http://evil.com/malware.exe",
    "type": "url",
    "category": "malware",
    "severity": 5,
    "action": "block"
  }'

# CIDR-Block blockieren
curl -X POST http://localhost:8089/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "10.0.0.0/8",
    "type": "cidr",
    "category": "botnet",
    "severity": 4,
    "action": "block"
  }'
```

### Blocklist-Format (.vbx Datei)

```
# Vallanx Universal Blocklist Format
# Einfache, lesbare Syntax

# IP-Adresse blockieren
block ip 192.0.2.100 severity=5 category=malware tags=c2,botnet

# Domain blockieren
block domain malicious-site.com severity=4 category=phishing

# URL blockieren
block url http://evil.com/malware.exe severity=5 category=malware

# CIDR-Block
block cidr 10.0.0.0/8 severity=4 category=botnet

# Mit Ablaufdatum
block ip 192.0.2.50 severity=3 category=spam expire=2024-12-31T23:59:59

# Nur überwachen (nicht blockieren)
monitor ip 192.0.2.200 severity=2 category=suspicious

# Mit Metadaten
block ip 203.0.113.1 severity=5 category=malware metadata={"source":"threat_feed","first_seen":"2024-01-01"}
```

### Import von Blocklists

```bash
# Via API
curl -X POST http://localhost:8089/api/vallanx/import \
  -F "file=@threat-feed.vbx"

# Via Web-Interface
# http://localhost:5000/vallanx → Upload Button

# Via Container
docker cp my-blocklist.vbx network-monitor:/etc/vallanx/feeds/
docker-compose restart network-monitor
```

### Export von Blocklists

```bash
# Als Vallanx Format
curl http://localhost:8089/api/vallanx/export/vallanx > blocklist.vbx

# Als iptables Script
curl http://localhost:8089/api/vallanx/export/iptables > vallanx-iptables.sh
chmod +x vallanx-iptables.sh
./vallanx-iptables.sh

# Als Suricata Rules (falls benötigt)
curl http://localhost:8089/api/vallanx/export/suricata > vallanx.rules

# Als hosts File
curl http://localhost:8089/api/vallanx/export/hosts > vallanx-hosts

# Alle Formate (ZIP)
curl http://localhost:5000/api/vallanx/export-all -o vallanx-export.zip
```

## 🔧 Vallanx Konfiguration

### Kategorien

```
- malware      # Malware, Trojaner, Viren
- phishing     # Phishing-Websites
- botnet       # Botnet C&C Server
- exploit      # Exploit-Hosts
- spam         # Spam-Quellen
- ddos         # DDoS-Angreifer
- tracker      # Tracking/Werbung
- pup          # Potentiell unerwünschte Programme
- suspicious   # Verdächtige Aktivitäten
```

### Severity Levels

```
1 = Info        (nur logging)
2 = Low         (überwachen)
3 = Medium      (warnen)
4 = High        (blockieren)
5 = Critical    (sofort blockieren + Alarm)
```

### Actions

```
- block        # Blockieren
- monitor      # Nur überwachen/loggen
- alert        # Alarm auslösen
- redirect     # Zu anderer Seite umleiten
```

## 📊 Monitoring & Statistics

```bash
# Vallanx Statistiken
curl http://localhost:8089/api/vallanx/stats | jq

# Live-Blocks anzeigen
curl http://localhost:5000/api/vallanx/live-blocks | jq

# Letzte Threats
curl http://localhost:5000/api/threats | jq

# Netzwerk-Statistiken
curl http://localhost:5000/api/stats | jq
```

## 🐛 Troubleshooting

### Build schlägt fehl

```powershell
# Cache löschen und neu bauen
docker-compose build --no-cache

# Einzelne Schritte prüfen
docker-compose build --progress=plain
```

### Container startet nicht

```powershell
# Logs prüfen
docker-compose logs -f network-monitor

# In Container einsteigen
docker-compose exec network-monitor bash

# Vallanx manuell testen
python3 -c "from vallanx_blocklist_manager import VallanxBlocklistManager; vm = VallanxBlocklistManager('/etc/vallanx'); print(vm.get_statistics())"
```

### Keine Pakete werden erfasst

```powershell
# Netzwerk-Interface prüfen
docker-compose exec network-monitor ip link show

# Promiscuous Mode aktivieren
docker-compose exec network-monitor ip link set eth0 promisc on

# Test mit tcpdump
docker-compose exec network-monitor tcpdump -i eth0 -c 10
```

### Performance-Probleme

```bash
# In .env anpassen:
VALLANX_MAX_ENTRIES=100000  # Weniger Einträge
MAX_PACKET_QUEUE=5000       # Kleinere Queue
```

## 📈 Vergleich: Vorher vs. Nachher

| Feature | Mit Suricata | Nur Vallanx |
|---------|-------------|-------------|
| Build-Zeit | ~10 Minuten | ~3 Minuten |
| Image-Größe | ~1.2 GB | ~500 MB |
| RAM-Bedarf | ~2 GB | ~1 GB |
| Konfiguration | 2 Systeme | 1 System |
| Rule-Syntax | Suricata + Vallanx | Nur Vallanx |
| Installation | Komplex (PPA) | Einfach |
| Wartung | Aufwändig | Einfach |

## ✅ Was Vallanx bietet (statt Suricata)

- ✨ **Einheitliche Syntax** - Alle Rules in einem Format
- 🚀 **Einfacher Import/Export** - Zu/von allen Formaten
- 🔄 **Automatische Konvertierung** - iptables, hosts, etc.
- 📊 **Bessere Statistiken** - Detaillierte Analytics
- 🎯 **Flexible Kategorien** - Custom Categories möglich
- ⚡ **Schnellere Updates** - Keine Rule-Kompilierung
- 🔧 **API-First** - Alles über REST API steuerbar
- 🌐 **Multi-Format Support** - Import von verschiedenen Feeds

## 🎓 Beispiel-Workflows

### 1. Threat Feed importieren

```bash
# Feed herunterladen
wget https://example.com/threat-feed.txt

# In Vallanx Format konvertieren
# (Vallanx kann viele Formate direkt importieren)

# Importieren
curl -X POST http://localhost:8089/api/vallanx/import \
  -F "file=@threat-feed.txt" \
  -F "format=plaintext" \
  -F "type=ip"
```

### 2. Eigene Blocklist erstellen

```bash
# blocklist.vbx erstellen
cat > myblocklist.vbx << 'EOF'
# Meine Blocklist
block ip 192.0.2.1 severity=5 category=malware
block domain evil.com severity=5 category=phishing
block cidr 10.0.0.0/8 severity=4 category=private
EOF

# Importieren
docker cp myblocklist.vbx network-monitor:/etc/vallanx/feeds/
docker-compose restart network-monitor
```

### 3. Auto-Block aktivieren

```bash
# In .env:
AUTO_BLOCK_ENABLED=true
VALLANX_AUTO_BLOCK=true
VALLANX_CONFIDENCE_THRESHOLD=0.7  # Nur >= 70% Confidence blockieren

# Restart
docker-compose restart network-monitor
```

## 🔗 Nützliche Links

- **Vallanx Syntax**: Siehe vallanx-blocklist-manager.py
- **API-Dokumentation**: http://localhost:5000/api/docs
- **Dashboard**: http://localhost:5000/vallanx
- **Statistiken**: http://localhost:8089/api/vallanx/stats

---

**Sie haben jetzt ein schlankes, leistungsstarkes Netzwerk-Monitoring-Tool mit der Vallanx Universal Blocklist! 🎉**
