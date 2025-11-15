# Network Monitor mit Vallanx - Schnellstart-Anleitung

## 🚀 Schnellstart (5 Minuten)

### Voraussetzungen
- Docker Engine 20.10+ oder Docker Desktop
- Docker Compose 2.0+
- Linux-System (empfohlen) oder macOS/Windows mit Docker Desktop
- Mindestens 2GB RAM
- 10GB freier Festplattenspeicher

### Installation in 4 Schritten

#### 1. Projekt-Dateien vorbereiten
```bash
# Verzeichnis erstellen
mkdir network-monitor && cd network-monitor

# Alle bereitgestellten Dateien in dieses Verzeichnis kopieren:
# - Dockerfile
# - docker-compose.yaml
# - docker-entrypoint.sh
# - requirements.txt
# - .env.example
# - .dockerignore
# - Makefile
# - config/mysql-init.sql
# - Ihre Python-Dateien (network_monitor.py, vallanx_blocklist_manager.py, etc.)
```

#### 2. Konfiguration anpassen
```bash
# Umgebungsvariablen kopieren
cp .env.example .env

# WICHTIG: Passwörter ändern!
nano .env
```

**Minimale Änderungen in .env:**
```bash
MYSQL_ROOT_PASSWORD=IhrSicheresRootPasswort2024!
MYSQL_PASSWORD=IhrSicheresUserPasswort2024!
MONITOR_INTERFACE=eth0  # Ihr Netzwerk-Interface
```

#### 3. Starten
```bash
# Mit Makefile (empfohlen)
make install

# ODER manuell
docker-compose build
docker-compose up -d
```

#### 4. Zugreifen
- **Web-Interface**: http://localhost:5000
- **Vallanx API**: http://localhost:8089
- **MySQL**: localhost:3306

## 🎯 Wichtige Befehle

### Mit Makefile
```bash
make help           # Alle verfügbaren Befehle anzeigen
make up             # Services starten
make down           # Services stoppen
make logs           # Logs anzeigen
make status         # Status prüfen
make backup         # Backup erstellen
make health         # Health-Check durchführen
```

### Mit Docker Compose
```bash
docker-compose up -d              # Starten
docker-compose down               # Stoppen
docker-compose logs -f            # Logs anzeigen
docker-compose ps                 # Status
docker-compose restart            # Neu starten
```

## 🔧 Netzwerk-Interface konfigurieren

### Interface herausfinden
```bash
# Alle verfügbaren Interfaces anzeigen
ip link show

# Oder
ifconfig
```

Typische Interface-Namen:
- `eth0` - Erste Ethernet-Schnittstelle
- `ens33` - VMware/VirtualBox
- `enp0s3` - Modern naming
- `wlan0` - WLAN

### Interface in .env setzen
```bash
MONITOR_INTERFACE=eth0  # Ihr Interface hier
```

## 🛡️ Vallanx Blocklist verwenden

### Via Web-Interface
1. Browser öffnen: http://localhost:5000/vallanx
2. IP oder Domain hinzufügen
3. Kategorie und Severity wählen
4. Speichern

### Via API
```bash
# IP blockieren
curl -X POST http://localhost:8089/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.0.2.100",
    "type": "ip",
    "category": "malware",
    "severity": 5,
    "action": "block"
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

# Statistiken abrufen
curl http://localhost:8089/api/vallanx/stats
```

### Threat-Feed importieren
```bash
# Via API
curl -X POST http://localhost:8089/api/vallanx/import \
  -F "file=@threat-feed.vbx"

# Via Container
docker cp threat-feed.vbx network-monitor:/etc/vallanx/feeds/
docker-compose exec network-monitor python3 -c "
from vallanx_blocklist_manager import VallanxBlocklistManager
vm = VallanxBlocklistManager('/etc/vallanx')
with open('/etc/vallanx/feeds/threat-feed.vbx', 'r') as f:
    imported = vm.import_vallanx_format(f.read())
    print(f'Imported {imported} entries')
"
```

## 📊 Monitoring

### Logs in Echtzeit anzeigen
```bash
# Alle Services
make logs

# Nur Network Monitor
docker-compose logs -f network-monitor

# Nur MySQL
docker-compose logs -f mysql
```

### Status prüfen
```bash
# Service-Status
make status

# Health-Check
make health

# Container-Ressourcen
docker stats
```

### Vallanx Statistiken
```bash
# Via Makefile
make vallanx-stats

# Via API
curl http://localhost:8089/api/vallanx/stats | jq
```

## 💾 Backup & Wiederherstellung

### Backup erstellen
```bash
# Automatisches Backup
make backup

# Manuelles Backup
mkdir -p backups/$(date +%Y%m%d)
docker-compose exec -T mysql mysqldump -u root -p${MYSQL_ROOT_PASSWORD} \
  --all-databases > backups/$(date +%Y%m%d)/database.sql
docker cp network-monitor:/etc/vallanx backups/$(date +%Y%m%d)/
```

### Backup wiederherstellen
```bash
make restore BACKUP_DIR=backups/20240101_120000
```

## 🔒 Sicherheit

### Passwörter ändern (WICHTIG!)
```bash
nano .env

# Ändern Sie:
MYSQL_ROOT_PASSWORD=IhrSicheresPasswort
MYSQL_PASSWORD=IhrSicheresPasswort
SECRET_KEY=Ihr-32-Zeichen-Secret-Key
```

### Zugriff beschränken
```yaml
# In docker-compose.yaml
ports:
  - "127.0.0.1:5000:5000"  # Nur localhost
  - "127.0.0.1:8089:8089"  # Nur localhost
```

### HTTPS aktivieren
```bash
# Mit Nginx Profil
make with-nginx

# Konfiguration in config/nginx.conf anpassen
```

## 🐛 Troubleshooting

### Container startet nicht
```bash
# Logs prüfen
docker-compose logs network-monitor

# Port bereits belegt?
sudo lsof -i :5000
sudo lsof -i :8089

# Berechtigungen prüfen
ls -la
```

### Kein Netzwerk-Capture
```bash
# Interface prüfen
docker-compose exec network-monitor ip link show

# Als root ausführen (in docker-compose.yaml)
privileged: true

# Oder im Container
docker-compose exec network-monitor bash
ip link set eth0 promisc on
tcpdump -i eth0 -c 5
```

### Datenbank-Verbindung fehlgeschlagen
```bash
# MySQL Status prüfen
docker-compose logs mysql

# Verbindung testen
docker-compose exec network-monitor mysql -h mysql -u monitor_user -p

# MySQL neu starten
docker-compose restart mysql
```

### Performance-Probleme
```bash
# Ressourcen-Nutzung prüfen
docker stats

# Datenbank optimieren
make db-optimize

# Alte Daten löschen (> 30 Tage)
docker-compose exec mysql mysql -u root -p -e \
  "CALL network_monitor.sp_cleanup_old_data(30);"
```

## 📈 Erweiterte Features

### Mit Grafana starten
```bash
make with-grafana
# Zugriff: http://localhost:3000
# Login: admin / admin (beim ersten Login ändern)
```

### Mit Nginx Reverse Proxy
```bash
make with-nginx
# Zugriff: http://localhost
```

### Mit allen Services
```bash
make with-all
# Startet: Network Monitor, MySQL, Nginx, Grafana, Redis
```

## 🔄 Updates

### System aktualisieren
```bash
# Automatisches Update mit Backup
make update

# Manuell
make backup
git pull
make build
make restart
```

## 📚 Weitere Ressourcen

- **Vollständige Dokumentation**: DOCKER_README.md
- **API-Dokumentation**: http://localhost:5000/api/docs
- **Vallanx-Syntax**: Siehe vallanx_blocklist_manager.py
- **Makefile-Befehle**: `make help`

## 🆘 Support

Bei Problemen:
1. Logs prüfen: `make logs`
2. Health-Check: `make health`
3. Dokumentation lesen: DOCKER_README.md
4. Issue erstellen mit Logs und Konfiguration

## ✅ Checkliste für Produktiv-Einsatz

- [ ] Passwörter geändert
- [ ] Netzwerk-Interface konfiguriert
- [ ] Backup eingerichtet (cron job)
- [ ] HTTPS aktiviert (mit Nginx)
- [ ] Monitoring aktiviert (Grafana)
- [ ] Log-Rotation konfiguriert
- [ ] Firewall-Regeln gesetzt
- [ ] Dokumentation gelesen
- [ ] Tests durchgeführt

## 📝 Beispiel: Komplette Installation

```bash
# 1. Projekt erstellen
mkdir /opt/network-monitor
cd /opt/network-monitor

# 2. Dateien kopieren
# (alle bereitgestellten Dateien)

# 3. Konfigurieren
cp .env.example .env
nano .env
# Passwörter ändern!
# Interface anpassen!

# 4. Installieren
make install

# 5. Prüfen
make health
make logs-monitor

# 6. Zugreifen
firefox http://localhost:5000

# 7. Erste Blocklist-Einträge
curl -X POST http://localhost:8089/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.0.2.1",
    "type": "ip",
    "category": "malware",
    "severity": 5,
    "action": "block"
  }'

# 8. Backup einrichten
crontab -e
# Hinzufügen:
# 0 2 * * * cd /opt/network-monitor && make backup
```

---

**Viel Erfolg mit Ihrem Network Monitor mit Vallanx Universal Blocklist! 🚀**
