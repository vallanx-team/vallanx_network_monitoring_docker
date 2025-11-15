# Vallanx Network Monitor - Schnellstart

## 🚀 In 3 Schritten starten

### 1. Dependencies installieren
```bash
pip3 install -r requirements-standalone.txt
```

### 2. Starten
```bash
sudo ./start.sh
```

### 3. Dashboard öffnen
Öffne im Browser: **http://localhost:5000**

---

## 📌 Das war's!

Die Standalone-Version läuft komplett eigenständig:
- ✅ SQLite Datenbank (keine externe DB nötig)
- ✅ Alle Komponenten in einer Datei
- ✅ Automatische Vallanx Blocklist

## 📖 Mehr Infos

- **Ausführliche Anleitung**: [README-STANDALONE.md](README-STANDALONE.md)
- **Original Dokumentation**: [README.md](README.md)

## 🔧 Manuelle Optionen

```bash
# Custom Interface & Port
sudo python3 standalone_monitor.py --interface wlan0 --port 8080

# Custom Data Directory
sudo python3 standalone_monitor.py --data-dir /var/lib/vallanx
```

## ⚡ API Quick Test

```bash
# Stats abrufen
curl http://localhost:5000/api/stats

# IP zur Blocklist hinzufügen
curl -X POST http://localhost:5000/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{"value":"192.0.2.1","type":"ip","category":"malware","severity":5,"action":"block"}'

# IP überprüfen
curl -X POST http://localhost:5000/api/vallanx/check \
  -H "Content-Type: application/json" \
  -d '{"value":"192.0.2.1"}'
```

## 🆘 Probleme?

**Packet Capture funktioniert nicht?**
→ Mit `sudo` ausführen!

**Port bereits in Verwendung?**
→ Anderen Port wählen: `--port 8080`

**Interface nicht gefunden?**
→ Interfaces anzeigen: `ip link show`

---

**Happy Monitoring! 🎉**
