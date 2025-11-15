# Final Setup Script - Network Monitor mit Vallanx (OHNE Suricata)
# Führt alle notwendigen Schritte automatisch aus

param(
    [switch]$SkipBuild,
    [switch]$SkipStart
)

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  Network Monitor mit Vallanx - Vollständiges Setup" -ForegroundColor Cyan
Write-Host "  Version: 2.0.0-vallanx-only (OHNE Suricata)" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""

# Farben
function Write-Success { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Info { param($msg) Write-Host "  [INFO] $msg" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "  [FEHLER] $msg" -ForegroundColor Red }

# Schritt 1: Docker prüfen
Write-Host "Schritt 1: Docker-Status prüfen..." -ForegroundColor Yellow
try {
    $null = docker ps 2>&1
    Write-Success "Docker läuft"
} catch {
    Write-Error "Docker läuft nicht oder ist nicht installiert!"
    Write-Host "  Bitte starten Sie Docker Desktop und führen Sie das Script erneut aus." -ForegroundColor White
    exit 1
}

# Schritt 2: Verzeichnisse erstellen
Write-Host ""
Write-Host "Schritt 2: Verzeichnisstruktur erstellen..." -ForegroundColor Yellow

$directories = @("templates", "static", "config", "volumes", "volumes/logs", "volumes/data", "volumes/backups")
foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Success "Verzeichnis '$dir' erstellt"
    } else {
        Write-Info "Verzeichnis '$dir' existiert bereits"
    }
}

# Schritt 3: Dateien umbenennen
Write-Host ""
Write-Host "Schritt 3: Dateien umbenennen..." -ForegroundColor Yellow

# dockerignore -> .dockerignore
if (Test-Path "dockerignore") {
    if (Test-Path ".dockerignore") { Remove-Item ".dockerignore" -Force }
    Rename-Item "dockerignore" ".dockerignore" -Force
    Write-Success "dockerignore -> .dockerignore"
} elseif (Test-Path ".dockerignore") {
    Write-Info ".dockerignore existiert bereits"
} else {
    Write-Info "Keine .dockerignore Datei gefunden"
}

# env.example -> .env.example
if (Test-Path "env.example") {
    if (Test-Path ".env.example") { Remove-Item ".env.example" -Force }
    Rename-Item "env.example" ".env.example" -Force
    Write-Success "env.example -> .env.example"
} elseif (Test-Path ".env.example") {
    Write-Info ".env.example existiert bereits"
}

# Schritt 4: Web-Dateien verschieben
Write-Host ""
Write-Host "Schritt 4: Web-Dateien organisieren..." -ForegroundColor Yellow

if (Test-Path "index.html") {
    Copy-Item "index.html" "templates/index.html" -Force
    Write-Success "index.html -> templates/"
} else {
    Write-Error "index.html nicht gefunden!"
}

if (Test-Path "style.css") {
    Copy-Item "style.css" "static/style.css" -Force
    Write-Success "style.css -> static/"
} else {
    Write-Info "style.css nicht gefunden (optional)"
}

if (Test-Path "app.js") {
    Copy-Item "app.js" "static/app.js" -Force
    Write-Success "app.js -> static/"
} else {
    Write-Info "app.js nicht gefunden (optional)"
}

# Schritt 5: .env Konfiguration
Write-Host ""
Write-Host "Schritt 5: Konfigurationsdatei (.env) prüfen..." -ForegroundColor Yellow

if (-not (Test-Path ".env")) {
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env" -Force
        Write-Success ".env aus .env.example erstellt"
        Write-Host ""
        Write-Host "  ⚠️  WICHTIG: Passwörter müssen noch geändert werden!" -ForegroundColor Red
        Write-Host "  Öffnen Sie .env und ändern Sie:" -ForegroundColor Yellow
        Write-Host "    - MYSQL_ROOT_PASSWORD" -ForegroundColor White
        Write-Host "    - MYSQL_PASSWORD" -ForegroundColor White
        Write-Host "    - MONITOR_INTERFACE (z.B. eth0)" -ForegroundColor White
        Write-Host ""
        
        $answer = Read-Host "  Möchten Sie .env jetzt bearbeiten? (j/n)"
        if ($answer -eq "j" -or $answer -eq "J" -or $answer -eq "y" -or $answer -eq "Y") {
            notepad .env
        }
    } else {
        Write-Error ".env.example nicht gefunden!"
        Write-Host "  Erstellen Sie manuell eine .env Datei" -ForegroundColor White
    }
} else {
    Write-Info ".env existiert bereits"
}

# Schritt 6: docker-compose.yaml anpassen
Write-Host ""
Write-Host "Schritt 6: docker-compose.yaml prüfen..." -ForegroundColor Yellow

if (Test-Path "docker-compose.yaml") {
    $content = Get-Content "docker-compose.yaml" -Raw
    if ($content -match "^version:") {
        $lines = Get-Content "docker-compose.yaml"
        $lines | Select-Object -Skip 1 | Set-Content "docker-compose.yaml"
        Write-Success "'version:' Zeile entfernt"
    } else {
        Write-Info "Keine 'version:' Zeile gefunden"
    }
} else {
    Write-Error "docker-compose.yaml nicht gefunden!"
}

# Schritt 7: Dateien prüfen
Write-Host ""
Write-Host "Schritt 7: Erforderliche Dateien prüfen..." -ForegroundColor Yellow

$requiredFiles = @{
    "docker-compose.yaml" = "Docker Compose Konfiguration"
    "Dockerfile" = "Docker Build Datei"
    "docker-entrypoint.sh" = "Container Entrypoint"
    "requirements.txt" = "Python Dependencies"
    "vallanx_integrated_network_monitor.py" = "Hauptanwendung (NEU!)"
    "vallanx-blocklist-manager.py" = "Blocklist Manager"
    "db-credentials.json" = "Datenbank Konfiguration"
    "templates/index.html" = "Web Interface"
}

$allPresent = $true
$missing = @()

foreach ($file in $requiredFiles.Keys) {
    if (Test-Path $file) {
        Write-Success "$file"
    } else {
        Write-Error "$file FEHLT!"
        $missing += $file
        $allPresent = $false
    }
}

if (-not $allPresent) {
    Write-Host ""
    Write-Host "========================================================================" -ForegroundColor Red
    Write-Host "  FEHLER: Folgende Dateien fehlen:" -ForegroundColor Red
    Write-Host "========================================================================" -ForegroundColor Red
    foreach ($file in $missing) {
        Write-Host "  - $file" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  Bitte laden Sie die fehlenden Dateien herunter:" -ForegroundColor Yellow
    Write-Host "  1. vallanx_integrated_network_monitor.py" -ForegroundColor Cyan
    Write-Host "  2. Dockerfile" -ForegroundColor Cyan
    Write-Host "  3. docker-compose.yaml" -ForegroundColor Cyan
    Write-Host "  4. docker-entrypoint.sh" -ForegroundColor Cyan
    Write-Host ""
    exit 1
}

# Schritt 8: Build
Write-Host ""
Write-Host "========================================================================" -ForegroundColor Green
Write-Host "  Alle Dateien vorhanden!" -ForegroundColor Green
Write-Host "========================================================================" -ForegroundColor Green
Write-Host ""

if (-not $SkipBuild) {
    $answer = Read-Host "Möchten Sie jetzt 'docker-compose build' ausführen? (j/n)"
    if ($answer -eq "j" -or $answer -eq "J" -or $answer -eq "y" -or $answer -eq "Y") {
        Write-Host ""
        Write-Host "Schritt 8: Docker Image bauen..." -ForegroundColor Yellow
        Write-Host "  Dies kann 3-5 Minuten dauern..." -ForegroundColor White
        Write-Host ""
        
        docker-compose build
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Success "Docker Build erfolgreich!"
            
            if (-not $SkipStart) {
                $answer2 = Read-Host "Möchten Sie die Container jetzt starten? (j/n)"
                if ($answer2 -eq "j" -or $answer2 -eq "J" -or $answer2 -eq "y" -or $answer2 -eq "Y") {
                    Write-Host ""
                    Write-Host "Schritt 9: Container starten..." -ForegroundColor Yellow
                    docker-compose up -d
                    
                    if ($LASTEXITCODE -eq 0) {
                        Write-Host ""
                        Write-Success "Container erfolgreich gestartet!"
                        Write-Host ""
                        Write-Host "Container Status:" -ForegroundColor Yellow
                        docker-compose ps
                        Write-Host ""
                        Write-Host "========================================================================" -ForegroundColor Green
                        Write-Host "  Installation abgeschlossen!" -ForegroundColor Green
                        Write-Host "========================================================================" -ForegroundColor Green
                        Write-Host ""
                        Write-Host "Zugriff auf die Anwendung:" -ForegroundColor Cyan
                        Write-Host "  Web-Interface:     http://localhost:5000" -ForegroundColor White
                        Write-Host "  Vallanx Dashboard: http://localhost:5000/vallanx" -ForegroundColor White
                        Write-Host "  Vallanx API:       http://localhost:8089" -ForegroundColor White
                        Write-Host ""
                        Write-Host "Nützliche Befehle:" -ForegroundColor Cyan
                        Write-Host "  Logs anzeigen:     docker-compose logs -f network-monitor" -ForegroundColor White
                        Write-Host "  Status prüfen:     docker-compose ps" -ForegroundColor White
                        Write-Host "  Container stoppen: docker-compose stop" -ForegroundColor White
                        Write-Host "  Container starten: docker-compose start" -ForegroundColor White
                        Write-Host ""
                    } else {
                        Write-Error "Container-Start fehlgeschlagen!"
                        Write-Host "  Prüfen Sie die Logs: docker-compose logs" -ForegroundColor Yellow
                    }
                }
            }
        } else {
            Write-Host ""
            Write-Error "Docker Build fehlgeschlagen!"
            Write-Host ""
            Write-Host "Häufige Ursachen:" -ForegroundColor Yellow
            Write-Host "  1. Fehlende Dateien (siehe oben)" -ForegroundColor White
            Write-Host "  2. Dateien haben falsche Namen" -ForegroundColor White
            Write-Host "  3. Nicht genügend Speicherplatz" -ForegroundColor White
            Write-Host "  4. Docker läuft nicht richtig" -ForegroundColor White
            Write-Host ""
            Write-Host "Lösungsvorschläge:" -ForegroundColor Cyan
            Write-Host "  - Stellen Sie sicher, dass alle Dateien vorhanden sind" -ForegroundColor White
            Write-Host "  - Prüfen Sie: docker-compose build --progress=plain" -ForegroundColor White
            Write-Host "  - Löschen Sie alte Images: docker system prune -a" -ForegroundColor White
            Write-Host ""
        }
    }
} else {
    Write-Info "Build übersprungen (Parameter -SkipBuild)"
}

Write-Host ""
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host "  Setup-Script abgeschlossen" -ForegroundColor Cyan
Write-Host "========================================================================" -ForegroundColor Cyan
Write-Host ""
