# Diagnose und Fix Script für Docker Build Probleme
# Prüft alle möglichen Fehlerquellen und behebt sie

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Docker Build Diagnose & Fix" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# Funktion für farbige Ausgabe
function Write-Success { param($msg) Write-Host "[OK]   $msg" -ForegroundColor Green }
function Write-Error { param($msg) Write-Host "[FEHLER] $msg" -ForegroundColor Red }
function Write-Info { param($msg) Write-Host "[INFO] $msg" -ForegroundColor Yellow }
function Write-Fix { param($msg) Write-Host "[FIX]  $msg" -ForegroundColor Cyan }

# Schritt 1: Aktuelle Verzeichnis-Struktur prüfen
Write-Host "Schritt 1: Aktuelle Datei-Struktur analysieren..." -ForegroundColor Yellow
Write-Host ""

$currentFiles = Get-ChildItem -File | Select-Object -ExpandProperty Name
Write-Host "Gefundene Dateien im Hauptverzeichnis:" -ForegroundColor White
foreach ($file in $currentFiles) {
    Write-Host "  - $file" -ForegroundColor Gray
}

Write-Host ""

# Schritt 2: Erforderliche Dateien prüfen
Write-Host "Schritt 2: Erforderliche Dateien prüfen..." -ForegroundColor Yellow
Write-Host ""

$requiredFiles = @{
    "Dockerfile" = "Docker Build Instruktionen"
    "docker-compose.yaml" = "Docker Compose Konfiguration"
    "docker-entrypoint.sh" = "Container Startscript"
    "requirements.txt" = "Python Dependencies"
    "vallanx_integrated_network_monitor.py" = "Hauptanwendung"
    "vallanx-blocklist-manager.py" = "Vallanx Manager"
    "db-credentials.json" = "Datenbank Config"
    "index.html" = "Web Interface"
}

$missingFiles = @()
$presentFiles = @()

foreach ($file in $requiredFiles.Keys) {
    if (Test-Path $file) {
        Write-Success "$file - $($requiredFiles[$file])"
        $presentFiles += $file
    } else {
        Write-Error "$file - FEHLT!"
        $missingFiles += $file
    }
}

Write-Host ""

# Schritt 3: Verzeichnisstruktur prüfen
Write-Host "Schritt 3: Verzeichnisstruktur prüfen..." -ForegroundColor Yellow
Write-Host ""

$requiredDirs = @("templates", "static", "config")
$missingDirs = @()

foreach ($dir in $requiredDirs) {
    if (Test-Path $dir) {
        Write-Success "Verzeichnis $dir/ existiert"
        
        # Prüfe Dateien im Verzeichnis
        $filesInDir = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue
        if ($filesInDir.Count -gt 0) {
            foreach ($f in $filesInDir) {
                Write-Host "    └─ $($f.Name)" -ForegroundColor Gray
            }
        } else {
            Write-Info "    └─ (leer)"
        }
    } else {
        Write-Error "Verzeichnis $dir/ FEHLT!"
        $missingDirs += $dir
    }
}

Write-Host ""

# Schritt 4: Automatische Fixes
if ($missingDirs.Count -gt 0 -or $missingFiles.Count -gt 0) {
    Write-Host "Schritt 4: Automatische Problembehebung..." -ForegroundColor Yellow
    Write-Host ""
    
    # Verzeichnisse erstellen
    if ($missingDirs.Count -gt 0) {
        Write-Fix "Erstelle fehlende Verzeichnisse..."
        foreach ($dir in $missingDirs) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Write-Success "Verzeichnis $dir/ erstellt"
        }
    }
    
    # Dateien verschieben
    if ((Test-Path "index.html") -and -not (Test-Path "templates/index.html")) {
        Copy-Item "index.html" "templates/" -Force
        Write-Fix "index.html -> templates/"
    }
    
    if ((Test-Path "style.css") -and -not (Test-Path "static/style.css")) {
        Copy-Item "style.css" "static/" -Force
        Write-Fix "style.css -> static/"
    }
    
    if ((Test-Path "app.js") -and -not (Test-Path "static/app.js")) {
        Copy-Item "app.js" "static/" -Force
        Write-Fix "app.js -> static/"
    }
    
    Write-Host ""
}

# Schritt 5: Docker-spezifische Probleme
Write-Host "Schritt 5: Docker-Konfiguration prüfen..." -ForegroundColor Yellow
Write-Host ""

# Prüfe .dockerignore
if (Test-Path "dockerignore") {
    Write-Fix "Benenne 'dockerignore' um zu '.dockerignore'"
    if (Test-Path ".dockerignore") { Remove-Item ".dockerignore" -Force }
    Rename-Item "dockerignore" ".dockerignore" -Force
    Write-Success ".dockerignore erstellt"
} elseif (Test-Path ".dockerignore") {
    Write-Success ".dockerignore existiert"
} else {
    Write-Info ".dockerignore nicht gefunden (optional)"
}

# Prüfe docker-compose.yaml
if (Test-Path "docker-compose.yaml") {
    $content = Get-Content "docker-compose.yaml" -Raw
    if ($content -match "^version:") {
        Write-Fix "Entferne obsolete 'version:' Zeile aus docker-compose.yaml"
        $lines = Get-Content "docker-compose.yaml"
        $lines | Select-Object -Skip 1 | Set-Content "docker-compose.yaml"
        Write-Success "docker-compose.yaml bereinigt"
    } else {
        Write-Success "docker-compose.yaml ist OK"
    }
}

Write-Host ""

# Schritt 6: Zusammenfassung und Empfehlung
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Diagnose Abgeschlossen" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

if ($missingFiles.Count -gt 0) {
    Write-Host "⚠️  FEHLENDE DATEIEN:" -ForegroundColor Red
    Write-Host ""
    foreach ($file in $missingFiles) {
        Write-Host "  ❌ $file" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "NÄCHSTE SCHRITTE:" -ForegroundColor Yellow
    Write-Host "  1. Laden Sie die fehlenden Dateien herunter" -ForegroundColor White
    Write-Host "  2. Legen Sie sie in das Projektverzeichnis" -ForegroundColor White
    Write-Host "  3. Führen Sie dieses Script erneut aus" -ForegroundColor White
    Write-Host ""
} else {
    Write-Host "✅ Alle erforderlichen Dateien sind vorhanden!" -ForegroundColor Green
    Write-Host ""
    
    # Zeige Dateistruktur
    Write-Host "Finale Dateistruktur:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Projektverzeichnis/" -ForegroundColor White
    Write-Host "├── Dockerfile" -ForegroundColor Gray
    Write-Host "├── docker-compose.yaml" -ForegroundColor Gray
    Write-Host "├── docker-entrypoint.sh" -ForegroundColor Gray
    Write-Host "├── requirements.txt" -ForegroundColor Gray
    Write-Host "├── vallanx_integrated_network_monitor.py" -ForegroundColor Gray
    Write-Host "├── vallanx-blocklist-manager.py" -ForegroundColor Gray
    Write-Host "├── db-credentials.json" -ForegroundColor Gray
    Write-Host "├── .env" -ForegroundColor Gray
    Write-Host "├── templates/" -ForegroundColor Gray
    Write-Host "│   └── index.html" -ForegroundColor Gray
    Write-Host "└── static/" -ForegroundColor Gray
    Write-Host "    ├── style.css" -ForegroundColor Gray
    Write-Host "    └── app.js" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "BEREIT FÜR DOCKER BUILD!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Nächste Schritte:" -ForegroundColor Yellow
    Write-Host "  1. docker-compose build" -ForegroundColor Cyan
    Write-Host "  2. docker-compose up -d" -ForegroundColor Cyan
    Write-Host ""
    
    $answer = Read-Host "Möchten Sie jetzt 'docker-compose build' ausführen? (j/n)"
    if ($answer -eq "j" -or $answer -eq "J" -or $answer -eq "y" -or $answer -eq "Y") {
        Write-Host ""
        Write-Host "Starte Docker Build..." -ForegroundColor Yellow
        Write-Host ""
        
        # Alte Builds löschen für sauberen Start
        Write-Host "Lösche alte Docker-Artifacts..." -ForegroundColor Yellow
        docker-compose down 2>$null
        docker system prune -f 2>$null
        
        Write-Host "Starte Build (dies kann 3-5 Minuten dauern)..." -ForegroundColor Yellow
        Write-Host ""
        
        docker-compose build --progress=plain
        
        if ($LASTEXITCODE -eq 0) {
            Write-Host ""
            Write-Host "=====================================================================" -ForegroundColor Green
            Write-Host "  ✅ BUILD ERFOLGREICH!" -ForegroundColor Green
            Write-Host "=====================================================================" -ForegroundColor Green
            Write-Host ""
            
            $answer2 = Read-Host "Möchten Sie die Container jetzt starten? (j/n)"
            if ($answer2 -eq "j" -or $answer2 -eq "J" -or $answer2 -eq "y" -or $answer2 -eq "Y") {
                Write-Host ""
                docker-compose up -d
                Write-Host ""
                Write-Host "Container Status:" -ForegroundColor Cyan
                docker-compose ps
                Write-Host ""
                Write-Host "Zugriff:" -ForegroundColor Cyan
                Write-Host "  Web:     http://localhost:5000" -ForegroundColor White
                Write-Host "  Vallanx: http://localhost:5000/vallanx" -ForegroundColor White
                Write-Host "  API:     http://localhost:8089" -ForegroundColor White
                Write-Host ""
            }
        } else {
            Write-Host ""
            Write-Host "=====================================================================" -ForegroundColor Red
            Write-Host "  ❌ BUILD FEHLGESCHLAGEN" -ForegroundColor Red
            Write-Host "=====================================================================" -ForegroundColor Red
            Write-Host ""
            Write-Host "Fehlerursachen:" -ForegroundColor Yellow
            Write-Host "  1. Prüfen Sie die Fehlermeldung oben" -ForegroundColor White
            Write-Host "  2. Stellen Sie sicher, dass alle Dateien korrekt sind" -ForegroundColor White
            Write-Host "  3. Prüfen Sie templates/ und static/ Verzeichnisse" -ForegroundColor White
            Write-Host ""
            Write-Host "Debug-Befehl:" -ForegroundColor Cyan
            Write-Host "  docker-compose build --no-cache --progress=plain" -ForegroundColor White
            Write-Host ""
        }
    }
}

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
