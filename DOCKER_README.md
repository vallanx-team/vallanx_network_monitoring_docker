# Network Monitor with Vallanx - Docker Deployment Guide

## Overview

This Docker setup provides a complete Network Traffic Monitor with Vallanx Universal Blocklist Integration, including:

- **Network Monitor**: Real-time packet capture and analysis
- **Vallanx Universal Blocklist**: Multi-format threat intelligence management
- **Suricata IDS**: Intrusion Detection System integration
- **MySQL Database**: Persistent storage for logs and statistics
- **Web Interface**: Real-time monitoring dashboard
- **WebSocket API**: Live updates and alerts

## Prerequisites

- Docker Engine 20.10+ or Docker Desktop
- Docker Compose 2.0+
- Linux host with network access
- At least 2GB RAM
- 10GB free disk space

## Quick Start

### 1. Clone or Download Files

```bash
# Create project directory
mkdir network-monitor
cd network-monitor

# Copy all provided files to this directory
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env

# Important: Change default passwords!
# - MYSQL_ROOT_PASSWORD
# - MYSQL_PASSWORD
# - SECRET_KEY
```

### 3. Build and Start

```bash
# Build images
docker-compose build

# Start services (basic setup)
docker-compose up -d

# Check logs
docker-compose logs -f network-monitor

# Check all services
docker-compose ps
```

### 4. Access the Application

- **Web Interface**: http://localhost:5000
- **Vallanx API**: http://localhost:8089
- **MySQL**: localhost:3306

## Configuration

### Network Interface

By default, the monitor captures from `eth0`. To change:

```bash
# Edit .env file
MONITOR_INTERFACE=ens33

# Or set environment variable
docker-compose up -d -e MONITOR_INTERFACE=ens33
```

### Network Modes

#### Host Network Mode (Default - Recommended)

Best for packet capture and network monitoring:

```yaml
services:
  network-monitor:
    network_mode: host
```

**Pros:**
- Direct access to host network interfaces
- No NAT overhead
- Best performance for packet capture

**Cons:**
- Less isolated
- Port conflicts possible

#### Bridge Network Mode

For isolated networking:

```yaml
services:
  network-monitor:
    networks:
      - monitor-network
    ports:
      - "5000:5000"
      - "8089:8089"
```

### Database Options

#### MySQL (Default)

```bash
docker-compose up -d
```

#### PostgreSQL

```bash
docker-compose --profile postgres up -d

# Update .env
DB_TYPE=postgresql
DB_HOST=postgres
DB_PORT=5432
```

#### SQLite (Fallback)

Automatic fallback if database connection fails. No additional configuration needed.

## Optional Services

### Enable Redis Cache

```bash
docker-compose --profile cache up -d
```

### Enable Nginx Reverse Proxy

```bash
# Create nginx configuration first
mkdir -p config
cp nginx.conf.example config/nginx.conf

docker-compose --profile nginx up -d
```

### Enable Grafana Dashboard

```bash
docker-compose --profile monitoring up -d

# Access Grafana at http://localhost:3000
# Default credentials: admin / admin (change after first login)
```

## Vallanx Universal Blocklist

### Import Threat Feeds

```bash
# Copy threat feed to container
docker cp threat-feed.vbx network-monitor:/etc/vallanx/feeds/

# Import via API
curl -X POST http://localhost:8089/api/vallanx/import \
  -H "Content-Type: application/json" \
  -d @threat-feed.json

# Or via web interface
# Navigate to http://localhost:5000/vallanx
```

### Export Blocklists

```bash
# Export as Suricata rules
curl http://localhost:8089/api/vallanx/export/suricata > vallanx.rules

# Export as iptables script
curl http://localhost:8089/api/vallanx/export/iptables > vallanx-iptables.sh

# Export all formats (ZIP)
curl http://localhost:5000/api/vallanx/export-all -o vallanx-export.zip
```

### Add Entries via API

```bash
# Block an IP
curl -X POST http://localhost:8089/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "192.0.2.100",
    "type": "ip",
    "category": "malware",
    "severity": 5,
    "action": "block"
  }'

# Block a domain
curl -X POST http://localhost:8089/api/vallanx/add \
  -H "Content-Type: application/json" \
  -d '{
    "value": "evil.example.com",
    "type": "domain",
    "category": "phishing",
    "severity": 4,
    "action": "block"
  }'
```

## Management Commands

### Container Management

```bash
# Start services
docker-compose up -d

# Stop services
docker-compose stop

# Restart services
docker-compose restart

# View logs
docker-compose logs -f [service_name]

# Execute command in container
docker-compose exec network-monitor bash

# Remove everything (including volumes!)
docker-compose down -v
```

### Database Management

```bash
# Connect to MySQL
docker-compose exec mysql mysql -u monitor_user -p network_monitor

# Backup database
docker-compose exec mysql mysqldump -u root -p network_monitor > backup.sql

# Restore database
docker-compose exec -T mysql mysql -u root -p network_monitor < backup.sql

# Check database size
docker-compose exec mysql mysql -u root -p -e "
  SELECT 
    table_schema AS 'Database',
    ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS 'Size (MB)'
  FROM information_schema.tables
  WHERE table_schema = 'network_monitor'
  GROUP BY table_schema;"
```

### Vallanx Management

```bash
# Enter container
docker-compose exec network-monitor bash

# Check Vallanx statistics
python3 << EOF
from vallanx_blocklist_manager import VallanxBlocklistManager
vm = VallanxBlocklistManager('/etc/vallanx')
print(vm.get_statistics())
EOF

# Update Suricata rules from Vallanx
python3 << EOF
from vallanx_blocklist_manager import VallanxBlocklistManager
vm = VallanxBlocklistManager('/etc/vallanx')
rules = vm.export_suricata_rules()
with open('/etc/suricata/rules/vallanx.rules', 'w') as f:
    f.write(rules)
EOF

# Cleanup expired entries
python3 << EOF
from vallanx_blocklist_manager import VallanxBlocklistManager
vm = VallanxBlocklistManager('/etc/vallanx')
vm.cleanup_expired()
EOF
```

### Monitoring

```bash
# Check container stats
docker stats

# Check network usage
docker-compose exec network-monitor ip -s link

# Monitor packet capture
docker-compose exec network-monitor tcpdump -i eth0 -c 10

# Check Suricata alerts
docker-compose exec network-monitor tail -f /var/log/suricata/eve.json
```

## Security Considerations

### 1. Change Default Passwords

**Critical:** Change all default passwords in `.env`:
- `MYSQL_ROOT_PASSWORD`
- `MYSQL_PASSWORD`
- `SECRET_KEY`
- `GRAFANA_PASSWORD`

### 2. Restrict Network Access

```yaml
# Bind only to localhost
ports:
  - "127.0.0.1:5000:5000"
  - "127.0.0.1:8089:8089"
```

### 3. Enable Authentication

Set in `.env`:
```bash
API_AUTH_REQUIRED=true
```

### 4. Use HTTPS

Enable Nginx profile and configure SSL certificates:

```bash
# Generate self-signed certificate (testing only)
mkdir -p config/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout config/ssl/nginx.key \
  -out config/ssl/nginx.crt

# Start with Nginx
docker-compose --profile nginx up -d
```

### 5. Regular Updates

```bash
# Update images
docker-compose pull

# Rebuild with latest code
docker-compose build --no-cache

# Restart services
docker-compose up -d
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs network-monitor

# Common issues:
# 1. Port already in use
sudo lsof -i :5000

# 2. Permission issues
sudo chown -R 1000:1000 volumes/

# 3. Database not ready
docker-compose logs mysql
```

### No Network Capture

```bash
# Check if running as privileged
docker-compose exec network-monitor id
# Should show: uid=0(root)

# Check network interface
docker-compose exec network-monitor ip link show

# Enable promiscuous mode manually
docker-compose exec network-monitor ip link set eth0 promisc on

# Test packet capture
docker-compose exec network-monitor tcpdump -i eth0 -c 5
```

### Database Connection Issues

```bash
# Test MySQL connection
docker-compose exec network-monitor mysql -h mysql -u monitor_user -p

# Check MySQL status
docker-compose exec mysql mysqladmin -u root -p status

# Restart database
docker-compose restart mysql
```

### High Memory Usage

```bash
# Limit container memory
docker-compose.yml:
  services:
    network-monitor:
      mem_limit: 1g
      memswap_limit: 2g

# Reduce packet queue size in .env
MAX_PACKET_QUEUE=5000
```

### Performance Issues

```bash
# Check container resources
docker stats network-monitor

# Optimize database
docker-compose exec mysql mysqlcheck -u root -p --optimize --all-databases

# Reduce log verbosity in .env
LOG_LEVEL=WARNING
```

## Backup and Recovery

### Manual Backup

```bash
# Create backup directory
mkdir -p backups/$(date +%Y%m%d)

# Backup database
docker-compose exec mysql mysqldump -u root -p --all-databases \
  > backups/$(date +%Y%m%d)/database.sql

# Backup Vallanx data
docker cp network-monitor:/etc/vallanx backups/$(date +%Y%m%d)/

# Backup configuration
cp -r config backups/$(date +%Y%m%d)/
cp .env backups/$(date +%Y%m%d)/
```

### Automated Backup

Add to crontab:

```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * cd /path/to/network-monitor && ./backup.sh
```

Create `backup.sh`:

```bash
#!/bin/bash
BACKUP_DIR="backups/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

docker-compose exec -T mysql mysqldump -u root -p${MYSQL_ROOT_PASSWORD} \
  --all-databases > "$BACKUP_DIR/database.sql"

docker cp network-monitor:/etc/vallanx "$BACKUP_DIR/"

# Keep only last 30 days
find backups/ -type d -mtime +30 -exec rm -rf {} +
```

### Restore from Backup

```bash
# Stop services
docker-compose stop

# Restore database
docker-compose exec -T mysql mysql -u root -p < backups/20240101/database.sql

# Restore Vallanx data
docker cp backups/20240101/vallanx network-monitor:/etc/

# Restart services
docker-compose start
```

## Upgrading

### Update to Latest Version

```bash
# Backup current data
./backup.sh

# Pull latest changes
git pull

# Rebuild containers
docker-compose build --no-cache

# Stop old containers
docker-compose down

# Start new containers
docker-compose up -d

# Check logs
docker-compose logs -f
```

### Migration Guide

When upgrading major versions:

1. Read CHANGELOG.md for breaking changes
2. Backup all data
3. Update docker-compose.yaml if needed
4. Run database migrations
5. Test in staging environment first

## Production Deployment

### Recommended Setup

1. **Use Docker Swarm or Kubernetes** for orchestration
2. **Enable all security features**:
   - Authentication
   - HTTPS/TLS
   - Rate limiting
   - IP whitelisting

3. **Configure monitoring**:
   - Grafana dashboards
   - Log aggregation (ELK stack)
   - Alerting (Prometheus)

4. **Regular maintenance**:
   - Automated backups
   - Log rotation
   - Security updates
   - Performance monitoring

### Example Production Compose

```yaml
version: '3.8'

services:
  network-monitor:
    image: network-monitor:production
    restart: always
    networks:
      - monitor-network
    volumes:
      - /data/monitor:/var/lib/network-monitor
    environment:
      - FLASK_ENV=production
      - API_AUTH_REQUIRED=true
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

## Support and Resources

- **Documentation**: /docs
- **API Reference**: http://localhost:5000/api/docs
- **Issue Tracker**: GitHub Issues
- **Community**: Discord/Slack

## License

[Your License Here]

## Contributing

Pull requests are welcome! Please read CONTRIBUTING.md first.

---

**Created with**: Docker, Python, Flask, Scapy, Suricata, MySQL, and the Vallanx Universal Blocklist System
