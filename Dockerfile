# Dockerfile for Network Monitor with Vallanx Universal Blocklist
# Final working version with correct file structure

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    TZ=Europe/Berlin

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    build-essential \
    libpcap-dev \
    tcpdump \
    net-tools \
    iproute2 \
    iptables \
    sqlite3 \
    mysql-client \
    curl \
    wget \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p \
    /app \
    /app/templates \
    /app/static \
    /var/log/network-monitor \
    /var/lib/network-monitor \
    /etc/network-monitor \
    /etc/vallanx/feeds

WORKDIR /app

# Copy requirements
COPY requirements.txt .

# Install Python packages
RUN python3 -m pip install --break-system-packages -r requirements.txt

# Copy BOTH Python files - ORDER MATTERS!
COPY network_monitor.py ./network_monitor.py
COPY vallanx_integrated_network_monitor.py ./vallanx_integrated_network_monitor.py
COPY vallanx-blocklist-manager.py ./vallanx_blocklist_manager.py
COPY db-credentials.json /etc/network-monitor/db-credentials.json

# Copy web files
COPY templates/index.html ./templates/
COPY templates/vallanx_dashboard.html ./templates/
COPY static/style.css ./static/
COPY static/app.js ./static/

# Copy entrypoint
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Expose ports
EXPOSE 5000 8089

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/api/stats || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["python3", "vallanx_integrated_network_monitor.py"]
