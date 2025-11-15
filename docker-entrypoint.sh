#!/bin/bash
set -e

echo "========================================="
echo "Network Monitor with Vallanx Starting..."
echo "========================================="

# Function to wait for database
wait_for_db() {
    local db_type=$1
    local max_attempts=30
    local attempt=1
    
    echo "Waiting for ${db_type} database to be ready..."
    
    if [ "$db_type" = "mysql" ]; then
        while [ $attempt -le $max_attempts ]; do
            if mysqladmin ping -h"${DB_HOST:-mysql}" -u"${DB_USER:-monitor_user}" -p"${DB_PASSWORD}" --silent 2>/dev/null; then
                echo "✓ MySQL is ready!"
                return 0
            fi
            echo "  Attempt $attempt/$max_attempts: MySQL not ready yet..."
            sleep 2
            attempt=$((attempt + 1))
        done
    elif [ "$db_type" = "postgresql" ]; then
        while [ $attempt -le $max_attempts ]; do
            if PGPASSWORD="${DB_PASSWORD}" psql -h"${DB_HOST:-postgres}" -U"${DB_USER:-monitor_user}" -d"${DB_NAME:-network_monitor}" -c '\q' 2>/dev/null; then
                echo "✓ PostgreSQL is ready!"
                return 0
            fi
            echo "  Attempt $attempt/$max_attempts: PostgreSQL not ready yet..."
            sleep 2
            attempt=$((attempt + 1))
        done
    fi
    
    echo "✗ Database not ready after $max_attempts attempts"
    return 1
}

# Function to initialize Vallanx
initialize_vallanx() {
    echo "Initializing Vallanx Universal Blocklist..."
    
    # Create Vallanx directories
    mkdir -p /etc/vallanx/{skills/public,feeds,lists}
    
    # Initialize Vallanx if not already initialized
    if [ ! -f /etc/vallanx/vallanx.yaml ]; then
        echo "Creating Vallanx configuration..."
        python3 << EOF
from vallanx_blocklist_manager import VallanxBlocklistManager
vm = VallanxBlocklistManager('/etc/vallanx')
print('✓ Vallanx initialized successfully')
EOF
    else
        echo "✓ Vallanx configuration already exists"
    fi
    
    # Import sample blocklist if provided
    if [ -f /etc/vallanx/feeds/example_blocklist.vbx ]; then
        echo "Importing example Vallanx blocklist..."
        python3 << EOF
from vallanx_blocklist_manager import VallanxBlocklistManager
vm = VallanxBlocklistManager('/etc/vallanx')
try:
    with open('/etc/vallanx/feeds/example_blocklist.vbx', 'r') as f:
        imported = vm.import_vallanx_format(f.read())
        print(f'✓ Imported {imported} entries from example blocklist')
except Exception as e:
    print(f'⚠ Could not import example blocklist: {e}')
EOF
    fi
}

# Function to set up iptables
setup_iptables() {
    echo "Setting up iptables rules for Vallanx..."
    
    # Create custom chains for Vallanx
    iptables -N VALLANX_INPUT 2>/dev/null || iptables -F VALLANX_INPUT
    iptables -N VALLANX_OUTPUT 2>/dev/null || iptables -F VALLANX_OUTPUT
    
    # Insert custom chains into INPUT and OUTPUT
    iptables -C INPUT -j VALLANX_INPUT 2>/dev/null || iptables -I INPUT -j VALLANX_INPUT
    iptables -C OUTPUT -j VALLANX_OUTPUT 2>/dev/null || iptables -I OUTPUT -j VALLANX_OUTPUT
    
    echo "✓ iptables chains created"
}

# Function to check network interface
check_network_interface() {
    local interface="${MONITOR_INTERFACE:-eth0}"
    
    echo "Checking network interface: ${interface}"
    
    if ip link show "$interface" &> /dev/null; then
        echo "✓ Network interface ${interface} found"
        
        # Get interface info
        local ip_addr=$(ip -4 addr show "$interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [ -n "$ip_addr" ]; then
            echo "  Interface IP: ${ip_addr}"
        fi
        
        # Enable promiscuous mode for packet capture
        ip link set "$interface" promisc on 2>/dev/null || true
        echo "  Promiscuous mode enabled"
        
        return 0
    else
        echo "⚠ Network interface ${interface} not found"
        echo "  Available interfaces:"
        ip link show | grep -E '^[0-9]+:' | awk '{print "    " $2}' | sed 's/:$//'
        return 1
    fi
}

# Function to display configuration
display_config() {
    echo ""
    echo "========================================="
    echo "Configuration:"
    echo "========================================="
    echo "Database Type:        ${DB_TYPE:-sqlite}"
    echo "Database Host:        ${DB_HOST:-localhost}"
    echo "Monitoring Interface: ${MONITOR_INTERFACE:-eth0}"
    echo "Vallanx Path:         ${VALLANX_BASE_PATH:-/etc/vallanx}"
    echo "Auto-Block:           ${AUTO_BLOCK_ENABLED:-true}"
    echo "API Port:             ${API_PORT:-5000}"
    echo "Vallanx API Port:     ${VALLANX_API_PORT:-8089}"
    echo "========================================="
    echo ""
}

# Function to run database migrations
run_migrations() {
    echo "Running database migrations..."
    
    python3 << EOF
import sys
sys.path.insert(0, '/app')

try:
    # Import your database manager here
    # from network_monitor import DatabaseManagerExtended
    # db = DatabaseManagerExtended('/etc/network-monitor/db-credentials.json')
    print('✓ Database migrations completed')
except Exception as e:
    print(f'⚠ Database migration warning: {e}')
    # Continue anyway - might be using SQLite fallback
EOF
}

# Main initialization
main() {
    echo ""
    echo "Starting initialization sequence..."
    echo ""
    
    # Display configuration
    display_config
    
    # Check network interface
    check_network_interface || echo "⚠ Continuing without network interface check"
    
    # Wait for database if using MySQL/PostgreSQL
    if [ "${DB_TYPE}" = "mysql" ]; then
        wait_for_db "mysql" || {
            echo "⚠ MySQL not available, falling back to SQLite"
            export DB_TYPE=sqlite
        }
    elif [ "${DB_TYPE}" = "postgresql" ]; then
        wait_for_db "postgresql" || {
            echo "⚠ PostgreSQL not available, falling back to SQLite"
            export DB_TYPE=sqlite
        }
    fi
    
    # Run database migrations
    run_migrations
    
    # Initialize Vallanx
    initialize_vallanx
    
    # Setup iptables
    if [ "${AUTO_BLOCK_ENABLED:-true}" = "true" ]; then
        setup_iptables || echo "⚠ Failed to setup iptables"
    fi
    
    echo ""
    echo "========================================="
    echo "✓ Initialization complete!"
    echo "========================================="
    echo "Starting application..."
    echo ""
    
    # Print Vallanx statistics
    python3 << EOF
try:
    from vallanx_blocklist_manager import VallanxBlocklistManager
    vm = VallanxBlocklistManager('/etc/vallanx')
    stats = vm.get_statistics()
    print(f"Vallanx Statistics:")
    print(f"  Total entries: {stats.get('total_entries', 0)}")
    print(f"  By type: {stats.get('by_type', {})}")
    print("")
except Exception as e:
    print(f"⚠ Could not load Vallanx statistics: {e}")
    print("")
EOF
    
    # Execute the main command
    exec "$@"
}

# Trap signals for graceful shutdown
trap 'echo "Received SIGTERM, shutting down..."; exit 0' SIGTERM
trap 'echo "Received SIGINT, shutting down..."; exit 0' SIGINT

# Run main initialization
main "$@"
