#!/bin/bash
################################################################################
# Vallanx Network Monitor - Quick Start Script
# This script starts the standalone network monitor
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "========================================================================="
echo "  Vallanx Network Monitor - Standalone Version"
echo "========================================================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}ERROR: This script must be run as root for packet capture${NC}"
    echo "Please run: sudo ./start.sh"
    exit 1
fi

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo -e "${GREEN}✓${NC} Python version: $PYTHON_VERSION"

# Check if dependencies are installed
echo "Checking dependencies..."

if ! python3 -c "import flask" 2>/dev/null; then
    echo -e "${YELLOW}⚠${NC} Flask not found. Installing dependencies..."
    pip3 install -r requirements.txt
else
    echo -e "${GREEN}✓${NC} Dependencies installed"
fi

# Get network interface
DEFAULT_INTERFACE="eth0"

# Try to detect available interfaces
if command -v ip &> /dev/null; then
    echo ""
    echo "Available network interfaces:"
    ip -br link show | grep -v "lo" | awk '{print "  - " $1}'
    echo ""
fi

# Ask for interface
read -p "Enter network interface to monitor (default: $DEFAULT_INTERFACE): " INTERFACE
INTERFACE=${INTERFACE:-$DEFAULT_INTERFACE}

# Ask for port
read -p "Enter web interface port (default: 5000): " PORT
PORT=${PORT:-5000}

echo ""
echo "========================================================================="
echo "  Starting Monitor"
echo "========================================================================="
echo "  Interface: $INTERFACE"
echo "  Web Port:  $PORT"
echo "========================================================================="
echo ""

# Create data directory
mkdir -p data/vallanx

# Start the monitor
python3 standalone_monitor.py --interface "$INTERFACE" --port "$PORT"
