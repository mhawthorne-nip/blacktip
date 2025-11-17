#!/bin/bash
#
# Uninstall Blacktip service with state monitor and web frontend
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Blacktip Service Uninstallation${NC}"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run with: sudo $0"
    exit 1
fi

SERVICE_FILE="/etc/systemd/system/blacktip.service"

# Check if service exists
if [ ! -f "$SERVICE_FILE" ]; then
    echo -e "${YELLOW}Warning: Service file not found at $SERVICE_FILE${NC}"
    echo "Service may not be installed"
    exit 0
fi

# Step 1: Stop the service
echo -e "${YELLOW}[1/5]${NC} Stopping blacktip service..."
if systemctl is-active --quiet blacktip.service; then
    systemctl stop blacktip.service
    echo -e "${GREEN}✓${NC} Service stopped"
else
    echo "Service is not running"
fi
echo ""

# Step 2: Disable the service
echo -e "${YELLOW}[2/5]${NC} Disabling blacktip service..."
if systemctl is-enabled --quiet blacktip.service; then
    systemctl disable blacktip.service
    echo -e "${GREEN}✓${NC} Service disabled"
else
    echo "Service is not enabled"
fi
echo ""

# Step 3: Remove service file
echo -e "${YELLOW}[3/5]${NC} Removing service file..."
rm -f "$SERVICE_FILE"
echo -e "${GREEN}✓${NC} Removed $SERVICE_FILE"
echo ""

# Step 4: Reload systemd
echo -e "${YELLOW}[4/5]${NC} Reloading systemd daemon..."
systemctl daemon-reload
systemctl reset-failed
echo -e "${GREEN}✓${NC} Systemd daemon reloaded"
echo ""

# Step 5: Clean up PID files
echo -e "${YELLOW}[5/5]${NC} Cleaning up..."
rm -f /var/run/blacktip/*.pid
echo -e "${GREEN}✓${NC} Removed PID files"
echo ""

echo -e "${GREEN}Uninstallation complete!${NC}"
echo ""
echo "Note: The following were NOT removed:"
echo "  - Database: /var/lib/blacktip/blacktip.db"
echo "  - Logs: /var/log/blacktip/"
echo "  - Installation: /opt/blacktip/"
echo ""
echo "To completely remove all data, run:"
echo "  sudo rm -rf /var/lib/blacktip"
echo "  sudo rm -rf /var/log/blacktip"
echo "  sudo rm -rf /var/run/blacktip"
echo "  sudo rm -rf /opt/blacktip"
echo ""
