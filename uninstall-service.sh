#!/bin/bash
#
# Blacktip Service Uninstallation Script
# This script removes Blacktip systemd service and optionally removes data/logs
#
# Usage: sudo bash uninstall-service.sh [--keep-data]
#   --keep-data: Keep database and log files (only remove service)
#

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Parse arguments
KEEP_DATA=false
if [ "$1" = "--keep-data" ]; then
    KEEP_DATA=true
    echo -e "${YELLOW}Data preservation mode: Database and logs will be kept${NC}"
fi

echo -e "${GREEN}Starting Blacktip service uninstallation...${NC}"

# Step 1: Stop the service
echo -e "\n${YELLOW}Step 1: Stopping Blacktip service...${NC}"
if systemctl is-active --quiet blacktip.service; then
    systemctl stop blacktip.service
    echo -e "${GREEN}✓ Service stopped${NC}"
else
    echo -e "${YELLOW}Service is not running${NC}"
fi

# Step 2: Disable the service
echo -e "\n${YELLOW}Step 2: Disabling Blacktip service...${NC}"
if systemctl is-enabled --quiet blacktip.service; then
    systemctl disable blacktip.service
    echo -e "${GREEN}✓ Service disabled${NC}"
else
    echo -e "${YELLOW}Service is not enabled${NC}"
fi

# Step 3: Remove service file
echo -e "\n${YELLOW}Step 3: Removing service file...${NC}"
if [ -f /etc/systemd/system/blacktip.service ]; then
    rm /etc/systemd/system/blacktip.service
    echo -e "${GREEN}✓ Service file removed${NC}"
else
    echo -e "${YELLOW}Service file not found${NC}"
fi

# Step 4: Reload systemd
echo -e "\n${YELLOW}Step 4: Reloading systemd...${NC}"
systemctl daemon-reload
systemctl reset-failed
echo -e "${GREEN}✓ Systemd configuration reloaded${NC}"

# Step 5: Remove log rotation configuration
echo -e "\n${YELLOW}Step 5: Removing log rotation configuration...${NC}"
if [ -f /etc/logrotate.d/blacktip ]; then
    rm /etc/logrotate.d/blacktip
    echo -e "${GREEN}✓ Log rotation configuration removed${NC}"
else
    echo -e "${YELLOW}Log rotation configuration not found${NC}"
fi

# Step 6: Remove data and logs (if not keeping)
if [ "$KEEP_DATA" = false ]; then
    echo -e "\n${YELLOW}Step 6: Removing data and logs...${NC}"
    
    if [ -d /var/lib/blacktip ]; then
        rm -rf /var/lib/blacktip
        echo -e "${GREEN}✓ Database directory removed${NC}"
    fi
    
    if [ -d /var/log/blacktip ]; then
        rm -rf /var/log/blacktip
        echo -e "${GREEN}✓ Log directory removed${NC}"
    fi
    
    if [ -d /opt/blacktip ]; then
        rm -rf /opt/blacktip
        echo -e "${GREEN}✓ Application directory removed${NC}"
    fi
else
    echo -e "\n${YELLOW}Step 6: Preserving data and logs...${NC}"
    echo -e "${GREEN}✓ Database preserved at: /var/lib/blacktip${NC}"
    echo -e "${GREEN}✓ Logs preserved at: /var/log/blacktip${NC}"
fi

# Step 7: Uninstall package (optional confirmation)
echo -e "\n${YELLOW}Step 7: Uninstalling Blacktip package...${NC}"
read -p "Do you want to uninstall the Blacktip Python package? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    if command -v blacktip &> /dev/null; then
        # Try with --break-system-packages flag first (for modern Ubuntu/Debian)
        if pip uninstall -y --break-system-packages blacktip 2>/dev/null; then
            echo -e "${GREEN}✓ Blacktip package uninstalled${NC}"
        elif pip uninstall -y blacktip 2>/dev/null; then
            echo -e "${GREEN}✓ Blacktip package uninstalled${NC}"
        else
            echo -e "${RED}Failed to uninstall. Try manually: sudo pip uninstall blacktip${NC}"
        fi
    else
        echo -e "${YELLOW}Blacktip package not found${NC}"
    fi
else
    echo -e "${YELLOW}Keeping Blacktip package installed${NC}"
fi

# Display summary
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Blacktip Service Uninstallation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

if [ "$KEEP_DATA" = true ]; then
    echo -e "${YELLOW}Preserved data locations:${NC}"
    echo "  Database: /var/lib/blacktip/blacktip.db"
    echo "  Logs:     /var/log/blacktip/"
    echo ""
    echo "To completely remove data, run:"
    echo "  sudo rm -rf /var/lib/blacktip /var/log/blacktip /opt/blacktip"
else
    echo -e "${GREEN}All service files, data, and logs have been removed.${NC}"
fi

echo ""
echo -e "${GREEN}The Blacktip service has been successfully uninstalled.${NC}"
echo ""
