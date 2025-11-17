#!/bin/bash
#
# Blacktip Service Installation Script
# This script installs and configures Blacktip as a systemd service on Ubuntu
#
# Usage: sudo bash install-service.sh [interface]
#   interface: Optional network interface to monitor (e.g., eth0, wlan0)
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

# Get the script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Optional interface parameter
INTERFACE=""
if [ -n "$1" ]; then
    INTERFACE="$1"
    echo -e "${GREEN}Configuring for interface: ${INTERFACE}${NC}"
fi

echo -e "${GREEN}Starting Blacktip service installation...${NC}"

# Step 1: Install Blacktip package
echo -e "\n${YELLOW}Step 1: Installing Blacktip package...${NC}"
cd "$SCRIPT_DIR"

# Try pip install with --break-system-packages flag for modern Ubuntu/Debian
if pip install --break-system-packages . 2>/dev/null; then
    echo -e "${GREEN}✓ Installed using pip with --break-system-packages${NC}"
elif pip install . 2>/dev/null; then
    echo -e "${GREEN}✓ Installed using pip${NC}"
else
    echo -e "${RED}Error: Failed to install Blacktip package${NC}"
    echo -e "${YELLOW}Try manually: sudo pip install --break-system-packages .${NC}"
    exit 1
fi

if ! command -v blacktip &> /dev/null; then
    echo -e "${RED}Error: blacktip command not found after installation${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Blacktip installed successfully${NC}"

# Step 2: Create directories
echo -e "\n${YELLOW}Step 2: Creating required directories...${NC}"
mkdir -p /var/lib/blacktip
chmod 755 /var/lib/blacktip
echo -e "${GREEN}✓ Created /var/lib/blacktip${NC}"

mkdir -p /var/log/blacktip
chmod 755 /var/log/blacktip
echo -e "${GREEN}✓ Created /var/log/blacktip${NC}"

mkdir -p /opt/blacktip
chmod 755 /opt/blacktip
echo -e "${GREEN}✓ Created /opt/blacktip${NC}"

# Step 3: Install service file
echo -e "\n${YELLOW}Step 3: Installing systemd service file...${NC}"
if [ -f "$SCRIPT_DIR/blacktip.service" ]; then
    # If interface is specified, modify the service file
    if [ -n "$INTERFACE" ]; then
        sed "s|--interval 300|--interface $INTERFACE --interval 300|g" \
            "$SCRIPT_DIR/blacktip.service" > /etc/systemd/system/blacktip.service
        echo -e "${GREEN}✓ Service file installed with interface: ${INTERFACE}${NC}"
    else
        cp "$SCRIPT_DIR/blacktip.service" /etc/systemd/system/
        echo -e "${GREEN}✓ Service file installed${NC}"
    fi
    chmod 644 /etc/systemd/system/blacktip.service
else
    echo -e "${RED}Error: blacktip.service file not found in $SCRIPT_DIR${NC}"
    exit 1
fi

# Step 4: Set up log rotation
echo -e "\n${YELLOW}Step 4: Setting up log rotation...${NC}"
cat > /etc/logrotate.d/blacktip << 'EOF'
/var/log/blacktip/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        systemctl reload blacktip.service >/dev/null 2>&1 || true
    endscript
}
EOF
echo -e "${GREEN}✓ Log rotation configured${NC}"

# Step 5: Reload systemd and enable service
echo -e "\n${YELLOW}Step 5: Configuring systemd...${NC}"
systemctl daemon-reload
echo -e "${GREEN}✓ Systemd configuration reloaded${NC}"

systemctl enable blacktip.service
echo -e "${GREEN}✓ Blacktip service enabled for auto-start on boot${NC}"

# Step 6: Start the service
echo -e "\n${YELLOW}Step 6: Starting Blacktip service...${NC}"
systemctl start blacktip.service

# Wait a moment for the service to start
sleep 2

# Check service status
if systemctl is-active --quiet blacktip.service; then
    echo -e "${GREEN}✓ Blacktip service started successfully${NC}"
else
    echo -e "${RED}Warning: Service may have failed to start${NC}"
    echo -e "${YELLOW}Check status with: sudo systemctl status blacktip.service${NC}"
fi

# Display summary
echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}Blacktip Service Installation Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "Service Status: ${GREEN}$(systemctl is-active blacktip.service)${NC}"
echo -e "Auto-start on Boot: ${GREEN}$(systemctl is-enabled blacktip.service)${NC}"
echo ""
echo "Useful Commands:"
echo "  Check status:     sudo systemctl status blacktip.service"
echo "  View logs:        sudo journalctl -u blacktip.service -f"
echo "  View log file:    sudo tail -f /var/log/blacktip/blacktip.log"
echo "  Stop service:     sudo systemctl stop blacktip.service"
echo "  Restart service:  sudo systemctl restart blacktip.service"
echo "  Query database:   blacktip --datafile /var/lib/blacktip/blacktip.db --query <address>"
echo ""
echo -e "Database location: ${YELLOW}/var/lib/blacktip/blacktip.db${NC}"
echo -e "Log file location: ${YELLOW}/var/log/blacktip/blacktip.log${NC}"
echo -e "Documentation:     ${YELLOW}$SCRIPT_DIR/SYSTEMD_SETUP.md${NC}"
echo ""
echo -e "${YELLOW}Note: The service is now running and will auto-start on system reboot.${NC}"
echo ""
