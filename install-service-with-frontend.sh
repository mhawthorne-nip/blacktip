#!/bin/bash
#
# Install Blacktip service with state monitor and web frontend
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}Blacktip Service Installation${NC}"
echo "============================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run with: sudo $0"
    exit 1
fi

# Detect script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo -e "Script directory: ${BLUE}$SCRIPT_DIR${NC}"
echo ""

# Install location
INSTALL_DIR="/opt/blacktip"
SERVICE_FILE="/etc/systemd/system/blacktip.service"

# Step 1: Check if blacktip is installed
echo -e "${YELLOW}[1/8]${NC} Checking blacktip installation..."
if ! command -v blacktip &> /dev/null; then
    echo -e "${RED}Error: blacktip command not found${NC}"
    echo "Please install blacktip first with: pip install -e ."
    exit 1
fi

if ! command -v blacktip-state-monitor &> /dev/null; then
    echo -e "${RED}Error: blacktip-state-monitor command not found${NC}"
    echo "Please install blacktip first with: pip install -e ."
    exit 1
fi

echo -e "${GREEN}✓${NC} blacktip and blacktip-state-monitor are installed"
echo "  blacktip: $(which blacktip)"
echo "  blacktip-state-monitor: $(which blacktip-state-monitor)"
echo ""

# Step 2: Check web frontend dependencies
echo -e "${YELLOW}[2/8]${NC} Checking web frontend dependencies..."

# Check if all dependencies are available
FLASK_OK=false
FLASK_CORS_OK=false

if python3 -c "import flask" 2>/dev/null; then
    FLASK_OK=true
fi

if python3 -c "import flask_cors" 2>/dev/null; then
    FLASK_CORS_OK=true
fi

if [ "$FLASK_OK" = false ] || [ "$FLASK_CORS_OK" = false ]; then
    echo -e "${YELLOW}Installing missing web frontend dependencies...${NC}"
    
    # Try pip3 with --break-system-packages first
    if pip3 install -r "$SCRIPT_DIR/web-frontend/requirements.txt" --break-system-packages 2>/dev/null; then
        echo -e "${GREEN}✓${NC} Dependencies installed via pip3"
    # If that fails, try using system package manager
    elif command -v apt-get &> /dev/null; then
        echo -e "${YELLOW}Trying system package manager (apt)...${NC}"
        apt-get update -qq
        apt-get install -y python3-flask python3-flask-cors
        echo -e "${GREEN}✓${NC} Dependencies installed via apt"
    else
        echo -e "${RED}Error: Could not install dependencies${NC}"
        echo "Please install manually:"
        echo "  sudo apt install python3-flask python3-flask-cors"
        echo "  OR"
        echo "  pip3 install -r web-frontend/requirements.txt --break-system-packages"
        exit 1
    fi
else
    echo -e "${GREEN}✓${NC} All dependencies already installed"
fi

echo ""

# Step 3: Create installation directory
echo -e "${YELLOW}[3/8]${NC} Setting up installation directory..."
mkdir -p "$INSTALL_DIR"

# Copy web frontend
if [ -d "$SCRIPT_DIR/web-frontend" ]; then
    cp -r "$SCRIPT_DIR/web-frontend" "$INSTALL_DIR/"
    echo -e "${GREEN}✓${NC} Copied web-frontend to $INSTALL_DIR/"
else
    echo -e "${RED}Error: web-frontend directory not found${NC}"
    exit 1
fi

# Create necessary directories
mkdir -p /var/lib/blacktip
mkdir -p /var/log/blacktip
mkdir -p /var/run/blacktip

# Set permissions
chown -R root:root /var/lib/blacktip /var/log/blacktip /var/run/blacktip
chmod 755 /var/lib/blacktip /var/log/blacktip /var/run/blacktip

echo -e "${GREEN}✓${NC} Created directories:"
echo "  /var/lib/blacktip (database storage)"
echo "  /var/log/blacktip (log files)"
echo "  /var/run/blacktip (PID files)"
echo ""

# Step 4: Install systemd service
echo -e "${YELLOW}[4/8]${NC} Installing systemd service..."

# Stop existing service if running
if systemctl is-active --quiet blacktip.service; then
    echo "Stopping existing blacktip service..."
    systemctl stop blacktip.service
fi

# Copy service file
cp "$SCRIPT_DIR/blacktip.service" "$SERVICE_FILE"
echo -e "${GREEN}✓${NC} Copied service file to $SERVICE_FILE"
echo ""

# Step 5: Reload systemd
echo -e "${YELLOW}[5/8]${NC} Reloading systemd daemon..."
systemctl daemon-reload
echo -e "${GREEN}✓${NC} Systemd daemon reloaded"
echo ""

# Step 6: Enable service
echo -e "${YELLOW}[6/8]${NC} Enabling blacktip service..."
systemctl enable blacktip.service
echo -e "${GREEN}✓${NC} Service enabled (will start on boot)"
echo ""

# Step 7: Display configuration summary
echo -e "${YELLOW}[7/8]${NC} Configuration Summary"
echo "============================================"
echo ""
echo "Service components:"
echo "  1. Blacktip Scanner  - ARP monitoring and nmap scanning"
echo "  2. State Monitor     - Device online/offline tracking (with active probing)"
echo "  3. Web Frontend      - Dashboard at http://localhost:5000"
echo ""
echo "Configuration files:"
echo "  Service: $SERVICE_FILE"
echo "  Database: /var/lib/blacktip/blacktip.db"
echo "  Web app: $INSTALL_DIR/web-frontend/"
echo ""
echo "Log files:"
echo "  Main service: /var/log/blacktip/service.log"
echo "  Scanner: /var/log/blacktip/blacktip.log"
echo "  State monitor: /var/log/blacktip/state-monitor.log"
echo "  Web frontend: /var/log/blacktip/web-frontend.log"
echo ""

# Step 8: Offer to start service
echo -e "${YELLOW}[8/8]${NC} Start service now?"
read -p "Start blacktip service now? [Y/n] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    echo "Starting blacktip service..."
    systemctl start blacktip.service
    
    # Wait a moment for services to start
    sleep 3
    
    # Check status
    if systemctl is-active --quiet blacktip.service; then
        echo -e "${GREEN}✓${NC} Service started successfully!"
        echo ""
        echo "Check status with: sudo systemctl status blacktip.service"
        echo ""
        
        # Show service info
        echo "Service information:"
        systemctl status blacktip.service --no-pager -l | head -20
        echo ""
        
        # Check if web frontend is accessible
        echo "Checking web frontend..."
        sleep 2
        if curl -s http://localhost:5000/api/health > /dev/null 2>&1; then
            echo -e "${GREEN}✓${NC} Web frontend is running at http://localhost:5000"
        else
            echo -e "${YELLOW}⚠${NC}  Web frontend may still be starting..."
            echo "   Check logs: tail -f /var/log/blacktip/web-frontend.log"
        fi
    else
        echo -e "${RED}✗${NC} Service failed to start"
        echo "Check logs with: journalctl -u blacktip.service -n 50"
    fi
else
    echo "Service not started. Start manually with:"
    echo "  sudo systemctl start blacktip.service"
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "Useful commands:"
echo "  Start:   sudo systemctl start blacktip.service"
echo "  Stop:    sudo systemctl stop blacktip.service"
echo "  Restart: sudo systemctl restart blacktip.service"
echo "  Status:  sudo systemctl status blacktip.service"
echo "  Logs:    sudo journalctl -u blacktip.service -f"
echo ""
echo "Access web dashboard at: http://localhost:5000"
echo ""
