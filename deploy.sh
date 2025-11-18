#!/bin/bash

# Blacktip Complete Deployment Script
# This script automates the full deployment process for both the Blacktip scanner and web frontend

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
APP_DIR="/opt/blacktip"
WEB_DIR="${APP_DIR}/web-frontend"
BACKUP_DIR="/var/backups/blacktip"
DB_PATH="/var/lib/blacktip/blacktip.db"

# Functions
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_section() {
    echo -e "\n${BLUE}==== $1 ====${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

create_backup() {
    print_status "Creating backup..."
    
    # Create backup directory if it doesn't exist
    mkdir -p "${BACKUP_DIR}"
    
    # Backup timestamp
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    
    # Backup database
    if [ -f "${DB_PATH}" ]; then
        cp "${DB_PATH}" "${BACKUP_DIR}/blacktip_${TIMESTAMP}.db"
        print_status "Database backed up to ${BACKUP_DIR}/blacktip_${TIMESTAMP}.db"
    else
        print_warning "Database not found at ${DB_PATH}, skipping database backup"
    fi
    
    # Backup .env file
    if [ -f "${WEB_DIR}/.env" ]; then
        cp "${WEB_DIR}/.env" "${BACKUP_DIR}/.env_${TIMESTAMP}"
        print_status "Configuration backed up"
    fi
}

update_code() {
    print_status "Updating code from repository..."
    
    cd "${APP_DIR}"
    
    # Fetch latest changes
    git fetch origin
    
    # Check if there are updates
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse origin/main)
    
    if [ "$LOCAL" = "$REMOTE" ]; then
        print_status "Already up to date"
        return 0
    fi
    
    print_status "New changes detected, pulling..."
    git pull origin main
    
    print_status "Code updated successfully"
}

update_dependencies() {
    print_status "Updating dependencies..."
    
    cd "${APP_DIR}"
    
    # Check if main requirements changed
    if git diff HEAD@{1} HEAD -- requirements.txt | grep -q '^[+-]'; then
        print_status "Main requirements changed, updating core packages..."
        pip3 install -r requirements.txt --break-system-packages
        
        # Reinstall in editable mode
        print_status "Reinstalling blacktip package..."
        pip3 install -e . --break-system-packages
    else
        print_status "No core dependency changes detected"
    fi
    
    # Check web frontend requirements
    cd "${WEB_DIR}"
    if git diff HEAD@{1} HEAD -- requirements.txt | grep -q '^[+-]'; then
        print_status "Web frontend requirements changed, updating packages..."
        pip3 install -r requirements.txt --break-system-packages
    else
        print_status "No web frontend dependency changes detected"
    fi
}

restart_services() {
    print_status "Restarting services..."
    
    # Restart main scanner service
    print_status "Restarting blacktip scanner service..."
    systemctl restart blacktip.service
    
    # Wait for service to stabilize
    sleep 3
    
    # Check if scanner service is running
    if systemctl is-active --quiet blacktip.service; then
        print_status "✓ Scanner service restarted successfully"
    else
        print_error "✗ Scanner service failed to start"
        journalctl -u blacktip.service -n 20 --no-pager
        exit 1
    fi
    
    # Restart web service
    print_status "Restarting web frontend service..."
    systemctl restart blacktip-web.service
    
    # Wait for service to start
    sleep 2
    
    # Check if web service is running
    if systemctl is-active --quiet blacktip-web.service; then
        print_status "✓ Web service restarted successfully"
    else
        print_error "✗ Web service failed to start"
        journalctl -u blacktip-web.service -n 20 --no-pager
        exit 1
    fi
}

verify_deployment() {
    print_status "Verifying deployment..."
    
    # Check scanner service status
    if systemctl is-active --quiet blacktip.service; then
        print_status "✓ Scanner service is running"
    else
        print_error "✗ Scanner service is not running"
        return 1
    fi
    
    # Check web service status
    if systemctl is-active --quiet blacktip-web.service; then
        print_status "✓ Web service is running"
    else
        print_error "✗ Web service is not running"
        return 1
    fi
    
    # Check if Gunicorn is listening
    if ss -tlnp | grep -q ':5000'; then
        print_status "✓ Gunicorn is listening on port 5000"
    else
        print_warning "✗ Gunicorn is not listening on port 5000"
    fi
    
    # Verify database exists and has correct permissions
    if [ -f "${DB_PATH}" ]; then
        print_status "✓ Database file exists"
        DB_PERMS=$(stat -c "%a" "${DB_PATH}" 2>/dev/null || echo "unknown")
        DB_OWNER=$(stat -c "%U:%G" "${DB_PATH}" 2>/dev/null || echo "unknown")
        print_status "  Permissions: ${DB_PERMS}, Owner: ${DB_OWNER}"
    else
        print_warning "✗ Database file not found (may still be initializing)"
    fi
    
    # Test health endpoint
    if command -v curl &> /dev/null; then
        RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:5000/api/health 2>/dev/null || echo "000")
        if [ "$RESPONSE" = "200" ]; then
            print_status "✓ Health endpoint responding (HTTP $RESPONSE)"
        else
            print_warning "✗ Health endpoint not responding (HTTP $RESPONSE)"
        fi
    fi
}

show_logs() {
    print_section "Recent Scanner Logs"
    journalctl -u blacktip.service -n 10 --no-pager
    
    echo
    print_section "Recent Web Service Logs"
    journalctl -u blacktip-web.service -n 10 --no-pager
}

# Main deployment process
main() {
    echo "================================================"
    echo "  Blacktip Complete Deployment Script"
    echo "  Scanner + Web Frontend"
    echo "================================================"
    echo
    
    check_root
    
    print_section "Backup"
    create_backup
    
    print_section "Code Update"
    update_code
    
    print_section "Dependencies"
    update_dependencies
    
    print_section "Service Restart"
    restart_services
    
    print_section "Verification"
    verify_deployment
    
    # Show recent logs
    echo
    show_logs
    
    echo
    echo "================================================"
    print_status "Deployment completed successfully! 🎉"
    echo "================================================"
    echo
    echo "Useful commands:"
    echo "  Scanner logs:     sudo journalctl -u blacktip.service -f"
    echo "  Web logs:         sudo journalctl -u blacktip-web.service -f"
    echo "  Scanner status:   sudo systemctl status blacktip.service"
    echo "  Web status:       sudo systemctl status blacktip-web.service"
    echo "  Both services:    sudo systemctl status 'blacktip*'"
}

# Run main function
main
