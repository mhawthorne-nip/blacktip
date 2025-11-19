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

fix_permissions_quick() {
    # Fix critical permissions needed for services to run
    
    # Database directory - SQLite needs write access to create journal/lock files
    mkdir -p /var/lib/blacktip
    chown root:blacktip /var/lib/blacktip
    chmod 775 /var/lib/blacktip
    
    # Database file
    if [ -f "${DB_PATH}" ]; then
        chown root:blacktip "${DB_PATH}"
        chmod 664 "${DB_PATH}"
    fi
    
    # .env file
    if [ -f "${WEB_DIR}/.env" ]; then
        chown blacktip:blacktip "${WEB_DIR}/.env"
        chmod 640 "${WEB_DIR}/.env"
    fi
    
    # Runtime directory
    mkdir -p /run/blacktip
    chown blacktip:blacktip /run/blacktip
    chmod 755 /run/blacktip
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
    
    # Configure git to handle permissions properly
    git config --local core.fileMode false
    git config --local safe.directory "${APP_DIR}"
    
    # Ensure git directory has correct permissions
    chown -R root:root .git
    chmod -R 775 .git
    chmod -R g+w .git
    
    # Stash any local changes to avoid conflicts
    git stash --quiet || true
    
    # Fetch latest changes
    git fetch origin
    
    # Check if there are updates
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse origin/main)
    
    if [ "$LOCAL" = "$REMOTE" ]; then
        print_status "Already up to date"
    else
        print_status "New changes detected, pulling..."
        git pull origin main
    fi
    
    # Fix ownership after pull
    chown -R root:root "${APP_DIR}"
    
    # Make .git writable to avoid permission errors
    chmod -R 775 .git
    chmod -R g+w .git
    
    # Make scripts executable
    chmod +x "${APP_DIR}"/*.sh 2>/dev/null || true
    chmod +x "${WEB_DIR}"/*.sh 2>/dev/null || true
    
    # Install speedtest binary
    if [ -f "${APP_DIR}/bin/speedtest" ]; then
        print_status "Installing speedtest binary to /usr/local/bin..."
        cp "${APP_DIR}/bin/speedtest" /usr/local/bin/speedtest
        chmod +x /usr/local/bin/speedtest
        chown root:root /usr/local/bin/speedtest
        print_status "✓ Speedtest binary installed"
    else
        print_warning "Speedtest binary not found at ${APP_DIR}/bin/speedtest"
    fi
    
    # Restore web frontend ownership
    chown -R blacktip:blacktip "${WEB_DIR}"
    
    # Protect .env file if it exists
    if [ -f "${WEB_DIR}/.env" ]; then
        chown blacktip:blacktip "${WEB_DIR}/.env"
        chmod 600 "${WEB_DIR}/.env"
    fi
    
    print_status "Code updated successfully"
}

update_dependencies() {
    print_status "Updating dependencies..."

    cd "${APP_DIR}"

    # Determine pip flags (Ubuntu 24.04 needs --break-system-packages)
    PIP_FLAGS=""
    if pip3 install --help 2>&1 | grep -q "break-system-packages"; then
        PIP_FLAGS="--break-system-packages"
    fi

    # Check if main requirements changed
    if git diff HEAD@{1} HEAD -- requirements.txt 2>/dev/null | grep -q '^[+-]'; then
        print_status "Main requirements changed, updating core packages..."
        pip3 install -r requirements.txt $PIP_FLAGS

        # Reinstall in editable mode
        print_status "Reinstalling blacktip package..."
        pip3 install -e . $PIP_FLAGS
    else
        print_status "No core dependency changes detected"
    fi

    # Check web frontend requirements
    cd "${WEB_DIR}"
    if git diff HEAD@{1} HEAD -- requirements.txt 2>/dev/null | grep -q '^[+-]'; then
        print_status "Web frontend requirements changed, updating packages..."
        pip3 install -r requirements.txt $PIP_FLAGS
    else
        print_status "No web frontend dependency changes detected"
    fi
}

build_frontend() {
    print_status "Building React frontend..."

    cd "${WEB_DIR}/client"

    # Check if Node.js is installed
    if ! command -v node &> /dev/null; then
        print_error "Node.js is not installed. Please install Node.js 18+ first."
        exit 1
    fi

    # Check Node.js version
    NODE_VERSION=$(node -v | sed 's/v//' | cut -d. -f1)
    if [ "$NODE_VERSION" -lt 18 ]; then
        print_warning "Node.js version $NODE_VERSION detected. Version 18+ is recommended."
    fi

    # Install npm dependencies if package.json changed or node_modules missing
    if [ ! -d "node_modules" ] || git diff HEAD@{1} HEAD -- package.json 2>/dev/null | grep -q '^[+-]'; then
        print_status "Installing npm dependencies..."
        npm install
    else
        print_status "No package.json changes detected, skipping npm install"
    fi

    # Build the React app
    print_status "Running production build..."
    npm run build

    # Verify build output exists
    if [ -d "dist" ] && [ -f "dist/index.html" ]; then
        print_status "✓ Frontend build completed successfully"

        # Set correct permissions for the dist directory
        chown -R blacktip:blacktip dist/
        chmod -R 755 dist/

        # Show build stats
        BUILD_SIZE=$(du -sh dist/ | cut -f1)
        print_status "  Build size: ${BUILD_SIZE}"
    else
        print_error "✗ Frontend build failed - dist/index.html not found"
        exit 1
    fi

    cd "${APP_DIR}"
}

restart_services() {
    print_status "Restarting services..."
    
    # Stop services first before fixing permissions
    print_status "Stopping services..."
    systemctl stop blacktip-web.service || true
    systemctl stop blacktip.service || true
    
    # Fix permissions while services are stopped
    print_status "Fixing permissions..."
    fix_permissions_quick
    
    # Restart main scanner service
    print_status "Starting blacktip scanner service..."
    systemctl start blacktip.service
    
    # Wait for service to stabilize
    sleep 3
    
    # Check if scanner service is running
    if systemctl is-active --quiet blacktip.service; then
        print_status "✓ Scanner service started successfully"
    else
        print_error "✗ Scanner service failed to start"
        journalctl -u blacktip.service -n 20 --no-pager
        exit 1
    fi
    
    # Start web service
    print_status "Starting web frontend service..."
    systemctl start blacktip-web.service
    
    # Wait for service to start
    sleep 2
    
    # Check if web service is running
    if systemctl is-active --quiet blacktip-web.service; then
        print_status "✓ Web service started successfully"
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

    # Verify React frontend build exists
    if [ -f "${WEB_DIR}/client/dist/index.html" ]; then
        print_status "✓ React frontend build exists"
        FRONTEND_SIZE=$(du -sh "${WEB_DIR}/client/dist" | cut -f1 2>/dev/null || echo "unknown")
        print_status "  Build size: ${FRONTEND_SIZE}"
    else
        print_warning "✗ React frontend build not found at ${WEB_DIR}/client/dist"
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

    print_section "Frontend Build"
    build_frontend

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
