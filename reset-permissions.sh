#!/bin/bash

# Blacktip Permissions Reset Script
# This script resets all file and directory permissions to the correct values
# for the Blacktip scanner and web frontend

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_section() {
    echo -e "\n${BLUE}==== $1 ====${NC}"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

echo "================================================"
echo "  Blacktip Permissions Reset Script"
echo "================================================"
echo

# 1. Application Files
print_section "Application Files"

print_status "Setting ownership for application directory..."
chown -R root:root /opt/blacktip

# Fix git directory permissions to allow git operations
print_status "Fixing git directory permissions..."
chown -R root:root /opt/blacktip/.git
chmod -R 755 /opt/blacktip/.git

chmod -R 755 /opt/blacktip

print_status "Setting web frontend ownership..."
chown -R blacktip:blacktip /opt/blacktip/web-frontend
chmod -R 755 /opt/blacktip/web-frontend

# Protect .env file
if [ -f /opt/blacktip/web-frontend/.env ]; then
    print_status "Securing .env file..."
    chown blacktip:blacktip /opt/blacktip/web-frontend/.env
    chmod 600 /opt/blacktip/web-frontend/.env
fi

# Make scripts executable
print_status "Making scripts executable..."
chmod +x /opt/blacktip/deploy.sh 2>/dev/null || true
chmod +x /opt/blacktip/web-frontend/deploy.sh 2>/dev/null || true
chmod +x /opt/blacktip/web-frontend/fix-permissions.sh 2>/dev/null || true

# 2. Database Directory
print_section "Database Directory & Files"

print_status "Setting database directory permissions..."
chown root:blacktip /var/lib/blacktip
chmod 775 /var/lib/blacktip

if [ -f /var/lib/blacktip/blacktip.db ]; then
    print_status "Setting database file permissions..."
    chown root:blacktip /var/lib/blacktip/blacktip.db
    chmod 664 /var/lib/blacktip/blacktip.db
    ls -lh /var/lib/blacktip/blacktip.db
else
    print_status "Database file not found (will be created by scanner service)"
fi

# 3. Log Directory
print_section "Log Directory"

print_status "Setting log directory permissions..."
mkdir -p /var/log/blacktip
chown -R blacktip:blacktip /var/log/blacktip
chmod 755 /var/log/blacktip

# Create log files if they don't exist
touch /var/log/blacktip/gunicorn-access.log
touch /var/log/blacktip/gunicorn-error.log
chown blacktip:blacktip /var/log/blacktip/gunicorn-access.log
chown blacktip:blacktip /var/log/blacktip/gunicorn-error.log
chmod 644 /var/log/blacktip/gunicorn-access.log
chmod 644 /var/log/blacktip/gunicorn-error.log

# Set permissions on existing log files
if ls /var/log/blacktip/*.log >/dev/null 2>&1; then
    chown blacktip:blacktip /var/log/blacktip/*.log
    chmod 644 /var/log/blacktip/*.log
fi

# 4. Runtime Directory
print_section "Runtime Directory"

print_status "Installing tmpfiles.d configuration..."
if [ -f /opt/blacktip/web-frontend/blacktip-tmpfiles.conf ]; then
    cp /opt/blacktip/web-frontend/blacktip-tmpfiles.conf /etc/tmpfiles.d/blacktip.conf
    print_status "Creating runtime directory..."
    systemd-tmpfiles --create /etc/tmpfiles.d/blacktip.conf
    ls -ld /run/blacktip
else
    print_status "Creating runtime directory manually..."
    mkdir -p /run/blacktip
    chown blacktip:blacktip /run/blacktip
    chmod 755 /run/blacktip
    ls -ld /run/blacktip
fi

# 5. Systemd Service Files
print_section "Systemd Service Files"

if [ -f /etc/systemd/system/blacktip.service ]; then
    print_status "Setting blacktip.service permissions..."
    chmod 644 /etc/systemd/system/blacktip.service
fi

if [ -f /etc/systemd/system/blacktip-web.service ]; then
    print_status "Setting blacktip-web.service permissions..."
    chmod 644 /etc/systemd/system/blacktip-web.service
fi

# 6. Nginx Configuration
print_section "Nginx Configuration"

if [ -f /etc/nginx/sites-available/blacktip ]; then
    print_status "Setting nginx configuration permissions..."
    chown root:root /etc/nginx/sites-available/blacktip
    chmod 644 /etc/nginx/sites-available/blacktip
fi

# 7. Verify User Exists
print_section "User & Group Verification"

if id blacktip >/dev/null 2>&1; then
    print_status "User 'blacktip' exists"
    id blacktip
else
    print_error "User 'blacktip' does not exist!"
    echo "Create it with: sudo useradd --system --no-create-home --shell /bin/false --gid blacktip blacktip"
    exit 1
fi

# Summary
print_section "Summary"

echo "Directory Permissions:"
ls -ld /opt/blacktip
ls -ld /opt/blacktip/web-frontend
ls -ld /var/lib/blacktip
ls -ld /var/log/blacktip
ls -ld /run/blacktip

echo ""
echo "Critical Files:"
if [ -f /opt/blacktip/web-frontend/.env ]; then
    ls -lh /opt/blacktip/web-frontend/.env
fi
if [ -f /var/lib/blacktip/blacktip.db ]; then
    ls -lh /var/lib/blacktip/blacktip.db
fi

echo ""
print_status "Permissions reset complete! ✓"
echo ""
echo "Next steps:"
echo "  1. Reload systemd: sudo systemctl daemon-reload"
echo "  2. Restart services: sudo systemctl restart blacktip.service blacktip-web.service"
echo "  3. Check status: sudo systemctl status 'blacktip*'"
