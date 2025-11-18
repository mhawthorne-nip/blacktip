#!/bin/bash

# Fix Git Permissions for Blacktip Repository
# Run this if you get git permission errors

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root (use sudo)"
    exit 1
fi

echo "Fixing git repository permissions..."

# Configure git settings
cd /opt/blacktip
git config --local core.fileMode false
git config --local safe.directory /opt/blacktip

# Fix ownership of the entire repository
chown -R root:root /opt/blacktip

# Ensure .git directory is readable/writable
chown -R root:root /opt/blacktip/.git
chmod -R 775 /opt/blacktip/.git
chmod -R g+w /opt/blacktip/.git

# Fix specific git files that need write access
chmod 664 /opt/blacktip/.git/index 2>/dev/null || true
chmod 664 /opt/blacktip/.git/FETCH_HEAD 2>/dev/null || true
chmod 664 /opt/blacktip/.git/HEAD 2>/dev/null || true

echo "Git permissions fixed!"
echo ""
echo "You can now run: git pull"
