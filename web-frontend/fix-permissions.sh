#!/bin/bash

# Quick fix script for blacktip-web.service permission issues
# Run this if you encounter "Permission denied: '/run/blacktip/...'" errors

set -e

echo "Fixing Blacktip Web Service Permissions..."

# Install tmpfiles.d configuration
echo "Installing tmpfiles.d configuration..."
sudo cp /opt/blacktip/web-frontend/blacktip-tmpfiles.conf /etc/tmpfiles.d/blacktip.conf

# Create runtime directory with correct permissions
echo "Creating runtime directory..."
sudo systemd-tmpfiles --create /etc/tmpfiles.d/blacktip.conf

# Verify
echo "Verifying permissions..."
ls -ld /run/blacktip

# Restart service
echo "Restarting blacktip-web service..."
sudo systemctl restart blacktip-web.service

# Check status
echo ""
echo "Service status:"
sudo systemctl status blacktip-web.service

echo ""
echo "Fix completed! Check the status above."
