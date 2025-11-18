#!/bin/bash

# Blacktip Web Service Diagnostic Script
# Run this to diagnose why the web service won't start

echo "============================================"
echo "  Blacktip Web Service Diagnostics"
echo "============================================"
echo

echo "1. Checking service status..."
systemctl status blacktip-web.service --no-pager

echo ""
echo "2. Checking recent logs..."
journalctl -u blacktip-web.service -n 30 --no-pager

echo ""
echo "3. Checking permissions..."
echo "Web frontend directory:"
ls -la /opt/blacktip/web-frontend/

echo ""
echo "Log directory:"
ls -la /var/log/blacktip/

echo ""
echo "Database:"
ls -lh /var/lib/blacktip/blacktip.db 2>/dev/null || echo "Database not found"

echo ""
echo "Runtime directory:"
ls -ld /run/blacktip/ 2>/dev/null || echo "Runtime directory not found"

echo ""
echo "4. Checking .env file..."
if [ -f /opt/blacktip/web-frontend/.env ]; then
    echo "✓ .env exists"
    ls -lh /opt/blacktip/web-frontend/.env
else
    echo "✗ .env file missing!"
fi

echo ""
echo "5. Testing Gunicorn manually..."
echo "Running: sudo -u blacktip bash -c 'cd /opt/blacktip/web-frontend && python3 -m gunicorn --check-config gunicorn.conf.py'"
sudo -u blacktip bash -c 'cd /opt/blacktip/web-frontend && python3 -m gunicorn --check-config gunicorn.conf.py' 2>&1

echo ""
echo "6. Testing app import..."
echo "Running: sudo -u blacktip python3 -c 'import sys; sys.path.insert(0, \"/opt/blacktip/web-frontend\"); import app'"
sudo -u blacktip python3 -c 'import sys; sys.path.insert(0, "/opt/blacktip/web-frontend"); import app' 2>&1

echo ""
echo "============================================"
echo "Diagnostic complete"
echo "============================================"
