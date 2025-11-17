#!/bin/bash
# Verify that all required NSE scripts are installed

SCRIPT_DIR="/usr/share/nmap/scripts"
MISSING_SCRIPTS=()

REQUIRED_SCRIPTS=(
    "http-title"
    "http-server-header"
    "http-methods"
    "http-favicon"
    "ssl-cert"
    "ssl-enum-ciphers"
    "ssh-hostkey"
    "ssh2-enum-algos"
    "nbstat"
    "smb-os-discovery"
    "smb-protocols"
    "smb-security-mode"
    "dns-service-discovery"
    "ftp-anon"
)

echo "Checking for required NSE scripts in ${SCRIPT_DIR}..."
echo ""

for script in "${REQUIRED_SCRIPTS[@]}"; do
    if [ -f "${SCRIPT_DIR}/${script}.nse" ]; then
        echo "✓ ${script}.nse found"
    else
        echo "✗ ${script}.nse MISSING"
        MISSING_SCRIPTS+=("${script}")
    fi
done

echo ""

if [ ${#MISSING_SCRIPTS[@]} -eq 0 ]; then
    echo "SUCCESS: All required NSE scripts are installed!"
    exit 0
else
    echo "ERROR: ${#MISSING_SCRIPTS[@]} script(s) missing!"
    echo ""
    echo "Install missing scripts with:"
    echo "  Debian/Ubuntu: sudo apt-get install nmap nmap-common"
    echo "  RHEL/CentOS:   sudo yum install nmap nmap-common"
    echo "  Alpine:        sudo apk add nmap nmap-scripts"
    echo "  Arch:          sudo pacman -S nmap"
    exit 1
fi
