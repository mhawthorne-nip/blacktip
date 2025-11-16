# -*- coding: utf8 -*-
# Copyright (c) 2025 Michael Hawthorne

__title__ = "blacktip"
__author__ = "Michael Hawthorne <mph005@gmail.com>"
__version__ = "1.0.0"

__logger_default_level__ = "info"

# Packet sniffing configuration
__sniff_batch_size__ = 16
__sniff_batch_timeout__ = 2

# Database configuration
__save_data_interval__default__ = 30
__database_retry_attempts__ = 3
__database_retry_delay__ = 1  # seconds

# Nmap configuration - Enhanced with service, OS, NetBIOS/SMB, and mDNS/Bonjour detection
# -n: No DNS resolution (faster)
# -T4: Aggressive timing
# -Pn: Skip ping (assume host up)
# -sV: Service version detection
# -O: OS detection
# --script: Run NSE scripts for comprehensive enumeration
#   NetBIOS/SMB scripts:
#   - nbstat: NetBIOS name service enumeration (computer name, workgroup, MAC)
#   - smb-os-discovery: SMB OS discovery (OS, domain, workgroup, system time)
#   - smb-protocols: SMB protocol versions supported
#   - smb-security-mode: SMB security configuration
#   mDNS/Bonjour scripts:
#   - dns-service-discovery: DNS-SD/Bonjour service discovery (device names, service types)
# -oX -: XML output to stdout
__nmap__exec__ = "nmap -n -T4 -Pn -sV -O --script nbstat,smb-os-discovery,smb-protocols,smb-security-mode,dns-service-discovery -oX - {IP}"

# Command execution configuration
__exec_max_runtime__ = 60  # Increased for more thorough scans
