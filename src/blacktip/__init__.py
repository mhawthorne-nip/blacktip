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

# Nmap configuration - Comprehensive enumeration with NSE scripts
# -n: No DNS resolution (faster, we do DNS separately)
# -T4: Aggressive timing
# -Pn: Skip ping (assume host up)
# -sV: Service version detection (includes HTTP server headers and FTP banners)
# -O: OS detection
# --script: Run NSE scripts for comprehensive enumeration
#   HTTP scripts:
#   - http-title: Get HTTP page titles
#   - http-server-header: Get HTTP server headers
#   - http-methods: Enumerate HTTP methods
#   - http-favicon: Get favicon hash for identification
#   SSL/TLS scripts:
#   - ssl-cert: Extract SSL certificate details
#   - ssl-enum-ciphers: Enumerate supported ciphers and protocols
#   SSH scripts:
#   - ssh-hostkey: Get SSH host keys
#   - ssh2-enum-algos: SSH algorithm enumeration
#   NetBIOS/SMB scripts:
#   - nbstat: NetBIOS name service enumeration
#   - smb-os-discovery: SMB OS discovery
#   - smb-protocols: SMB protocol versions
#   - smb-security-mode: SMB security configuration
#   Service discovery:
#   - dns-service-discovery: DNS-SD/Bonjour service discovery
#   Other:
#   - ftp-anon: Check anonymous FTP access
# Note: http-robots-txt and ftp-banner removed (not available in nmap 7.94)
# Note: Service version detection (-sV) provides FTP banner and robots.txt info
# -oX -: XML output to stdout
__nmap__exec__ = "nmap -n -T4 -Pn -sV -O --script http-title,http-server-header,http-methods,http-favicon,ssl-cert,ssl-enum-ciphers,ssh-hostkey,ssh2-enum-algos,nbstat,smb-os-discovery,smb-protocols,smb-security-mode,dns-service-discovery,ftp-anon -oX - {IP}"

# Command execution configuration
__exec_max_runtime__ = 600  # Comprehensive enumeration with extensive NSE scripts can take time (10 minutes)

# Nmap refresh configuration
__nmap_refresh_interval__ = 3600  # Check for stale devices every hour (in seconds)
__nmap_refresh_threshold_days__ = 7  # Rescan devices with nmap data older than 7 days
