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

# Nmap configuration - Comprehensive enumeration with extensive NSE scripts
# -n: No DNS resolution (faster, we do DNS separately)
# -T4: Aggressive timing
# -Pn: Skip ping (assume host up)
# -sV: Service version detection
# -O: OS detection
# --script: Run NSE scripts for comprehensive enumeration
#   HTTP/HTTPS scripts:
#   - http-title: Extract page titles
#   - http-server-header: Get server banner
#   - http-methods: Enumerate HTTP methods
#   - http-robots-txt: Check robots.txt
#   - http-favicon: Get favicon hash for fingerprinting
#   SSL/TLS scripts:
#   - ssl-cert: Extract SSL certificate details
#   - ssl-enum-ciphers: Enumerate supported ciphers and protocols
#   SSH scripts:
#   - ssh-hostkey: Get SSH host keys
#   NetBIOS/SMB scripts:
#   - nbstat: NetBIOS name service enumeration
#   - smb-os-discovery: SMB OS discovery
#   - smb-protocols: SMB protocol versions
#   - smb-security-mode: SMB security configuration
#   mDNS scripts:
#   - dns-service-discovery: DNS-SD/Bonjour service discovery
#   Vulnerability scripts:
#   - vulners: CVE vulnerability detection
#   Other service scripts:
#   - ftp-anon: Check anonymous FTP access
#   - ftp-banner: Get FTP banner
#   - smtp-commands: Enumerate SMTP commands
#   - snmp-info: SNMP system information
#   - mysql-info: MySQL server info
#   - ssh2-enum-algos: SSH algorithm enumeration
# -oX -: XML output to stdout
__nmap__exec__ = "nmap -n -T4 -Pn -sV -O --script http-title,http-server-header,http-methods,http-robots-txt,http-favicon,ssl-cert,ssl-enum-ciphers,ssh-hostkey,ssh2-enum-algos,nbstat,smb-os-discovery,smb-protocols,smb-security-mode,dns-service-discovery,vulners,ftp-anon,ftp-banner,smtp-commands,snmp-info,mysql-info -oX - {IP}"

# Command execution configuration
__exec_max_runtime__ = 120  # Increased for comprehensive enumeration with extensive NSE scripts
