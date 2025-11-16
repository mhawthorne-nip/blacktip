# -*- coding: utf8 -*-
# Copyright (c) 2025 Michael Hawthorne

__title__ = "blacktip"
__author__ = "Michael Hawthorne <mph005@gmail.com>"
__version__ = "1.0.0"
__license__ = "BSD2"

__logger_default_level__ = "info"

# Packet sniffing configuration
__sniff_batch_size__ = 16
__sniff_batch_timeout__ = 2

# Database configuration
__save_data_interval__default__ = 30
__database_retry_attempts__ = 3
__database_retry_delay__ = 1  # seconds

# Nmap configuration - Enhanced with service and OS detection
# -n: No DNS resolution (faster)
# -T4: Aggressive timing
# -Pn: Skip ping (assume host up)
# -sV: Service version detection
# -O: OS detection
# -oX -: XML output to stdout
__nmap__exec__ = "nmap -n -T4 -Pn -sV -O -oX - {IP}"

# Command execution configuration
__exec_max_runtime__ = 60  # Increased for more thorough scans
