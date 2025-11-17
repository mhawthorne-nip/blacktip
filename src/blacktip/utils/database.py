import sqlite3
import json
import logging
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple
import os

from blacktip import __version__ as VERSION
from .utils import timestamp

# Use logging module directly to avoid initialization issues
_logger = logging.getLogger(__name__)


class BlacktipDatabase:
    """SQLite database handler for Blacktip ARP monitoring data"""
    
    def __init__(self, db_path: str):
        """Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        
        # Check if database directory is writable
        db_dir = os.path.dirname(self.db_path) or '.'
        if os.path.exists(self.db_path):
            # Check if database file is writable
            if not os.access(self.db_path, os.W_OK):
                raise PermissionError(
                    "Database file is not writable: {}\n"
                    "Try: chmod 666 {}".format(self.db_path, self.db_path)
                )
        elif not os.access(db_dir, os.W_OK):
            # Database doesn't exist, check if directory is writable
            raise PermissionError(
                "Cannot create database in directory: {}\n"
                "Try: chmod 777 {}".format(db_dir, db_dir)
            )
        
        self._init_database()
    
    @contextmanager
    def _get_connection(self):
        """Context manager for database connections with proper cleanup"""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            _logger.error("Database error: {}".format(e))
            raise
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database schema"""
        _logger.debug("Initializing database: {}".format(self.db_path))
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Devices table (combines IP and MAC associations)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    vendor TEXT,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    packet_count INTEGER DEFAULT 0,
                    request_count INTEGER DEFAULT 0,
                    reply_count INTEGER DEFAULT 0,
                    UNIQUE(ip_address, mac_address)
                )
            """)
            
            # ARP events table (optional: for detailed event history)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS arp_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    is_gratuitous INTEGER DEFAULT 0,
                    FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
                )
            """)
            
            # Anomalies table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    anomaly_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    ip_address TEXT,
                    mac_address TEXT,
                    timestamp TEXT NOT NULL
                )
            """)

            # Device state transitions table (online/offline events)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_state_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    previous_state TEXT,
                    new_state TEXT NOT NULL,
                    FOREIGN KEY (ip_address) REFERENCES devices(ip_address)
                )
            """)

            # Nmap scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    scan_start TEXT NOT NULL,
                    scan_end TEXT,
                    nmap_version TEXT,
                    nmap_args TEXT,
                    status TEXT,
                    hostname TEXT,
                    mac_address TEXT,
                    mac_vendor TEXT,
                    os_name TEXT,
                    os_accuracy INTEGER,
                    uptime_seconds INTEGER,
                    FOREIGN KEY (ip_address) REFERENCES devices(ip_address)
                )
            """)

            # Nmap ports table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    state TEXT NOT NULL,
                    service_name TEXT,
                    service_product TEXT,
                    service_version TEXT,
                    service_extrainfo TEXT,
                    FOREIGN KEY (scan_id) REFERENCES nmap_scans(id) ON DELETE CASCADE
                )
            """)

            # NetBIOS/SMB information table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_netbios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    netbios_computer_name TEXT,
                    netbios_domain_name TEXT,
                    netbios_workgroup TEXT,
                    netbios_user TEXT,
                    netbios_mac TEXT,
                    smb_os TEXT,
                    smb_computer_name TEXT,
                    smb_domain_name TEXT,
                    smb_domain_dns TEXT,
                    smb_forest_dns TEXT,
                    smb_fqdn TEXT,
                    smb_system_time TEXT,
                    smb_dialects TEXT,
                    smb_signing_enabled INTEGER,
                    smb_signing_required INTEGER,
                    smb_message_signing TEXT,
                    FOREIGN KEY (scan_id) REFERENCES nmap_scans(id) ON DELETE CASCADE,
                    UNIQUE(scan_id)
                )
            """)

            # mDNS/Bonjour services table (one-to-many with scans)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_mdns_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    service_name TEXT,
                    service_type TEXT,
                    port INTEGER,
                    target TEXT,
                    txt_records TEXT,
                    FOREIGN KEY (scan_id) REFERENCES nmap_scans(id) ON DELETE CASCADE
                )
            """)

            # HTTP metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_http (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    http_title TEXT,
                    http_server TEXT,
                    http_status INTEGER,
                    http_redirect_url TEXT,
                    http_robots_txt TEXT,
                    http_methods TEXT,
                    http_favicon_hash TEXT,
                    FOREIGN KEY (scan_id) REFERENCES nmap_scans(id) ON DELETE CASCADE
                )
            """)

            # SSL/TLS certificate table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_ssl (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    ssl_subject TEXT,
                    ssl_issuer TEXT,
                    ssl_serial TEXT,
                    ssl_not_before TEXT,
                    ssl_not_after TEXT,
                    ssl_fingerprint_sha1 TEXT,
                    ssl_fingerprint_sha256 TEXT,
                    ssl_ciphers TEXT,
                    ssl_tls_versions TEXT,
                    ssl_vulnerabilities TEXT,
                    FOREIGN KEY (scan_id) REFERENCES nmap_scans(id) ON DELETE CASCADE
                )
            """)

            # SSH information table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_ssh (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    ssh_protocol_version TEXT,
                    ssh_hostkey_type TEXT,
                    ssh_hostkey_fingerprint TEXT,
                    ssh_hostkey_bits INTEGER,
                    ssh_algorithms TEXT,
                    FOREIGN KEY (scan_id) REFERENCES nmap_scans(id) ON DELETE CASCADE
                )
            """)

            # Vulnerability assessment table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_vulns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port INTEGER,
                    vuln_id TEXT,
                    vuln_title TEXT,
                    vuln_description TEXT,
                    vuln_state TEXT,
                    vuln_risk TEXT,
                    cvss_score REAL,
                    cve_id TEXT,
                    exploit_available INTEGER DEFAULT 0,
                    FOREIGN KEY (scan_id) REFERENCES nmap_scans(id) ON DELETE CASCADE
                )
            """)

            # DNS resolution table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_dns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    ptr_hostname TEXT,
                    forward_validates INTEGER DEFAULT 0,
                    dns_response_time_ms REAL,
                    first_resolved TEXT NOT NULL,
                    last_resolved TEXT NOT NULL,
                    FOREIGN KEY (ip_address) REFERENCES devices(ip_address)
                )
            """)

            # Device classification table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_classification (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    device_type TEXT,
                    device_category TEXT,
                    manufacturer TEXT,
                    model TEXT,
                    confidence_score REAL,
                    classification_method TEXT,
                    last_classified TEXT NOT NULL,
                    FOREIGN KEY (ip_address) REFERENCES devices(ip_address)
                )
            """)

            # Network information table (ISP, public IP, location, etc.)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS network_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    public_ip TEXT NOT NULL,
                    isp_name TEXT,
                    hostname TEXT,
                    city TEXT,
                    region TEXT,
                    country TEXT,
                    timezone TEXT,
                    latitude REAL,
                    longitude REAL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    UNIQUE(public_ip)
                )
            """)

            # Speed tests table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS speed_tests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_start TEXT NOT NULL,
                    test_end TEXT,
                    download_mbps REAL,
                    upload_mbps REAL,
                    ping_ms REAL,
                    jitter_ms REAL,
                    packet_loss_percent REAL,
                    isp_name TEXT,
                    public_ip TEXT,
                    server_name TEXT,
                    server_host TEXT,
                    server_location TEXT,
                    server_country TEXT,
                    server_distance_km REAL,
                    test_status TEXT NOT NULL,
                    error_message TEXT,
                    test_duration_seconds REAL,
                    triggered_by TEXT NOT NULL
                )
            """)

            # Speed test thresholds for alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS speed_test_thresholds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT NOT NULL,
                    warning_threshold REAL,
                    critical_threshold REAL,
                    enabled INTEGER DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(metric_name)
                )
            """)

            # Generic NSE scripts output table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nmap_scripts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    port INTEGER,
                    script_id TEXT NOT NULL,
                    script_output TEXT,
                    FOREIGN KEY (scan_id) REFERENCES nmap_scans(id) ON DELETE CASCADE
                )
            """)

            # Create indexes for performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_ip 
                ON devices(ip_address)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_mac 
                ON devices(mac_address)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_last_seen 
                ON devices(last_seen)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_device_id 
                ON arp_events(device_id)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_events_timestamp 
                ON arp_events(timestamp)
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_timestamp
                ON anomalies(timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_state_events_timestamp
                ON device_state_events(timestamp)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_state_events_ip
                ON device_state_events(ip_address)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_scans_ip
                ON nmap_scans(ip_address)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_scans_start
                ON nmap_scans(scan_start)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_ports_scan_id
                ON nmap_ports(scan_id)
            """)

            # Additional indexes for better performance
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_devices_vendor
                ON devices(vendor)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_anomalies_type
                ON anomalies(anomaly_type)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_ports_port
                ON nmap_ports(port)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_ports_service
                ON nmap_ports(service_name)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_netbios_scan_id
                ON nmap_netbios(scan_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_netbios_computer_name
                ON nmap_netbios(netbios_computer_name)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_mdns_scan_id
                ON nmap_mdns_services(scan_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_mdns_service_type
                ON nmap_mdns_services(service_type)
            """)

            # Indexes for HTTP data
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_http_scan_id
                ON nmap_http(scan_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_http_port
                ON nmap_http(port)
            """)

            # Indexes for SSL data
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_ssl_scan_id
                ON nmap_ssl(scan_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_ssl_port
                ON nmap_ssl(port)
            """)

            # Indexes for SSH data
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_ssh_scan_id
                ON nmap_ssh(scan_id)
            """)

            # Indexes for vulnerabilities
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_vulns_scan_id
                ON nmap_vulns(scan_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_vulns_cve
                ON nmap_vulns(cve_id)
            """)

            # Indexes for DNS data
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_dns_ip
                ON device_dns(ip_address)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_dns_hostname
                ON device_dns(ptr_hostname)
            """)

            # Indexes for classification
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_class_ip
                ON device_classification(ip_address)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_device_class_type
                ON device_classification(device_type)
            """)

            # Indexes for network info
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_network_info_ip
                ON network_info(public_ip)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_network_info_last_seen
                ON network_info(last_seen)
            """)

            # Indexes for speed tests
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_speed_tests_start
                ON speed_tests(test_start)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_speed_tests_status
                ON speed_tests(test_status)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_speed_tests_public_ip
                ON speed_tests(public_ip)
            """)

            # Indexes for generic scripts
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_scripts_scan_id
                ON nmap_scripts(scan_id)
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_nmap_scripts_script_id
                ON nmap_scripts(script_id)
            """)

            # Run schema migrations to add new columns
            self._migrate_schema(conn)

            # Initialize metadata if not exists
            cursor.execute("""
                INSERT OR IGNORE INTO metadata (key, value, updated_at) 
                VALUES ('version', ?, ?)
            """, (VERSION, timestamp()))
            
            cursor.execute("""
                INSERT OR IGNORE INTO metadata (key, value, updated_at) 
                VALUES ('starts', '0', ?)
            """, (timestamp(),))
            
            cursor.execute("""
                INSERT OR IGNORE INTO metadata (key, value, updated_at) 
                VALUES ('created_at', ?, ?)
            """, (timestamp(), timestamp()))
            
            conn.commit()
            _logger.debug("Database initialized successfully")

    def _migrate_schema(self, conn):
        """Migrate database schema to add new columns if they don't exist

        Args:
            conn: Active database connection
        """
        cursor = conn.cursor()

        # Get existing columns in devices table
        cursor.execute("PRAGMA table_info(devices)")
        existing_columns = {row[1] for row in cursor.fetchall()}

        # Add new columns to devices table if they don't exist
        new_device_columns = [
            ("hostname", "TEXT"),
            ("device_name", "TEXT"),  # User-defined friendly name for the device
            ("device_type", "TEXT"),  # router, server, workstation, mobile, iot
            ("os_family", "TEXT"),  # Windows, Linux, iOS, Android
            ("is_gateway", "INTEGER DEFAULT 0"),
            ("notes", "TEXT"),
            ("tags", "TEXT"),  # Comma-separated tags
        ]

        for column_name, column_type in new_device_columns:
            if column_name not in existing_columns:
                try:
                    cursor.execute("ALTER TABLE devices ADD COLUMN {} {}".format(column_name, column_type))
                    print("Added column '{}' to devices table".format(column_name))
                    _logger.debug("Added column '{}' to devices table".format(column_name))
                except Exception as e:
                    print("ERROR: Could not add column '{}': {}".format(column_name, e))
                    _logger.debug("Could not add column '{}': {}".format(column_name, e))

        # Get existing columns in nmap_ports table
        cursor.execute("PRAGMA table_info(nmap_ports)")
        existing_nmap_columns = {row[1] for row in cursor.fetchall()}

        # Add new columns to nmap_ports table if they don't exist
        new_nmap_port_columns = [
            ("cpe", "TEXT"),  # Common Platform Enumeration
            ("banner", "TEXT"),  # Service banner
        ]

        for column_name, column_type in new_nmap_port_columns:
            if column_name not in existing_nmap_columns:
                try:
                    cursor.execute("ALTER TABLE nmap_ports ADD COLUMN {} {}".format(column_name, column_type))
                    _logger.debug("Added column '{}' to nmap_ports table".format(column_name))
                except Exception as e:
                    _logger.debug("Could not add column '{}': {}".format(column_name, e))

        conn.commit()

    def increment_starts(self):
        """Increment the starts counter"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE metadata 
                SET value = CAST((CAST(value AS INTEGER) + 1) AS TEXT),
                    updated_at = ?
                WHERE key = 'starts'
            """, (timestamp(),))
    
    def get_metadata(self) -> Dict[str, str]:
        """Get all metadata as dictionary"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM metadata")
            return {row['key']: row['value'] for row in cursor.fetchall()}
    
    def update_metadata(self, key: str, value: str):
        """Update metadata value"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO metadata (key, value, updated_at)
                VALUES (?, ?, ?)
            """, (key, value, timestamp()))
    
    def upsert_device(self, ip_address: str, mac_address: str, vendor: str, 
                     packet_type: str, is_new_ip: bool, is_new_mac: bool) -> Tuple[int, bool, bool]:
        """Insert or update device record
        
        Args:
            ip_address: IP address
            mac_address: MAC address
            vendor: Hardware vendor name
            packet_type: 'request' or 'reply'
            is_new_ip: Whether this is a new IP (used for legacy data)
            is_new_mac: Whether this is a new MAC (used for legacy data)
            
        Returns:
            Tuple of (device_id, was_new_ip, was_new_mac)
        
        Raises:
            ValueError: If IP address or MAC address is invalid or reserved
        """
        # Validate against reserved/invalid IP addresses
        reserved_ips = ["0.0.0.0", "255.255.255.255"]
        if ip_address in reserved_ips:
            raise ValueError("Cannot record reserved IP address: {}".format(ip_address))
        
        # Validate IP address is not empty
        if not ip_address or not mac_address:
            raise ValueError("IP address and MAC address cannot be empty")
        
        ts = timestamp()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if this exact combination exists
            cursor.execute("""
                SELECT id, first_seen FROM devices 
                WHERE ip_address = ? AND mac_address = ?
            """, (ip_address, mac_address))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing record
                device_id = existing['id']
                was_new = False
                
                if packet_type == 'request':
                    cursor.execute("""
                        UPDATE devices 
                        SET last_seen = ?,
                            vendor = COALESCE(?, vendor),
                            packet_count = packet_count + 1,
                            request_count = request_count + 1
                        WHERE id = ?
                    """, (ts, vendor, device_id))
                else:  # reply
                    cursor.execute("""
                        UPDATE devices 
                        SET last_seen = ?,
                            vendor = COALESCE(?, vendor),
                            packet_count = packet_count + 1,
                            reply_count = reply_count + 1
                        WHERE id = ?
                    """, (ts, vendor, device_id))
            else:
                # Insert new record
                was_new = True
                
                req_count = 1 if packet_type == 'request' else 0
                rep_count = 1 if packet_type == 'reply' else 0
                
                cursor.execute("""
                    INSERT INTO devices 
                    (ip_address, mac_address, vendor, first_seen, last_seen, 
                     packet_count, request_count, reply_count)
                    VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                """, (ip_address, mac_address, vendor, ts, ts, req_count, rep_count))
                
                device_id = cursor.lastrowid
            
            # Check if this IP was seen with any device before
            cursor.execute("""
                SELECT COUNT(*) as cnt FROM devices WHERE ip_address = ?
            """, (ip_address,))
            ip_exists = cursor.fetchone()['cnt'] > 1 if was_new else True
            
            # Check if this MAC was seen with any device before  
            cursor.execute("""
                SELECT COUNT(*) as cnt FROM devices WHERE mac_address = ?
            """, (mac_address,))
            mac_exists = cursor.fetchone()['cnt'] > 1 if was_new else True
            
            return device_id, not ip_exists, not mac_exists
    
    def log_event(self, device_id: int, event_type: str, is_gratuitous: bool = False):
        """Log an ARP event"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO arp_events (device_id, event_type, timestamp, is_gratuitous)
                VALUES (?, ?, ?, ?)
            """, (device_id, event_type, timestamp(), 1 if is_gratuitous else 0))
    
    def log_anomaly(self, anomaly_type: str, message: str, 
                   ip_address: Optional[str] = None, mac_address: Optional[str] = None):
        """Log a security anomaly"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO anomalies (anomaly_type, message, ip_address, mac_address, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (anomaly_type, message, ip_address, mac_address, timestamp()))
    
    def log_state_transition(self, ip_address: str, mac_address: str, 
                            event_type: str, previous_state: Optional[str], new_state: str):
        """Log a device state transition (online/offline)
        
        Args:
            ip_address: IP address of the device
            mac_address: MAC address of the device
            event_type: Type of event ('online' or 'offline')
            previous_state: Previous state (None for first event)
            new_state: New state ('online' or 'offline')
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO device_state_events 
                (ip_address, mac_address, event_type, timestamp, previous_state, new_state)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (ip_address, mac_address, event_type, timestamp(), previous_state, new_state))
            _logger.debug("Logged state transition for {} ({}): {} -> {}".format(
                ip_address, mac_address, previous_state or 'new', new_state))
    
    def get_device_state_events(self, ip_address: Optional[str] = None, 
                               limit: Optional[int] = None) -> List[Dict]:
        """Get device state transition events
        
        Args:
            ip_address: Filter by IP address (optional)
            limit: Maximum number of events to return (optional)
            
        Returns:
            List of state event dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            if ip_address:
                query = """
                    SELECT * FROM device_state_events
                    WHERE ip_address = ?
                    ORDER BY timestamp DESC
                """
                if limit:
                    query += " LIMIT ?"
                    cursor.execute(query, (ip_address, limit))
                else:
                    cursor.execute(query, (ip_address,))
            else:
                query = """
                    SELECT * FROM device_state_events
                    ORDER BY timestamp DESC
                """
                if limit:
                    query += " LIMIT ?"
                    cursor.execute(query, (limit,))
                else:
                    cursor.execute(query)
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_last_device_state(self, ip_address: str, mac_address: str) -> Optional[str]:
        """Get the last known state for a device
        
        Args:
            ip_address: IP address
            mac_address: MAC address
            
        Returns:
            Last state ('online' or 'offline') or None if no history
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT new_state FROM device_state_events
                WHERE ip_address = ? AND mac_address = ?
                ORDER BY timestamp DESC
                LIMIT 1
            """, (ip_address, mac_address))
            
            result = cursor.fetchone()
            return result['new_state'] if result else None
    
    def query_by_address(self, address: str) -> Dict:
        """Query devices by IP or MAC address
        
        Args:
            address: IP address or MAC address (with colons)
            
        Returns:
            Dictionary with matching devices
        """
        address = address.replace("-", ":").lower()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Determine if it's IP or MAC
            if len(address.split(":")) == 6:
                # MAC address
                cursor.execute("""
                    SELECT * FROM devices WHERE mac_address = ?
                    ORDER BY last_seen DESC
                """, (address,))
                results = cursor.fetchall()
                
                if results:
                    return {
                        "hw": {
                            address: {
                                row['ip_address']: {
                                    "count": row['packet_count'],
                                    "ts_first": row['first_seen'],
                                    "ts_last": row['last_seen'],
                                    "hw_vendor": row['vendor'],
                                    "packets": {
                                        "request": row['request_count'],
                                        "reply": row['reply_count']
                                    }
                                } for row in results
                            }
                        }
                    }
            else:
                # IP address
                cursor.execute("""
                    SELECT * FROM devices WHERE ip_address = ?
                    ORDER BY last_seen DESC
                """, (address,))
                results = cursor.fetchall()
                
                if results:
                    return {
                        "ip": {
                            address: {
                                row['mac_address']: {
                                    "count": row['packet_count'],
                                    "ts_first": row['first_seen'],
                                    "ts_last": row['last_seen'],
                                    "hw_vendor": row['vendor'],
                                    "packets": {
                                        "request": row['request_count'],
                                        "reply": row['reply_count']
                                    }
                                } for row in results
                            }
                        }
                    }
        
        return {}
    
    def get_all_devices(self, limit: Optional[int] = None) -> List[Dict]:
        """Get all devices, optionally limited
        
        Args:
            limit: Maximum number of devices to return
            
        Returns:
            List of device dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT * FROM devices 
                ORDER BY last_seen DESC
            """
            if limit:
                query += " LIMIT ?"
                cursor.execute(query, (limit,))
            else:
                cursor.execute(query)
            
            results = cursor.fetchall()
            return [dict(row) for row in results]
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(DISTINCT ip_address) FROM devices")
            unique_ips = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT mac_address) FROM devices")
            unique_macs = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM devices")
            total_associations = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM arp_events")
            total_events = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM anomalies")
            total_anomalies = cursor.fetchone()[0]
            
            metadata = self.get_metadata()
            
            return {
                "unique_ip_addresses": unique_ips,
                "unique_mac_addresses": unique_macs,
                "total_associations": total_associations,
                "total_events": total_events,
                "total_anomalies": total_anomalies,
                "metadata": metadata
            }
    
    def check_ip_conflict(self, ip_address: str, current_mac: str) -> Optional[str]:
        """Check if IP was previously seen with different MAC
        
        Args:
            ip_address: IP to check
            current_mac: Current MAC address
            
        Returns:
            Previous MAC address if conflict exists, None otherwise
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT mac_address FROM devices 
                WHERE ip_address = ? AND mac_address != ?
                ORDER BY last_seen DESC
                LIMIT 1
            """, (ip_address, current_mac))
            
            result = cursor.fetchone()
            return result['mac_address'] if result else None

    def insert_nmap_scan(self, scan_data: Dict) -> int:
        """Insert nmap scan results into database

        Args:
            scan_data: Dictionary containing nmap scan results with keys:
                - ip_address: Target IP address
                - scan_start: Scan start timestamp
                - scan_end: Scan end timestamp
                - nmap_version: Nmap version string
                - nmap_args: Nmap command arguments
                - status: Host status (up/down)
                - hostname: Detected hostname (optional)
                - mac_address: MAC address (optional)
                - mac_vendor: MAC vendor (optional)
                - os_name: OS name (optional)
                - os_accuracy: OS detection accuracy (optional)
                - uptime_seconds: Host uptime in seconds (optional)
                - ports: List of port dictionaries (optional)
                - netbios: Dictionary of NetBIOS/SMB information (optional)
                - mdns_services: List of mDNS/Bonjour service dictionaries (optional)

        Returns:
            scan_id: The ID of the inserted scan record
        """
        _logger.debug("Inserting nmap scan for {}".format(scan_data.get('ip_address')))

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Insert scan record
            cursor.execute("""
                INSERT INTO nmap_scans
                (ip_address, scan_start, scan_end, nmap_version, nmap_args,
                 status, hostname, mac_address, mac_vendor, os_name,
                 os_accuracy, uptime_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_data.get('ip_address'),
                scan_data.get('scan_start'),
                scan_data.get('scan_end'),
                scan_data.get('nmap_version'),
                scan_data.get('nmap_args'),
                scan_data.get('status'),
                scan_data.get('hostname'),
                scan_data.get('mac_address'),
                scan_data.get('mac_vendor'),
                scan_data.get('os_name'),
                scan_data.get('os_accuracy'),
                scan_data.get('uptime_seconds')
            ))

            scan_id = cursor.lastrowid

            # Insert port records if any
            ports = scan_data.get('ports', [])
            for port in ports:
                cursor.execute("""
                    INSERT INTO nmap_ports
                    (scan_id, port, protocol, state, service_name,
                     service_product, service_version, service_extrainfo)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    port.get('port'),
                    port.get('protocol'),
                    port.get('state'),
                    port.get('service_name'),
                    port.get('service_product'),
                    port.get('service_version'),
                    port.get('service_extrainfo')
                ))

            # Insert NetBIOS/SMB data if any
            netbios = scan_data.get('netbios')
            if netbios:
                cursor.execute("""
                    INSERT INTO nmap_netbios
                    (scan_id, netbios_computer_name, netbios_domain_name,
                     netbios_workgroup, netbios_user, netbios_mac,
                     smb_os, smb_computer_name, smb_domain_name,
                     smb_domain_dns, smb_forest_dns, smb_fqdn,
                     smb_system_time, smb_dialects, smb_signing_enabled,
                     smb_signing_required, smb_message_signing)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    netbios.get('netbios_computer_name'),
                    netbios.get('netbios_domain_name'),
                    netbios.get('netbios_workgroup'),
                    netbios.get('netbios_user'),
                    netbios.get('netbios_mac'),
                    netbios.get('smb_os'),
                    netbios.get('smb_computer_name'),
                    netbios.get('smb_domain_name'),
                    netbios.get('smb_domain_dns'),
                    netbios.get('smb_forest_dns'),
                    netbios.get('smb_fqdn'),
                    netbios.get('smb_system_time'),
                    netbios.get('smb_dialects'),
                    netbios.get('smb_signing_enabled'),
                    netbios.get('smb_signing_required'),
                    netbios.get('smb_message_signing')
                ))
                _logger.debug("NetBIOS/SMB data inserted for scan ID {}".format(scan_id))

            # Insert mDNS/Bonjour services if any
            mdns_services = scan_data.get('mdns_services', [])
            if mdns_services:
                for service in mdns_services:
                    cursor.execute("""
                        INSERT INTO nmap_mdns_services
                        (scan_id, service_name, service_type, port, target, txt_records)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        service.get('service_name'),
                        service.get('service_type'),
                        service.get('port'),
                        service.get('target'),
                        service.get('txt_records')
                    ))
                _logger.debug("Inserted {} mDNS service(s) for scan ID {}".format(len(mdns_services), scan_id))

            # Insert HTTP data if any
            http_data = scan_data.get('http_data', [])
            if http_data:
                for data in http_data:
                    cursor.execute("""
                        INSERT INTO nmap_http
                        (scan_id, port, http_title, http_server, http_status,
                         http_redirect_url, http_robots_txt, http_methods, http_favicon_hash)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        data.get('port'),
                        data.get('title'),
                        data.get('server'),
                        data.get('status'),
                        data.get('redirect_url'),
                        data.get('robots_txt'),
                        data.get('methods'),
                        data.get('favicon_hash')
                    ))
                _logger.debug("Inserted {} HTTP record(s) for scan ID {}".format(len(http_data), scan_id))

            # Insert SSL data if any
            ssl_data = scan_data.get('ssl_data', [])
            if ssl_data:
                for data in ssl_data:
                    cursor.execute("""
                        INSERT INTO nmap_ssl
                        (scan_id, port, ssl_subject, ssl_issuer, ssl_serial,
                         ssl_not_before, ssl_not_after, ssl_fingerprint_sha1,
                         ssl_fingerprint_sha256, ssl_ciphers, ssl_tls_versions, ssl_vulnerabilities)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        data.get('port'),
                        data.get('subject'),
                        data.get('issuer'),
                        data.get('serial'),
                        data.get('not_before'),
                        data.get('not_after'),
                        data.get('sha1_fingerprint'),
                        data.get('sha256_fingerprint'),
                        data.get('ciphers'),
                        data.get('tls_versions'),
                        data.get('vulnerabilities')
                    ))
                _logger.debug("Inserted {} SSL record(s) for scan ID {}".format(len(ssl_data), scan_id))

            # Insert SSH data if any
            ssh_data = scan_data.get('ssh_data', [])
            if ssh_data:
                for data in ssh_data:
                    cursor.execute("""
                        INSERT INTO nmap_ssh
                        (scan_id, port, ssh_protocol_version, ssh_hostkey_type,
                         ssh_hostkey_fingerprint, ssh_hostkey_bits, ssh_algorithms)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        data.get('port'),
                        data.get('protocol_version'),
                        data.get('hostkey_type'),
                        data.get('hostkey_fingerprint'),
                        data.get('hostkey_bits'),
                        data.get('algorithms')
                    ))
                _logger.debug("Inserted {} SSH record(s) for scan ID {}".format(len(ssh_data), scan_id))

            # Insert vulnerability data if any
            vuln_data = scan_data.get('vuln_data', [])
            if vuln_data:
                for data in vuln_data:
                    cursor.execute("""
                        INSERT INTO nmap_vulns
                        (scan_id, port, vuln_id, vuln_title, vuln_description,
                         vuln_state, vuln_risk, cvss_score, cve_id, exploit_available)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        data.get('port'),
                        data.get('vuln_id'),
                        data.get('title'),
                        data.get('description'),
                        data.get('state'),
                        data.get('risk'),
                        data.get('cvss_score'),
                        data.get('cve_id'),
                        data.get('exploit_available', 0)
                    ))
                _logger.debug("Inserted {} vulnerability record(s) for scan ID {}".format(len(vuln_data), scan_id))

            # Insert generic script outputs if any
            generic_scripts = scan_data.get('generic_scripts', [])
            if generic_scripts:
                for data in generic_scripts:
                    cursor.execute("""
                        INSERT INTO nmap_scripts
                        (scan_id, port, script_id, script_output)
                        VALUES (?, ?, ?, ?)
                    """, (
                        scan_id,
                        data.get('port'),
                        data.get('script_id'),
                        data.get('output')
                    ))
                _logger.debug("Inserted {} script output record(s) for scan ID {}".format(len(generic_scripts), scan_id))

            _logger.debug("Nmap scan inserted with ID {} ({} ports{}{}{}{}{}{}{})".format(
                scan_id, len(ports),
                ", with NetBIOS data" if netbios else "",
                ", {} mDNS service(s)".format(len(mdns_services)) if mdns_services else "",
                ", {} HTTP record(s)".format(len(http_data)) if http_data else "",
                ", {} SSL record(s)".format(len(ssl_data)) if ssl_data else "",
                ", {} SSH record(s)".format(len(ssh_data)) if ssh_data else "",
                ", {} vulnerability(ies)".format(len(vuln_data)) if vuln_data else "",
                ", {} script output(s)".format(len(generic_scripts)) if generic_scripts else ""))

            return scan_id

    def get_nmap_scans(self, ip_address: Optional[str] = None,
                      limit: Optional[int] = None) -> List[Dict]:
        """Get nmap scan results

        Args:
            ip_address: Filter by IP address (optional)
            limit: Maximum number of scans to return (optional)

        Returns:
            List of scan dictionaries with port information
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            if ip_address:
                query = """
                    SELECT * FROM nmap_scans
                    WHERE ip_address = ?
                    ORDER BY scan_start DESC
                """
                if limit:
                    query += " LIMIT ?"
                    cursor.execute(query, (ip_address, limit))
                else:
                    cursor.execute(query, (ip_address,))
            else:
                query = """
                    SELECT * FROM nmap_scans
                    ORDER BY scan_start DESC
                """
                if limit:
                    query += " LIMIT ?"
                    cursor.execute(query, (limit,))
                else:
                    cursor.execute(query)

            scans = []
            for row in cursor.fetchall():
                scan = dict(row)

                # Get ports for this scan
                cursor.execute("""
                    SELECT * FROM nmap_ports
                    WHERE scan_id = ?
                    ORDER BY port
                """, (scan['id'],))

                scan['ports'] = [dict(port_row) for port_row in cursor.fetchall()]

                # Get NetBIOS/SMB data for this scan
                cursor.execute("""
                    SELECT * FROM nmap_netbios
                    WHERE scan_id = ?
                """, (scan['id'],))

                netbios_row = cursor.fetchone()
                if netbios_row:
                    scan['netbios'] = dict(netbios_row)
                else:
                    scan['netbios'] = None

                # Get mDNS/Bonjour services for this scan
                cursor.execute("""
                    SELECT * FROM nmap_mdns_services
                    WHERE scan_id = ?
                """, (scan['id'],))

                mdns_rows = cursor.fetchall()
                if mdns_rows:
                    scan['mdns_services'] = [dict(service_row) for service_row in mdns_rows]
                else:
                    scan['mdns_services'] = None

                scans.append(scan)

            return scans

    def get_nmap_ports(self, scan_id: int) -> List[Dict]:
        """Get ports for a specific nmap scan

        Args:
            scan_id: The scan ID to get ports for

        Returns:
            List of port dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM nmap_ports
                WHERE scan_id = ?
                ORDER BY port
            """, (scan_id,))

            return [dict(row) for row in cursor.fetchall()]

    def get_devices_needing_rescan(self, days_threshold: int = 7) -> List[Dict]:
        """Get devices that need nmap rescanning (data older than threshold or no scan)

        Args:
            days_threshold: Number of days after which a scan is considered stale (default: 7)

        Returns:
            List of device dictionaries (ip_address, mac_address, last_scan_date)
        """
        _logger.debug("Finding devices with nmap data older than {} days".format(days_threshold))

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Find devices that either:
            # 1. Have never been scanned with nmap
            # 2. Have nmap scans older than the threshold
            cursor.execute("""
                SELECT DISTINCT
                    d.ip_address,
                    d.mac_address,
                    d.vendor,
                    d.last_seen,
                    MAX(n.scan_start) as last_scan_date
                FROM devices d
                LEFT JOIN nmap_scans n ON d.ip_address = n.ip_address
                GROUP BY d.ip_address, d.mac_address
                HAVING last_scan_date IS NULL
                    OR datetime(last_scan_date) < datetime('now', '-{} days')
                ORDER BY last_scan_date ASC NULLS FIRST
            """.format(days_threshold))

            devices = [dict(row) for row in cursor.fetchall()]
            _logger.debug("Found {} device(s) needing rescan".format(len(devices)))
            return devices

    def cleanup_old_data(self, days_to_keep: int = 90) -> Dict[str, int]:
        """Remove old data from database based on retention policy

        Args:
            days_to_keep: Number of days of data to keep (default: 90)

        Returns:
            Dictionary with counts of deleted records
        """
        _logger.info("Cleaning up data older than {} days".format(days_to_keep))

        cutoff_date = timestamp()
        # Calculate cutoff date (simplified - in production use datetime properly)
        # For now, we'll use a simple approach

        with self._get_connection() as conn:
            cursor = conn.cursor()
            deleted = {}

            # Delete old ARP events
            cursor.execute("""
                DELETE FROM arp_events
                WHERE datetime(timestamp) < datetime('now', '-{} days')
            """.format(days_to_keep))
            deleted['arp_events'] = cursor.rowcount

            # Delete old anomalies
            cursor.execute("""
                DELETE FROM anomalies
                WHERE datetime(timestamp) < datetime('now', '-{} days')
            """.format(days_to_keep))
            deleted['anomalies'] = cursor.rowcount

            # Delete old nmap scans (and ports via CASCADE)
            cursor.execute("""
                DELETE FROM nmap_scans
                WHERE datetime(scan_start) < datetime('now', '-{} days')
            """.format(days_to_keep))
            deleted['nmap_scans'] = cursor.rowcount

            # Delete devices not seen in retention period
            cursor.execute("""
                DELETE FROM devices
                WHERE datetime(last_seen) < datetime('now', '-{} days')
            """.format(days_to_keep))
            deleted['devices'] = cursor.rowcount

            conn.commit()

        _logger.info("Cleanup complete: {}".format(deleted))
        return deleted

    def vacuum_database(self) -> None:
        """Vacuum the database to reclaim space and optimize performance"""
        _logger.info("Vacuuming database: {}".format(self.db_path))
        try:
            with self._get_connection() as conn:
                conn.execute("VACUUM")
                conn.execute("ANALYZE")
            _logger.info("Database vacuum complete")
        except Exception as e:
            _logger.error("Failed to vacuum database: {}".format(e))

    def get_database_size(self) -> int:
        """Get the size of the database file in bytes

        Returns:
            Size in bytes
        """
        try:
            return os.path.getsize(self.db_path)
        except Exception as e:
            _logger.error("Failed to get database size: {}".format(e))
            return 0

    def insert_http_data(self, scan_id: int, http_data: List[Dict]):
        """Insert HTTP metadata from nmap scans

        Args:
            scan_id: The scan ID this data belongs to
            http_data: List of HTTP data dictionaries
        """
        if not http_data:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for data in http_data:
                cursor.execute("""
                    INSERT INTO nmap_http
                    (scan_id, port, http_title, http_server, http_status,
                     http_redirect_url, http_robots_txt, http_methods, http_favicon_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    data.get('port'),
                    data.get('title'),
                    data.get('server'),
                    data.get('status'),
                    data.get('redirect_url'),
                    data.get('robots_txt'),
                    data.get('methods'),
                    data.get('favicon_hash')
                ))
        _logger.debug("Inserted {} HTTP record(s) for scan {}".format(len(http_data), scan_id))

    def insert_ssl_data(self, scan_id: int, ssl_data: List[Dict]):
        """Insert SSL/TLS certificate data from nmap scans

        Args:
            scan_id: The scan ID this data belongs to
            ssl_data: List of SSL data dictionaries
        """
        if not ssl_data:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for data in ssl_data:
                cursor.execute("""
                    INSERT INTO nmap_ssl
                    (scan_id, port, ssl_subject, ssl_issuer, ssl_serial,
                     ssl_not_before, ssl_not_after, ssl_fingerprint_sha1,
                     ssl_fingerprint_sha256, ssl_ciphers, ssl_tls_versions, ssl_vulnerabilities)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    data.get('port'),
                    data.get('subject'),
                    data.get('issuer'),
                    data.get('serial'),
                    data.get('not_before'),
                    data.get('not_after'),
                    data.get('sha1_fingerprint'),
                    data.get('sha256_fingerprint'),
                    data.get('ciphers'),
                    data.get('tls_versions'),
                    data.get('vulnerabilities')
                ))
        _logger.debug("Inserted {} SSL record(s) for scan {}".format(len(ssl_data), scan_id))

    def insert_ssh_data(self, scan_id: int, ssh_data: List[Dict]):
        """Insert SSH host key data from nmap scans

        Args:
            scan_id: The scan ID this data belongs to
            ssh_data: List of SSH data dictionaries
        """
        if not ssh_data:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for data in ssh_data:
                cursor.execute("""
                    INSERT INTO nmap_ssh
                    (scan_id, port, ssh_protocol_version, ssh_hostkey_type,
                     ssh_hostkey_fingerprint, ssh_hostkey_bits, ssh_algorithms)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    data.get('port'),
                    data.get('protocol_version'),
                    data.get('hostkey_type'),
                    data.get('hostkey_fingerprint'),
                    data.get('hostkey_bits'),
                    data.get('algorithms')
                ))
        _logger.debug("Inserted {} SSH record(s) for scan {}".format(len(ssh_data), scan_id))

    def insert_vulnerability_data(self, scan_id: int, vuln_data: List[Dict]):
        """Insert vulnerability assessment data from nmap scans

        Args:
            scan_id: The scan ID this data belongs to
            vuln_data: List of vulnerability dictionaries
        """
        if not vuln_data:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for data in vuln_data:
                cursor.execute("""
                    INSERT INTO nmap_vulns
                    (scan_id, port, vuln_id, vuln_title, vuln_description,
                     vuln_state, vuln_risk, cvss_score, cve_id, exploit_available)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    scan_id,
                    data.get('port'),
                    data.get('vuln_id'),
                    data.get('title'),
                    data.get('description'),
                    data.get('state'),
                    data.get('risk'),
                    data.get('cvss_score'),
                    data.get('cve_id'),
                    data.get('exploit_available', 0)
                ))
        _logger.debug("Inserted {} vulnerability record(s) for scan {}".format(len(vuln_data), scan_id))

    def insert_script_output(self, scan_id: int, script_data: List[Dict]):
        """Insert generic NSE script output

        Args:
            scan_id: The scan ID this data belongs to
            script_data: List of script output dictionaries
        """
        if not script_data:
            return

        with self._get_connection() as conn:
            cursor = conn.cursor()
            for data in script_data:
                cursor.execute("""
                    INSERT INTO nmap_scripts
                    (scan_id, port, script_id, script_output)
                    VALUES (?, ?, ?, ?)
                """, (
                    scan_id,
                    data.get('port'),
                    data.get('script_id'),
                    data.get('output')
                ))
        _logger.debug("Inserted {} script output record(s) for scan {}".format(len(script_data), scan_id))

    def upsert_dns_data(self, ip_address: str, ptr_hostname: Optional[str],
                       forward_validates: bool = False, response_time_ms: Optional[float] = None):
        """Insert or update DNS resolution data for a device

        Args:
            ip_address: IP address
            ptr_hostname: PTR record hostname
            forward_validates: Whether forward DNS matches reverse
            response_time_ms: DNS response time in milliseconds
        """
        ts = timestamp()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if record exists
            cursor.execute("""
                SELECT id FROM device_dns WHERE ip_address = ?
            """, (ip_address,))

            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE device_dns
                    SET ptr_hostname = ?,
                        forward_validates = ?,
                        dns_response_time_ms = ?,
                        last_resolved = ?
                    WHERE ip_address = ?
                """, (ptr_hostname, 1 if forward_validates else 0, response_time_ms, ts, ip_address))
            else:
                cursor.execute("""
                    INSERT INTO device_dns
                    (ip_address, ptr_hostname, forward_validates, dns_response_time_ms,
                     first_resolved, last_resolved)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (ip_address, ptr_hostname, 1 if forward_validates else 0,
                      response_time_ms, ts, ts))

        _logger.debug("Updated DNS data for {}".format(ip_address))

    def upsert_classification_data(self, ip_address: str, classification: Dict):
        """Insert or update device classification data

        Args:
            ip_address: IP address
            classification: Dictionary with classification fields
        """
        ts = timestamp()

        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Check if record exists
            cursor.execute("""
                SELECT id FROM device_classification WHERE ip_address = ?
            """, (ip_address,))

            existing = cursor.fetchone()

            if existing:
                cursor.execute("""
                    UPDATE device_classification
                    SET device_type = ?, device_category = ?, manufacturer = ?,
                        model = ?, confidence_score = ?, classification_method = ?,
                        last_classified = ?
                    WHERE ip_address = ?
                """, (
                    classification.get('device_type'),
                    classification.get('device_category'),
                    classification.get('manufacturer'),
                    classification.get('model'),
                    classification.get('confidence_score'),
                    classification.get('classification_method'),
                    ts,
                    ip_address
                ))
            else:
                cursor.execute("""
                    INSERT INTO device_classification
                    (ip_address, device_type, device_category, manufacturer,
                     model, confidence_score, classification_method, last_classified)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip_address,
                    classification.get('device_type'),
                    classification.get('device_category'),
                    classification.get('manufacturer'),
                    classification.get('model'),
                    classification.get('confidence_score'),
                    classification.get('classification_method'),
                    ts
                ))

        _logger.debug("Updated classification for {} as {}".format(
            ip_address, classification.get('device_type')))

    def update_device_name(self, ip_address: str, mac_address: str, device_name: str):
        """Update the user-defined name for a device (by MAC address)

        This updates ALL devices with the given MAC address, since we want to name
        the physical device (identified by MAC), not a specific IP/MAC combination.
        The ip_address parameter is used for logging context only.

        Args:
            ip_address: IP address of the device (used for logging only)
            mac_address: MAC address of the device (primary identifier)
            device_name: User-defined friendly name
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # Update the device name for ALL entries with this MAC address
            # This ensures the name follows the physical device even if IP changes
            cursor.execute("""
                UPDATE devices
                SET device_name = ?
                WHERE mac_address = ?
            """, (device_name if device_name else None, mac_address))

            if cursor.rowcount == 0:
                _logger.warning("No device found with MAC {}".format(mac_address))
            else:
                _logger.info("Updated device name for MAC {} ({}) to '{}'".format(
                    mac_address, ip_address, device_name))

    def get_device(self, ip_address: str, mac_address: str) -> Optional[Dict]:
        """Get a specific device by IP and MAC address
        
        Args:
            ip_address: IP address of the device
            mac_address: MAC address of the device
            
        Returns:
            Device dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM devices 
                WHERE ip_address = ? AND mac_address = ?
            """, (ip_address, mac_address))
            
            row = cursor.fetchone()
            return dict(row) if row else None
    
    def update_device_last_seen(self, ip_address: str, mac_address: str, timestamp: str):
        """Update the last_seen timestamp for a device
        
        This is used when a device responds to an active probe, allowing us
        to update its status without an actual ARP packet.
        
        Args:
            ip_address: IP address of the device
            mac_address: MAC address of the device
            timestamp: ISO 8601 timestamp string
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE devices
                SET last_seen = ?
                WHERE ip_address = ? AND mac_address = ?
            """, (timestamp, ip_address, mac_address))
            
            if cursor.rowcount > 0:
                _logger.debug("Updated last_seen for {} ({}) to {}".format(
                    ip_address, mac_address, timestamp))
            else:
                _logger.warning("Device not found: {} ({})".format(ip_address, mac_address))

    def insert_speed_test(self, test_data: Dict) -> int:
        """Insert speed test results
        
        Args:
            test_data: Dictionary containing speed test results
            
        Returns:
            test_id: The ID of the inserted test record
        """
        _logger.debug("Inserting speed test")
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT INTO speed_tests
                (test_start, test_end, download_mbps, upload_mbps,
                 ping_ms, jitter_ms, packet_loss_percent, isp_name, public_ip,
                 server_name, server_host, server_location, server_country,
                 server_distance_km, test_status, error_message,
                 test_duration_seconds, triggered_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                test_data.get('test_start'),
                test_data.get('test_end'),
                test_data.get('download_mbps'),
                test_data.get('upload_mbps'),
                test_data.get('ping_ms'),
                test_data.get('jitter_ms'),
                test_data.get('packet_loss_percent'),
                test_data.get('isp_name'),
                test_data.get('public_ip'),
                test_data.get('server_name'),
                test_data.get('server_host'),
                test_data.get('server_location'),
                test_data.get('server_country'),
                test_data.get('server_distance_km'),
                test_data.get('test_status'),
                test_data.get('error_message'),
                test_data.get('test_duration_seconds'),
                test_data.get('triggered_by')
            ))
            
            test_id = cursor.lastrowid
            _logger.debug("Speed test inserted with ID {}".format(test_id))
            return test_id

    def update_speed_test(self, test_id: int, test_data: Dict):
        """Update speed test results (for when test completes)
        
        Args:
            test_id: The test ID to update
            test_data: Dictionary containing updated test results
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE speed_tests
                SET test_end = ?,
                    download_mbps = ?,
                    upload_mbps = ?,
                    ping_ms = ?,
                    jitter_ms = ?,
                    packet_loss_percent = ?,
                    isp_name = ?,
                    public_ip = ?,
                    server_name = ?,
                    server_host = ?,
                    server_location = ?,
                    server_country = ?,
                    server_distance_km = ?,
                    test_status = ?,
                    error_message = ?,
                    test_duration_seconds = ?
                WHERE id = ?
            """, (
                test_data.get('test_end'),
                test_data.get('download_mbps'),
                test_data.get('upload_mbps'),
                test_data.get('ping_ms'),
                test_data.get('jitter_ms'),
                test_data.get('packet_loss_percent'),
                test_data.get('isp_name'),
                test_data.get('public_ip'),
                test_data.get('server_name'),
                test_data.get('server_host'),
                test_data.get('server_location'),
                test_data.get('server_country'),
                test_data.get('server_distance_km'),
                test_data.get('test_status'),
                test_data.get('error_message'),
                test_data.get('test_duration_seconds'),
                test_id
            ))
            
            _logger.debug("Updated speed test ID {}".format(test_id))

    def get_speed_tests(self, limit: Optional[int] = None, 
                       days: Optional[int] = None) -> List[Dict]:
        """Get speed test history
        
        Args:
            limit: Maximum number of tests to return (optional)
            days: Only return tests from last N days (optional)
            
        Returns:
            List of speed test dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT * FROM speed_tests
                WHERE 1=1
            """
            params = []
            
            if days:
                query += " AND datetime(test_start) > datetime(''now'', ''-{} days'')".format(days)
            
            query += " ORDER BY test_start DESC"
            
            if limit:
                query += " LIMIT ?"
                params.append(limit)
            
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            return [dict(row) for row in cursor.fetchall()]

    def get_speed_test_by_id(self, test_id: int) -> Optional[Dict]:
        """Get a specific speed test by ID
        
        Args:
            test_id: The test ID
            
        Returns:
            Speed test dictionary or None if not found
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM speed_tests WHERE id = ?
            """, (test_id,))
            
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_speed_test_statistics(self, days: Optional[int] = None) -> Dict:
        """Get aggregate speed test statistics
        
        Args:
            days: Calculate stats for last N days (optional, all if not specified)
            
        Returns:
            Dictionary with average speeds and counts
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            query = """
                SELECT 
                    COUNT(*) as total_tests,
                    AVG(download_mbps) as avg_download,
                    AVG(upload_mbps) as avg_upload,
                    AVG(ping_ms) as avg_ping,
                    MIN(download_mbps) as min_download,
                    MAX(download_mbps) as max_download,
                    MIN(upload_mbps) as min_upload,
                    MAX(upload_mbps) as max_upload,
                    MIN(ping_ms) as min_ping,
                    MAX(ping_ms) as max_ping
                FROM speed_tests
                WHERE test_status = ''completed''
            """
            
            if days:
                query += " AND datetime(test_start) > datetime(''now'', ''-{} days'')".format(days)
            
            cursor.execute(query)
            row = cursor.fetchone()
            
            return dict(row) if row else {}

    def upsert_network_info(self, network_data: Dict):
        """Insert or update network information
        
        Args:
            network_data: Dictionary containing network info (public_ip, isp_name, etc.)
        """
        ts = timestamp()
        public_ip = network_data.get(''public_ip'')
        
        if not public_ip:
            _logger.warning("Cannot upsert network info without public_ip")
            return
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Check if record exists
            cursor.execute("""
                SELECT id FROM network_info WHERE public_ip = ?
            """, (public_ip,))
            
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute("""
                    UPDATE network_info
                    SET isp_name = ?,
                        hostname = ?,
                        city = ?,
                        region = ?,
                        country = ?,
                        timezone = ?,
                        latitude = ?,
                        longitude = ?,
                        last_seen = ?
                    WHERE public_ip = ?
                """, (
                    network_data.get(''isp_name''),
                    network_data.get(''hostname''),
                    network_data.get(''city''),
                    network_data.get(''region''),
                    network_data.get(''country''),
                    network_data.get(''timezone''),
                    network_data.get(''latitude''),
                    network_data.get(''longitude''),
                    ts,
                    public_ip
                ))
                _logger.debug("Updated network info for {}".format(public_ip))
            else:
                cursor.execute("""
                    INSERT INTO network_info
                    (public_ip, isp_name, hostname, city, region, country,
                     timezone, latitude, longitude, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    public_ip,
                    network_data.get(''isp_name''),
                    network_data.get(''hostname''),
                    network_data.get(''city''),
                    network_data.get(''region''),
                    network_data.get(''country''),
                    network_data.get(''timezone''),
                    network_data.get(''latitude''),
                    network_data.get(''longitude''),
                    ts,
                    ts
                ))
                _logger.debug("Inserted network info for {}".format(public_ip))

    def get_network_info(self) -> Optional[Dict]:
        """Get the most recent network information
        
        Returns:
            Network info dictionary or None if no data
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM network_info
                ORDER BY last_seen DESC
                LIMIT 1
            """)
            
            row = cursor.fetchone()
            return dict(row) if row else None

    def upsert_speed_test_threshold(self, metric_name: str, warning: Optional[float],
                                    critical: Optional[float], enabled: bool = True):
        """Insert or update speed test threshold
        
        Args:
            metric_name: ''download'', ''upload'', or ''ping''
            warning: Warning threshold value
            critical: Critical threshold value
            enabled: Whether threshold checking is enabled
        """
        ts = timestamp()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO speed_test_thresholds
                (metric_name, warning_threshold, critical_threshold, enabled,
                 created_at, updated_at)
                VALUES (
                    ?,
                    ?,
                    ?,
                    ?,
                    COALESCE((SELECT created_at FROM speed_test_thresholds WHERE metric_name = ?), ?),
                    ?
                )
            """, (
                metric_name,
                warning,
                critical,
                1 if enabled else 0,
                metric_name,
                ts,
                ts
            ))
            
            _logger.debug("Updated threshold for {}".format(metric_name))

    def get_speed_test_thresholds(self) -> List[Dict]:
        """Get all speed test thresholds
        
        Returns:
            List of threshold dictionaries
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM speed_test_thresholds
                ORDER BY metric_name
            """)
            
            return [dict(row) for row in cursor.fetchall()]

    def check_speed_test_thresholds(self, test_results: Dict) -> List[Dict]:
        """Check if speed test results violate thresholds
        
        Args:
            test_results: Speed test results dictionary
            
        Returns:
            List of threshold violations
        """
        thresholds = self.get_speed_test_thresholds()
        violations = []
        
        for threshold in thresholds:
            if not threshold[''enabled'']:
                continue
            
            metric = threshold[''metric_name'']
            value = None
            
            if metric == ''download'':
                value = test_results.get(''download_mbps'')
            elif metric == ''upload'':
                value = test_results.get(''upload_mbps'')
            elif metric == ''ping'':
                value = test_results.get(''ping_ms'')
            
            if value is None:
                continue
            
            # For ping, higher is worse. For download/upload, lower is worse
            if metric == ''ping'':
                if threshold[''critical_threshold''] and value > threshold[''critical_threshold'']:
                    violations.append({
                        ''metric'': metric,
                        ''value'': value,
                        ''threshold'': threshold[''critical_threshold''],
                        ''severity'': ''critical'',
                        ''message'': ''Ping latency {} ms exceeds critical threshold of {} ms''.format(
                            value, threshold[''critical_threshold''])
                    })
                elif threshold[''warning_threshold''] and value > threshold[''warning_threshold'']:
                    violations.append({
                        ''metric'': metric,
                        ''value'': value,
                        ''threshold'': threshold[''warning_threshold''],
                        ''severity'': ''warning'',
                        ''message'': ''Ping latency {} ms exceeds warning threshold of {} ms''.format(
                            value, threshold[''warning_threshold''])
                    })
            else:  # download or upload
                if threshold[''critical_threshold''] and value < threshold[''critical_threshold'']:
                    violations.append({
                        ''metric'': metric,
                        ''value'': value,
                        ''threshold'': threshold[''critical_threshold''],
                        ''severity'': ''critical'',
                        ''message'': ''{} speed {} Mbps below critical threshold of {} Mbps''.format(
                            metric.capitalize(), value, threshold[''critical_threshold''])
                    })
                elif threshold[''warning_threshold''] and value < threshold[''warning_threshold'']:
                    violations.append({
                        ''metric'': metric,
                        ''value'': value,
                        ''threshold'': threshold[''warning_threshold''],
                        ''severity'': ''warning'',
                        ''message'': ''{} speed {} Mbps below warning threshold of {} Mbps''.format(
                            metric.capitalize(), value, threshold[''warning_threshold''])
                    })
        
        return violations
