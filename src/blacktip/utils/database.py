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
                    _logger.debug("Added column '{}' to devices table".format(column_name))
                except Exception as e:
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
        """
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

            _logger.debug("Nmap scan inserted with ID {} ({} ports{}{})".format(
                scan_id, len(ports),
                ", with NetBIOS data" if netbios else "",
                ", {} mDNS service(s)".format(len(mdns_services)) if mdns_services else ""))

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
