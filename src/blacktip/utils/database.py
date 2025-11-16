import sqlite3
import json
from contextlib import contextmanager
from typing import Dict, List, Optional, Tuple
import os

from blacktip import __version__ as VERSION
from .utils import timestamp
from . import logger


class BlacktipDatabase:
    """SQLite database handler for Blacktip ARP monitoring data"""
    
    def __init__(self, db_path: str):
        """Initialize database connection
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
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
            logger.error("Database error: {}".format(e))
            raise
        finally:
            conn.close()
    
    def _init_database(self):
        """Initialize database schema"""
        logger.debug("Initializing database: {}".format(self.db_path))
        
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
            logger.debug("Database initialized successfully")
    
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
    
    def export_to_json(self, filename: str):
        """Export database to JSON format (legacy compatibility)
        
        Args:
            filename: Output JSON file path
        """
        logger.debug("Exporting database to JSON: {}".format(filename))
        
        devices = self.get_all_devices()
        metadata = self.get_metadata()
        
        # Build JSON structure matching original format
        data = {
            "meta": {
                "blacktip": metadata.get('version', VERSION),
                "starts": int(metadata.get('starts', 0)),
                "ts_first": metadata.get('created_at', timestamp()),
                "ts_last": timestamp(),
                "hw_count": 0,
                "ip_count": 0,
            },
            "ip": {},
            "hw": {},
        }
        
        unique_ips = set()
        unique_macs = set()
        
        for device in devices:
            ip = device['ip_address']
            mac = device['mac_address']
            
            unique_ips.add(ip)
            unique_macs.add(mac)
            
            # Add to IP index
            if ip not in data["ip"]:
                data["ip"][ip] = {}
            data["ip"][ip][mac] = {
                "count": device['packet_count'],
                "ts_first": device['first_seen'],
                "ts_last": device['last_seen'],
                "hw_vendor": device['vendor'],
                "packets": {
                    "request": device['request_count'],
                    "reply": device['reply_count']
                }
            }
            
            # Add to MAC index
            if mac not in data["hw"]:
                data["hw"][mac] = {}
            data["hw"][mac][ip] = {
                "count": device['packet_count'],
                "ts_first": device['first_seen'],
                "ts_last": device['last_seen'],
                "hw_vendor": device['vendor'],
                "packets": {
                    "request": device['request_count'],
                    "reply": device['reply_count']
                }
            }
        
        data["meta"]["hw_count"] = len(unique_macs)
        data["meta"]["ip_count"] = len(unique_ips)
        
        import json
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, sort_keys=True)
        
        logger.debug("Export complete: {} IPs, {} MACs".format(
            len(unique_ips), len(unique_macs)))

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

        Returns:
            scan_id: The ID of the inserted scan record
        """
        logger.debug("Inserting nmap scan for {}".format(scan_data.get('ip_address')))

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

            logger.debug("Nmap scan inserted with ID {} ({} ports)".format(
                scan_id, len(ports)))

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
                scans.append(scan)

            return scans
