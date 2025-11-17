#!/usr/bin/env python3
"""
Blacktip Web Frontend - Flask Backend API
Provides RESTful API endpoints for the Blacktip network scanner web interface.
"""

import os
import sqlite3
from datetime import datetime, timezone
from typing import Dict, List, Optional
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Disable caching for static files in development
@app.after_request
def add_header(response):
    """Add headers to prevent caching"""
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Configuration
DEFAULT_DB_PATH = os.environ.get('BLACKTIP_DB', '/var/lib/blacktip/blacktip.db')
ONLINE_THRESHOLD_MINUTES = 10  # Consider device offline if not seen in 10 minutes


class BlacktipWebAPI:
    """API wrapper for Blacktip database queries"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._check_database()

    def _check_database(self):
        """Verify database exists and is accessible, and run migrations"""
        if not os.path.exists(self.db_path):
            raise FileNotFoundError(
                "Blacktip database not found at: {}\n"
                "Set BLACKTIP_DB environment variable to correct path.".format(self.db_path)
            )
        if not os.access(self.db_path, os.R_OK):
            raise PermissionError(
                "Cannot read Blacktip database at: {}".format(self.db_path)
            )

        # Initialize BlacktipDatabase to run migrations
        # This ensures the schema is up-to-date (e.g., device_name column exists)
        try:
            from blacktip.utils.database import BlacktipDatabase
            db = BlacktipDatabase(self.db_path)
            print("Database schema migrated successfully")
        except Exception as e:
            print("Warning: Could not run database migrations: {}".format(e))

    def _get_connection(self):
        """Get database connection with row factory"""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _calculate_online_status(self, last_seen: str) -> Dict:
        """Calculate online status and time since last seen

        Args:
            last_seen: ISO 8601 timestamp string

        Returns:
            Dictionary with online status and time ago string
        """
        try:
            # Parse the timestamp - handle various formats
            # Remove 'Z' suffix and parse
            timestamp_str = last_seen.rstrip('Z')

            # Try parsing with microseconds first
            try:
                if '.' in timestamp_str:
                    last_seen_dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
                else:
                    last_seen_dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
            except ValueError:
                # Fallback to fromisoformat (Python 3.7+)
                last_seen_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))

            # Make timezone-aware (assume UTC if no timezone)
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            time_diff = now - last_seen_dt

            # Calculate if online (seen within threshold)
            minutes_ago = time_diff.total_seconds() / 60
            is_online = minutes_ago <= ONLINE_THRESHOLD_MINUTES

            # Generate human-readable time ago string
            if time_diff.total_seconds() < 60:
                time_ago = "just now"
            elif time_diff.total_seconds() < 3600:
                mins = int(time_diff.total_seconds() / 60)
                time_ago = "{} minute{} ago".format(mins, 's' if mins != 1 else '')
            elif time_diff.total_seconds() < 86400:
                hours = int(time_diff.total_seconds() / 3600)
                time_ago = "{} hour{} ago".format(hours, 's' if hours != 1 else '')
            else:
                days = int(time_diff.total_seconds() / 86400)
                time_ago = "{} day{} ago".format(days, 's' if days != 1 else '')

            return {
                'is_online': is_online,
                'time_ago': time_ago,
                'minutes_since_seen': round(minutes_ago, 1)
            }
        except Exception as e:
            print("Error parsing timestamp {}: {}".format(last_seen, e))
            return {
                'is_online': False,
                'time_ago': 'unknown',
                'minutes_since_seen': None
            }

    def get_all_devices(self) -> List[Dict]:
        """Get all devices with enriched data

        Returns:
            List of device dictionaries
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Get all devices with latest nmap scan info
        cursor.execute("""
            SELECT
                d.*,
                dns.ptr_hostname,
                dc.device_type as classified_type,
                dc.device_category,
                dc.manufacturer,
                (
                    SELECT scan_start
                    FROM nmap_scans ns
                    WHERE ns.ip_address = d.ip_address
                    ORDER BY scan_start DESC
                    LIMIT 1
                ) as last_scan,
                (
                    SELECT COUNT(*)
                    FROM nmap_ports np
                    JOIN nmap_scans ns ON np.scan_id = ns.id
                    WHERE ns.ip_address = d.ip_address
                    AND ns.id = (
                        SELECT id FROM nmap_scans
                        WHERE ip_address = d.ip_address
                        ORDER BY scan_start DESC
                        LIMIT 1
                    )
                    AND np.state = 'open'
                ) as open_port_count
            FROM devices d
            LEFT JOIN device_dns dns ON d.ip_address = dns.ip_address
            LEFT JOIN device_classification dc ON d.ip_address = dc.ip_address
            ORDER BY d.last_seen DESC
        """)

        devices = []
        for row in cursor.fetchall():
            device = dict(row)

            # Add online status
            status = self._calculate_online_status(device['last_seen'])
            device.update(status)

            devices.append(device)

        conn.close()
        return devices

    def get_device_details(self, ip_address: str) -> Optional[Dict]:
        """Get detailed information about a specific device

        Args:
            ip_address: IP address to lookup

        Returns:
            Device details dictionary or None if not found
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        # Get device basic info
        cursor.execute("""
            SELECT
                d.*,
                dns.ptr_hostname,
                dns.forward_validates,
                dns.dns_response_time_ms,
                dc.device_type as classified_type,
                dc.device_category,
                dc.manufacturer,
                dc.model,
                dc.confidence_score,
                dc.classification_method
            FROM devices d
            LEFT JOIN device_dns dns ON d.ip_address = dns.ip_address
            LEFT JOIN device_classification dc ON d.ip_address = dc.ip_address
            WHERE d.ip_address = ?
            LIMIT 1
        """, (ip_address,))

        device_row = cursor.fetchone()
        if not device_row:
            conn.close()
            return None

        device = dict(device_row)

        # Add online status
        status = self._calculate_online_status(device['last_seen'])
        device.update(status)

        # Get latest nmap scan
        cursor.execute("""
            SELECT * FROM nmap_scans
            WHERE ip_address = ?
            ORDER BY scan_start DESC
            LIMIT 1
        """, (ip_address,))

        nmap_row = cursor.fetchone()
        if nmap_row:
            nmap_scan = dict(nmap_row)
            scan_id = nmap_scan['id']

            # Get ports for this scan
            cursor.execute("""
                SELECT * FROM nmap_ports
                WHERE scan_id = ?
                ORDER BY port
            """, (scan_id,))

            nmap_scan['ports'] = [dict(p) for p in cursor.fetchall()]

            # Get NetBIOS/SMB info
            cursor.execute("""
                SELECT * FROM nmap_netbios
                WHERE scan_id = ?
            """, (scan_id,))

            netbios_row = cursor.fetchone()
            nmap_scan['netbios'] = dict(netbios_row) if netbios_row else None

            # Get HTTP info
            cursor.execute("""
                SELECT * FROM nmap_http
                WHERE scan_id = ?
            """, (scan_id,))

            nmap_scan['http_data'] = [dict(h) for h in cursor.fetchall()]

            # Get SSL info
            cursor.execute("""
                SELECT * FROM nmap_ssl
                WHERE scan_id = ?
            """, (scan_id,))

            nmap_scan['ssl_data'] = [dict(s) for s in cursor.fetchall()]

            # Get SSH info
            cursor.execute("""
                SELECT * FROM nmap_ssh
                WHERE scan_id = ?
            """, (scan_id,))

            nmap_scan['ssh_data'] = [dict(s) for s in cursor.fetchall()]

            device['nmap_scan'] = nmap_scan
        else:
            device['nmap_scan'] = None

        # Get recent ARP events
        cursor.execute("""
            SELECT ae.* FROM arp_events ae
            JOIN devices d ON ae.device_id = d.id
            WHERE d.ip_address = ?
            ORDER BY ae.timestamp DESC
            LIMIT 20
        """, (ip_address,))

        device['recent_events'] = [dict(e) for e in cursor.fetchall()]

        # Get anomalies related to this device
        cursor.execute("""
            SELECT * FROM anomalies
            WHERE ip_address = ? OR mac_address = ?
            ORDER BY timestamp DESC
            LIMIT 10
        """, (ip_address, device.get('mac_address')))

        device['anomalies'] = [dict(a) for a in cursor.fetchall()]

        conn.close()
        return device

    def get_statistics(self) -> Dict:
        """Get database statistics

        Returns:
            Statistics dictionary
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        stats = {}

        # Total devices
        cursor.execute("SELECT COUNT(DISTINCT ip_address) as count FROM devices")
        stats['total_devices'] = cursor.fetchone()['count']

        # Online devices (seen in last 10 minutes)
        cursor.execute("""
            SELECT COUNT(DISTINCT ip_address) as count
            FROM devices
            WHERE datetime(last_seen) > datetime('now', '-{} minutes')
        """.format(ONLINE_THRESHOLD_MINUTES))
        stats['online_devices'] = cursor.fetchone()['count']

        # Unique MAC addresses
        cursor.execute("SELECT COUNT(DISTINCT mac_address) as count FROM devices")
        stats['unique_macs'] = cursor.fetchone()['count']

        # Total scans
        cursor.execute("SELECT COUNT(*) as count FROM nmap_scans")
        stats['total_scans'] = cursor.fetchone()['count']

        # Total anomalies
        cursor.execute("SELECT COUNT(*) as count FROM anomalies")
        stats['total_anomalies'] = cursor.fetchone()['count']

        # Metadata
        cursor.execute("SELECT key, value FROM metadata")
        stats['metadata'] = {row['key']: row['value'] for row in cursor.fetchall()}

        conn.close()
        return stats

    def get_timeline(self, limit: Optional[int] = 100) -> List[Dict]:
        """Generate timeline of device events (discovered, online, offline)

        Args:
            limit: Maximum number of events to return

        Returns:
            List of timeline event dictionaries
        """
        conn = self._get_connection()
        cursor = conn.cursor()

        events = []
        now = datetime.now(timezone.utc)

        # Get state transition events from the database
        cursor.execute("""
            SELECT 
                se.timestamp,
                se.event_type,
                se.ip_address,
                se.mac_address,
                se.new_state,
                se.previous_state,
                d.device_name,
                d.vendor,
                dc.device_type as classified_type,
                dns.ptr_hostname
            FROM device_state_events se
            LEFT JOIN devices d ON se.ip_address = d.ip_address AND se.mac_address = d.mac_address
            LEFT JOIN device_dns dns ON se.ip_address = dns.ip_address
            LEFT JOIN device_classification dc ON se.ip_address = dc.ip_address
            ORDER BY se.timestamp DESC
            LIMIT ?
        """, (limit,))

        state_events = [dict(row) for row in cursor.fetchall()]

        for event in state_events:
            device_name = self._get_device_display_name(event)
            device_type = event.get('classified_type') or event.get('vendor') or 'Unknown Device'
            
            if event['new_state'] == 'online':
                events.append({
                    'timestamp': event['timestamp'],
                    'event_type': 'online',
                    'device_name': device_name,
                    'device_type': device_type,
                    'ip_address': event['ip_address'],
                    'mac_address': event['mac_address'],
                    'title': '{} went online'.format(device_name),
                    'description': 'The device {} came online.'.format(device_type)
                })
            else:  # offline
                events.append({
                    'timestamp': event['timestamp'],
                    'event_type': 'offline',
                    'device_name': device_name,
                    'device_type': device_type,
                    'ip_address': event['ip_address'],
                    'mac_address': event['mac_address'],
                    'title': '{} went offline'.format(device_name),
                    'description': 'The device {} went offline.'.format(device_type)
                })

        # Get device discovery events (first seen) - only get recent ones
        cursor.execute("""
            SELECT DISTINCT
                d.ip_address,
                d.mac_address,
                d.vendor,
                d.hostname,
                d.device_name,
                d.device_type,
                dc.device_type as classified_type,
                d.first_seen,
                dns.ptr_hostname
            FROM devices d
            LEFT JOIN device_dns dns ON d.ip_address = dns.ip_address
            LEFT JOIN device_classification dc ON d.ip_address = dc.ip_address
            ORDER BY d.first_seen DESC
            LIMIT ?
        """, (limit,))

        devices = [dict(row) for row in cursor.fetchall()]

        for device in devices:
            device_name = self._get_device_display_name(device)
            device_type = device.get('classified_type') or device.get('vendor') or 'Unknown Device'

            # Add discovery event
            first_seen = device['first_seen']
            events.append({
                'timestamp': first_seen,
                'event_type': 'discovered',
                'device_name': device_name,
                'device_type': device_type,
                'ip_address': device['ip_address'],
                'mac_address': device['mac_address'],
                'title': '{} was discovered'.format(device_name),
                'description': 'The device {} joined the network.'.format(device_type)
            })

        # Get anomaly events
        cursor.execute("""
            SELECT * FROM anomalies
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))

        for row in cursor.fetchall():
            anomaly = dict(row)
            events.append({
                'timestamp': anomaly['timestamp'],
                'event_type': 'anomaly',
                'device_name': anomaly.get('ip_address', 'Unknown'),
                'device_type': anomaly['anomaly_type'],
                'ip_address': anomaly.get('ip_address'),
                'mac_address': anomaly.get('mac_address'),
                'title': 'Security anomaly: {}'.format(anomaly['anomaly_type']),
                'description': anomaly['message']
            })

        # Sort events by timestamp (newest first)
        events.sort(key=lambda x: x['timestamp'], reverse=True)

        # Add time_ago to each event
        for event in events[:limit]:
            if 'time_ago' not in event:
                status_info = self._calculate_online_status(event['timestamp'])
                event['time_ago'] = status_info['time_ago']

        conn.close()
        return events[:limit]

    def _get_device_display_name(self, device: Dict) -> str:
        """Generate a display name for a device

        Args:
            device: Device dictionary

        Returns:
            Display name string
        """
        # Priority: device_name > hostname > device_type > IP address
        if device.get('device_name'):
            return device['device_name']
        elif device.get('ptr_hostname'):
            return device['ptr_hostname'].replace('.local', '').replace('.lan', '').title()
        elif device.get('hostname'):
            return device['hostname'].replace('.local', '').replace('.lan', '').title()
        elif device.get('device_type'):
            return '{} ({})'.format(device['device_type'].title(), device['ip_address'])
        else:
            return device['ip_address']

    def update_device_name(self, ip_address: str, mac_address: str, device_name: str) -> bool:
        """Update the user-defined name for a device

        Args:
            ip_address: IP address of the device
            mac_address: MAC address of the device
            device_name: User-defined friendly name

        Returns:
            True if successful, False otherwise
        """
        # Import the database module here to use the update method
        from blacktip.utils.database import BlacktipDatabase

        try:
            db = BlacktipDatabase(self.db_path)
            db.update_device_name(ip_address, mac_address, device_name)
            return True
        except Exception as e:
            print("Error updating device name: {}".format(e))
            return False

    def _format_duration(self, seconds: float) -> str:
        """Format duration in seconds to human-readable string

        Args:
            seconds: Duration in seconds

        Returns:
            Formatted duration string (e.g., "2h 30m", "45m", "3d")
        """
        if seconds < 60:
            return "{}s".format(int(seconds))
        elif seconds < 3600:
            mins = int(seconds / 60)
            return "{}m".format(mins)
        elif seconds < 86400:
            hours = int(seconds / 3600)
            mins = int((seconds % 3600) / 60)
            if mins > 0:
                return "{}h {}m".format(hours, mins)
            return "{}h".format(hours)
        else:
            days = int(seconds / 86400)
            hours = int((seconds % 86400) / 3600)
            if hours > 0:
                return "{}d {}h".format(days, hours)
            return "{}d".format(days)


# Initialize API
try:
    api = BlacktipWebAPI(DEFAULT_DB_PATH)
except Exception as e:
    print("ERROR: Failed to initialize Blacktip Web API: {}".format(e))
    print("Using default database path: {}".format(DEFAULT_DB_PATH))
    print("Set BLACKTIP_DB environment variable if database is elsewhere.")
    api = None


# Routes
@app.route('/')
def index():
    """Render main page"""
    return render_template('index.html')


@app.route('/api/devices')
def get_devices():
    """Get all devices

    Returns:
        JSON array of devices
    """
    if not api:
        return jsonify({'error': 'Database not available'}), 500

    try:
        devices = api.get_all_devices()
        return jsonify(devices)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices/<ip_address>')
def get_device(ip_address):
    """Get device details

    Args:
        ip_address: IP address to lookup

    Returns:
        JSON device details
    """
    if not api:
        return jsonify({'error': 'Database not available'}), 500

    try:
        device = api.get_device_details(ip_address)
        if device:
            return jsonify(device)
        else:
            return jsonify({'error': 'Device not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/statistics')
def get_statistics():
    """Get database statistics

    Returns:
        JSON statistics
    """
    if not api:
        return jsonify({'error': 'Database not available'}), 500

    try:
        stats = api.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/timeline')
def get_timeline():
    """Get timeline of device events

    Query params:
        limit: Maximum number of events (default: 100)

    Returns:
        JSON array of timeline events
    """
    if not api:
        return jsonify({'error': 'Database not available'}), 500

    try:
        limit = request.args.get('limit', 100, type=int)
        timeline = api.get_timeline(limit=limit)
        return jsonify(timeline)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/health')
def health_check():
    """Health check endpoint

    Returns:
        JSON health status
    """
    if not api:
        return jsonify({
            'status': 'unhealthy',
            'message': 'Database not available'
        }), 500

    return jsonify({
        'status': 'healthy',
        'database': api.db_path
    })


@app.route('/api/devices/<ip_address>/name', methods=['PUT'])
def update_device_name(ip_address):
    """Update device name

    Args:
        ip_address: IP address of the device

    Request body:
        {
            "mac_address": "aa:bb:cc:dd:ee:ff",
            "device_name": "My Device"
        }

    Returns:
        JSON response with success status
    """
    if not api:
        return jsonify({'error': 'Database not available'}), 500

    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Request body must be JSON'}), 400

        mac_address = data.get('mac_address')
        device_name = data.get('device_name')

        if not mac_address:
            return jsonify({'error': 'mac_address is required'}), 400

        # device_name can be empty string to clear the name
        if device_name is None:
            return jsonify({'error': 'device_name is required'}), 400

        success = api.update_device_name(ip_address, mac_address, device_name)

        if success:
            return jsonify({'success': True, 'message': 'Device name updated'})
        else:
            return jsonify({'error': 'Failed to update device name'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Run development server
    # Production: use gunicorn or similar
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'

    print("Starting Blacktip Web Frontend...")
    print("Database: {}".format(DEFAULT_DB_PATH))
    print("Server: http://0.0.0.0:{}".format(port))

    app.run(host='0.0.0.0', port=port, debug=debug)
