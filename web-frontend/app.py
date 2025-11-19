#!/usr/bin/env python3
"""
Blacktip Web Frontend - Flask Backend API
Provides RESTful API endpoints for the Blacktip network scanner web interface.
"""

import os
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__,
            static_folder='client/dist/assets',
            static_url_path='/assets')

# Configure CORS for production - restrict to your domain
# In development, allow localhost. In production, set ALLOWED_ORIGINS env var
allowed_origins = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:5173,https://app.niceshark.com')
CORS(app, origins=allowed_origins.split(','))

# Secret key for session management
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())

# Speed test service (initialized after database)
speedtest_service = None

# Cache control - only disable caching for API endpoints
@app.after_request
def add_header(response):
    """Add cache control headers - no cache for API, allow cache for static files"""
    if request.path.startswith('/api/'):
        # Disable caching for API responses
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    elif request.path.startswith('/static/'):
        # Allow caching for static files (1 hour)
        response.headers['Cache-Control'] = 'public, max-age=3600'
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
                d.last_seen,
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

        # Process state events and calculate durations
        for i, event in enumerate(state_events):
            device_name = self._get_device_display_name(event)
            device_type = event.get('classified_type') or event.get('vendor') or 'Unknown Device'
            
            # Get current state
            current_status = self._calculate_online_status(event.get('last_seen'))
            current_state = 'online' if current_status['is_online'] else 'offline'
            
            # Check if device is still in the state it transitioned to
            is_still_in_state = (event['new_state'] == current_state)
            
            # Calculate duration in PREVIOUS state (before this transition)
            duration_str = None
            event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
            
            # Find the previous transition event (later in list, earlier in time)
            for j in range(i + 1, len(state_events)):
                if (state_events[j]['ip_address'] == event['ip_address'] and 
                    state_events[j]['mac_address'] == event['mac_address']):
                    prev_event_time = datetime.fromisoformat(state_events[j]['timestamp'].replace('Z', '+00:00'))
                    if prev_event_time.tzinfo is None:
                        prev_event_time = prev_event_time.replace(tzinfo=timezone.utc)
                    
                    # Duration in previous state = time from previous event to this event
                    duration = event_time - prev_event_time
                    duration_str = self._format_duration(duration.total_seconds())
                    break
            
            if event['new_state'] == 'online':
                events.append({
                    'timestamp': event['timestamp'],
                    'event_type': 'online',
                    'device_name': device_name,
                    'device_type': device_type,
                    'ip_address': event['ip_address'],
                    'mac_address': event['mac_address'],
                    'title': '{} went online'.format(device_name),
                    'description': 'The device {} came online.'.format(device_type),
                    'duration_str': duration_str,
                    'is_current_state': is_still_in_state,
                    'current_state': current_state,
                    'previous_state': event.get('previous_state', 'offline')
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
                    'description': 'The device {} went offline.'.format(device_type),
                    'duration_str': duration_str,
                    'is_current_state': is_still_in_state,
                    'current_state': current_state,
                    'previous_state': event.get('previous_state', 'online')
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

        # Get speed test events
        cursor.execute("""
            SELECT 
                id,
                test_start as timestamp,
                download_mbps,
                upload_mbps,
                ping_ms,
                server_location,
                test_status,
                error_message,
                triggered_by
            FROM speed_tests
            WHERE test_status = 'completed'
            ORDER BY test_start DESC
            LIMIT ?
        """, (limit,))

        for row in cursor.fetchall():
            test = dict(row)
            # Determine title based on how the test was triggered
            trigger_type = test.get('triggered_by', 'manual')
            if trigger_type == 'scheduled':
                title = 'Scheduled speed test completed'
            elif trigger_type == 'manual':
                title = 'Manual speed test completed'
            else:
                title = 'Speed test completed'
            
            events.append({
                'timestamp': test['timestamp'],
                'event_type': 'speedtest',
                'device_name': 'Internet Speed Test',
                'device_type': 'speedtest',
                'title': title,
                'description': 'Download speed is {:.1f} Mbps from {}. Upload speed is {:.1f} Mbps from {}. Latency is {:.0f} ms.'.format(
                    test['download_mbps'], 
                    test['server_location'] or 'Unknown',
                    test['upload_mbps'],
                    test['server_location'] or 'Unknown',
                    test['ping_ms']
                ),
                'download_mbps': test['download_mbps'],
                'upload_mbps': test['upload_mbps'],
                'ping_ms': test['ping_ms'],
                'server_location': test['server_location'],
                'triggered_by': trigger_type
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
    
    # Initialize speed test service
    from blacktip.utils.database import BlacktipDatabase
    from blacktip.utils.speedtest_service import SpeedTestService
    db = BlacktipDatabase(DEFAULT_DB_PATH)
    speedtest_service = SpeedTestService(database=db)
    print("Speed test service initialized")
except Exception as e:
    print("ERROR: Failed to initialize Blacktip Web API: {}".format(e))
    print("Using default database path: {}".format(DEFAULT_DB_PATH))
    print("Set BLACKTIP_DB environment variable if database is elsewhere.")
    api = None
    speedtest_service = None


# Routes
@app.route('/')
@app.route('/<path:path>')
def index(path=''):
    """Serve the React application"""
    return app.send_static_file('../client/dist/index.html')


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


@app.route('/api/speed-tests')
def get_speed_tests():
    """Get speed test history
    
    Query params:
        limit: Maximum number of tests to return (default: 50)
        days: Only return tests from last N days (optional)
    
    Returns:
        JSON array of speed tests
    """
    if not speedtest_service:
        return jsonify({'error': 'Speed test service not available'}), 500
    
    try:
        limit = request.args.get('limit', 50, type=int)
        days = request.args.get('days', None, type=int)
        
        from blacktip.utils.database import BlacktipDatabase
        db = BlacktipDatabase(DEFAULT_DB_PATH)
        tests = db.get_speed_tests(limit=limit, days=days)
        # Ensure triggered_by field is included in response
        return jsonify(tests)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/speed-tests/<int:test_id>')
def get_speed_test(test_id):
    """Get specific speed test by ID
    
    Args:
        test_id: Speed test ID
    
    Returns:
        JSON speed test details
    """
    if not speedtest_service:
        return jsonify({'error': 'Speed test service not available'}), 500
    
    try:
        from blacktip.utils.database import BlacktipDatabase
        db = BlacktipDatabase(DEFAULT_DB_PATH)
        test = db.get_speed_test_by_id(test_id)
        
        if test:
            return jsonify(test)
        else:
            return jsonify({'error': 'Speed test not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/speed-tests/run', methods=['POST'])
def run_speed_test():
    """Trigger a new speed test
    
    Returns:
        JSON response with test ID and status
    """
    if not speedtest_service:
        return jsonify({'error': 'Speed test service not available'}), 500
    
    try:
        # Check if test can be run (rate limiting)
        if not speedtest_service.can_run_test():
            return jsonify({
                'error': 'Please wait before running another test',
                'message': 'Speed tests are rate-limited to prevent excessive testing'
            }), 429
        
        # Run speed test in background thread to avoid blocking
        def run_test_async():
            try:
                speedtest_service.run_speed_test(triggered_by='manual')
            except Exception as e:
                print("Error in background speed test: {}".format(e))
        
        thread = threading.Thread(target=run_test_async, daemon=True)
        thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Speed test started',
            'note': 'This may take 20-30 seconds to complete'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/speed-tests/statistics')
def get_speed_test_statistics():
    """Get speed test statistics
    
    Query params:
        days: Calculate stats for last N days (optional, all time if not specified)
    
    Returns:
        JSON statistics
    """
    if not speedtest_service:
        return jsonify({'error': 'Speed test service not available'}), 500
    
    try:
        days = request.args.get('days', None, type=int)
        
        from blacktip.utils.database import BlacktipDatabase
        db = BlacktipDatabase(DEFAULT_DB_PATH)
        stats = db.get_speed_test_statistics(days=days)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/network-info')
def get_network_info():
    """Get current network information
    
    Returns:
        JSON network information
    """
    if not api:
        return jsonify({'error': 'Database not available'}), 500
    
    try:
        from blacktip.utils.database import BlacktipDatabase
        db = BlacktipDatabase(DEFAULT_DB_PATH)
        info = db.get_network_info()
        
        if info:
            return jsonify(info)
        else:
            return jsonify({
                'message': 'No network information available yet',
                'suggestion': 'Run a speed test to collect network information'
            })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/speed-tests/thresholds', methods=['GET', 'PUT'])
def manage_thresholds():
    """Get or update speed test thresholds
    
    GET: Returns all thresholds
    PUT: Updates thresholds (requires JSON body)
    
    Returns:
        JSON threshold data
    """
    if not api:
        return jsonify({'error': 'Database not available'}), 500
    
    from blacktip.utils.database import BlacktipDatabase
    db = BlacktipDatabase(DEFAULT_DB_PATH)
    
    if request.method == 'GET':
        try:
            thresholds = db.get_speed_test_thresholds()
            return jsonify(thresholds)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    elif request.method == 'PUT':
        try:
            data = request.get_json()
            if not data:
                return jsonify({'error': 'Request body must be JSON'}), 400
            
            metric = data.get('metric_name')
            warning = data.get('warning_threshold')
            critical = data.get('critical_threshold')
            enabled = data.get('enabled', True)
            
            if not metric:
                return jsonify({'error': 'metric_name is required'}), 400
            
            if metric not in ['download', 'upload', 'ping']:
                return jsonify({'error': 'Invalid metric_name. Must be download, upload, or ping'}), 400
            
            db.upsert_speed_test_threshold(metric, warning, critical, enabled)
            
            return jsonify({
                'success': True,
                'message': 'Threshold updated for {}'.format(metric)
            })
        except Exception as e:
            return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    # Development server only - use Gunicorn for production
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'

    print("Starting Blacktip Web Frontend (Development Mode)...")
    print("Database: {}".format(DEFAULT_DB_PATH))
    print("Server: http://127.0.0.1:{}".format(port))
    print("")
    print("WARNING: This is the development server.")
    print("For production, use: gunicorn -c gunicorn.conf.py app:app")
    print("")

    # Bind to localhost only in development for security
    app.run(host='127.0.0.1', port=port, debug=debug)
