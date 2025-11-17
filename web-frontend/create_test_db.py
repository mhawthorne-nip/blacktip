#!/usr/bin/env python3
"""
Create a test database with sample data for Blacktip Web Frontend testing
"""

import os
import sys
import sqlite3
from datetime import datetime, timezone, timedelta

# Add parent directory to path to import blacktip modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from blacktip.utils.database import BlacktipDatabase
from blacktip.utils.utils import timestamp


def create_test_database(db_path):
    """Create a test database with sample devices"""

    # Remove existing test database
    if os.path.exists(db_path):
        print("Removing existing test database...")
        os.remove(db_path)

    print("Creating test database at: {}".format(db_path))
    db = BlacktipDatabase(db_path)

    # Sample devices with various states
    devices = [
        # Online devices (seen recently)
        {
            'ip': '192.168.1.1',
            'mac': 'aa:bb:cc:dd:ee:01',
            'vendor': 'Ubiquiti Networks',
            'hostname': 'gateway.local',
            'device_type': 'router',
            'minutes_ago': 1,
            'packet_count': 1500,
            'has_nmap': True,
            'ports': [22, 80, 443],
        },
        {
            'ip': '192.168.1.10',
            'mac': 'aa:bb:cc:dd:ee:02',
            'vendor': 'Apple, Inc.',
            'hostname': 'macbook-pro.local',
            'device_type': 'workstation',
            'minutes_ago': 3,
            'packet_count': 850,
            'has_nmap': True,
            'ports': [22, 88, 445],
        },
        {
            'ip': '192.168.1.20',
            'mac': 'aa:bb:cc:dd:ee:03',
            'vendor': 'Amazon Technologies Inc.',
            'hostname': 'echo-dot.local',
            'device_type': 'iot',
            'minutes_ago': 5,
            'packet_count': 320,
            'has_nmap': False,
            'ports': [],
        },
        {
            'ip': '192.168.1.30',
            'mac': 'aa:bb:cc:dd:ee:04',
            'vendor': 'Raspberry Pi Trading Ltd',
            'hostname': 'pi-hole.local',
            'device_type': 'server',
            'minutes_ago': 2,
            'packet_count': 2100,
            'has_nmap': True,
            'ports': [22, 53, 80],
        },
        {
            'ip': '192.168.1.40',
            'mac': 'aa:bb:cc:dd:ee:05',
            'vendor': 'Samsung Electronics Co., Ltd',
            'hostname': None,
            'device_type': 'mobile',
            'minutes_ago': 8,
            'packet_count': 450,
            'has_nmap': False,
            'ports': [],
        },
        # Offline devices (not seen recently)
        {
            'ip': '192.168.1.50',
            'mac': 'aa:bb:cc:dd:ee:06',
            'vendor': 'Dell Inc.',
            'hostname': 'desktop-pc.local',
            'device_type': 'workstation',
            'minutes_ago': 120,  # 2 hours
            'packet_count': 1200,
            'has_nmap': True,
            'ports': [22, 135, 445, 3389],
        },
        {
            'ip': '192.168.1.60',
            'mac': 'aa:bb:cc:dd:ee:07',
            'vendor': 'Hewlett Packard',
            'hostname': 'printer.local',
            'device_type': 'printer',
            'minutes_ago': 1440,  # 24 hours
            'packet_count': 80,
            'has_nmap': True,
            'ports': [9100, 515, 631],
        },
        {
            'ip': '192.168.1.70',
            'mac': 'aa:bb:cc:dd:ee:08',
            'vendor': 'Synology Incorporated',
            'hostname': 'nas.local',
            'device_type': 'server',
            'minutes_ago': 4320,  # 3 days
            'packet_count': 5000,
            'has_nmap': True,
            'ports': [22, 80, 443, 445, 5000, 5001],
        },
    ]

    print("Adding {} test devices...".format(len(devices)))

    for device in devices:
        # Calculate timestamp based on minutes ago
        now = datetime.now(timezone.utc)
        last_seen = now - timedelta(minutes=device['minutes_ago'])
        first_seen = last_seen - timedelta(days=30)  # Seen for 30 days

        # Format timestamps
        last_seen_str = last_seen.isoformat().replace('+00:00', 'Z')
        first_seen_str = first_seen.isoformat().replace('+00:00', 'Z')

        # Insert device
        with db._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO devices
                (ip_address, mac_address, vendor, hostname, device_type,
                 first_seen, last_seen, packet_count, request_count, reply_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device['ip'],
                device['mac'],
                device['vendor'],
                device['hostname'],
                device['device_type'],
                first_seen_str,
                last_seen_str,
                device['packet_count'],
                device['packet_count'] // 2,
                device['packet_count'] // 2
            ))

            # Add DNS data if hostname exists
            if device['hostname']:
                cursor.execute("""
                    INSERT INTO device_dns
                    (ip_address, ptr_hostname, forward_validates,
                     dns_response_time_ms, first_resolved, last_resolved)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    device['ip'],
                    device['hostname'],
                    1,
                    15.5,
                    first_seen_str,
                    last_seen_str
                ))

            # Add nmap scan if applicable
            if device['has_nmap'] and device['ports']:
                scan_time = (now - timedelta(minutes=device['minutes_ago'] + 5)).isoformat().replace('+00:00', 'Z')

                cursor.execute("""
                    INSERT INTO nmap_scans
                    (ip_address, scan_start, scan_end, nmap_version, nmap_args,
                     status, hostname, mac_address, mac_vendor, os_name, os_accuracy)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    device['ip'],
                    scan_time,
                    scan_time,
                    'Nmap 7.94',
                    '-sV -O',
                    'up',
                    device['hostname'],
                    device['mac'],
                    device['vendor'],
                    'Linux 5.x' if device['device_type'] in ['server', 'router'] else None,
                    95 if device['device_type'] in ['server', 'router'] else None
                ))

                scan_id = cursor.lastrowid

                # Add ports
                for port in device['ports']:
                    service_map = {
                        22: ('ssh', 'OpenSSH', '8.2p1'),
                        53: ('domain', 'dnsmasq', '2.85'),
                        80: ('http', 'nginx', '1.18.0'),
                        443: ('https', 'nginx', '1.18.0'),
                        445: ('microsoft-ds', 'Samba', '4.13.0'),
                        3389: ('ms-wbt-server', 'Microsoft Terminal Services', None),
                        9100: ('jetdirect', 'HP JetDirect', None),
                        515: ('printer', 'lpd', None),
                        631: ('ipp', 'CUPS', '2.3'),
                        5000: ('upnp', 'Synology DiskStation', None),
                        5001: ('commplex-link', 'Synology DiskStation', None),
                    }

                    service_name, product, version = service_map.get(port, ('unknown', None, None))

                    cursor.execute("""
                        INSERT INTO nmap_ports
                        (scan_id, port, protocol, state, service_name,
                         service_product, service_version)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (
                        scan_id,
                        port,
                        'tcp',
                        'open',
                        service_name,
                        product,
                        version
                    ))

        print("  Added: {} ({}) - {}".format(
            device['ip'],
            device['mac'],
            'online' if device['minutes_ago'] <= 10 else 'offline'
        ))

    # Add a few anomalies for testing
    print("Adding test anomalies...")
    db.log_anomaly(
        'ip_conflict',
        'IP address conflict detected: 192.168.1.50 changed MAC from aa:bb:cc:dd:ee:99 to aa:bb:cc:dd:ee:06',
        '192.168.1.50',
        'aa:bb:cc:dd:ee:06'
    )

    print("\nTest database created successfully!")
    print("Database path: {}".format(db_path))
    print("\nStatistics:")
    stats = db.get_statistics()
    print("  Total device records: {}".format(stats['total_associations']))
    print("  Unique IPs: {}".format(stats['unique_ip_addresses']))
    print("  Unique MACs: {}".format(stats['unique_mac_addresses']))
    print("  Anomalies: {}".format(stats['total_anomalies']))


if __name__ == '__main__':
    # Default test database path
    default_path = '/tmp/blacktip-test.db'

    # Allow custom path from command line
    db_path = sys.argv[1] if len(sys.argv) > 1 else default_path

    create_test_database(db_path)

    print("\nTo use this database with the web frontend:")
    print("  export BLACKTIP_DB={}".format(db_path))
    print("  python app.py")
    print("\nOr:")
    print("  BLACKTIP_DB={} python app.py".format(db_path))
