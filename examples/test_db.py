#!/usr/bin/env python3
"""
Quick test of the database functionality
"""
import sys
import os

# Add blacktip to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from blacktip.utils.database import BlacktipDatabase

# Test database creation (use temp directory)
import tempfile
db_path = os.path.join(tempfile.gettempdir(), 'test_blacktip.db')
print(f"Creating test database at {db_path}...")
db = BlacktipDatabase(db_path)

print("✓ Database created successfully!")

# Test stats
stats = db.get_statistics()
print("\nDatabase Statistics:")
print(f"  Unique IPs: {stats['unique_ip_addresses']}")
print(f"  Unique MACs: {stats['unique_mac_addresses']}")
print(f"  Total Associations: {stats['total_associations']}")

# Test device insertion
print("\nInserting test device...")
device_id, is_new_ip, is_new_hw = db.upsert_device(
    ip_address='192.168.1.100',
    mac_address='aa:bb:cc:dd:ee:ff',
    vendor='Test Vendor',
    packet_type='request',
    is_new_ip=True,
    is_new_mac=True
)
print(f"✓ Device inserted with ID: {device_id}, new_ip={is_new_ip}, new_hw={is_new_hw}")

# Test query
print("\nQuerying for IP 192.168.1.100...")
result = db.query_by_address('192.168.1.100')
print(f"✓ Query result: {result}")

# Test nmap scan insertion
print("\nInserting test nmap scan...")
scan_data = {
    'ip_address': '192.168.1.100',
    'scan_start': '2025-01-01T12:00:00',
    'scan_end': '2025-01-01T12:01:00',
    'nmap_version': '7.94',
    'nmap_args': '-sV -O',
    'status': 'up',
    'hostname': 'test-host.local',
    'os_name': 'Linux 5.x',
    'os_accuracy': 95,
    'ports': [
        {
            'port': 22,
            'protocol': 'tcp',
            'state': 'open',
            'service_name': 'ssh',
            'service_product': 'OpenSSH',
            'service_version': '8.2p1'
        },
        {
            'port': 80,
            'protocol': 'tcp',
            'state': 'open',
            'service_name': 'http',
            'service_product': 'nginx',
            'service_version': '1.18.0'
        }
    ]
}

scan_id = db.insert_nmap_scan(scan_data)
print(f"✓ Nmap scan inserted with ID: {scan_id}")

# Get scans for this IP
scans = db.get_nmap_scans(ip_address='192.168.1.100')
print(f"\n✓ Found {len(scans)} scan(s) for 192.168.1.100")
if scans:
    print(f"  Latest scan: {scans[0]['scan_start']}")
    print(f"  Hostname: {scans[0]['hostname']}")
    print(f"  OS: {scans[0]['os_name']}")

# Get ports for the scan
ports = db.get_nmap_ports(scan_id=scan_id)
print(f"\n✓ Found {len(ports)} port(s) in scan")
for port in ports:
    print(f"  {port['port']}/{port['protocol']}: {port['state']} - {port['service_name']}")

print("\n✅ All tests passed!")
