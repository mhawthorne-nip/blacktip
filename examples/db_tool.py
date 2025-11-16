#!/usr/bin/env python3
"""
Database management utility for Blacktip

Usage:
    python db_tool.py /path/to/arp_data.db stats
    python db_tool.py /path/to/arp_data.db list [--limit 20]
    python db_tool.py /path/to/arp_data.db query 192.168.1.100
    python db_tool.py /path/to/arp_data.db export output.json
    python db_tool.py /path/to/arp_data.db anomalies
    python db_tool.py /path/to/arp_data.db sql "SELECT * FROM devices LIMIT 10"
"""

import sys
import os
import argparse
import json

# Add blacktip to path if running from source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from blacktip.utils.database import BlacktipDatabase


def cmd_stats(db):
    """Show database statistics"""
    stats = db.get_statistics()
    print("\n=== Database Statistics ===")
    print("Unique IP Addresses:    {}".format(stats['unique_ip_addresses']))
    print("Unique MAC Addresses:   {}".format(stats['unique_mac_addresses']))
    print("Total Associations:     {}".format(stats['total_associations']))
    print("Total Events:           {}".format(stats['total_events']))
    print("Total Anomalies:        {}".format(stats['total_anomalies']))
    print("\n=== Metadata ===")
    for key, value in stats['metadata'].items():
        print("{:20s}: {}".format(key, value))
    print()


def cmd_list(db, limit=50):
    """List recent devices"""
    devices = db.get_all_devices(limit=limit)
    
    if not devices:
        print("No devices found")
        return
    
    print("\n{:<15} {:<17} {:<25} {:<10}".format(
        "IP Address", "MAC Address", "Vendor", "Packets"
    ))
    print("-" * 80)
    
    for device in devices:
        print("{:<15} {:<17} {:<25} {:<10}".format(
            device['ip_address'],
            device['mac_address'],
            (device['vendor'] or 'Unknown')[:25],
            device['packet_count']
        ))
    
    print("\nShowing {} of {} total associations".format(
        len(devices), db.get_statistics()['total_associations']
    ))
    print()


def cmd_query(db, address):
    """Query by IP or MAC address"""
    result = db.query_by_address(address)
    
    if not result:
        print("No results found for: {}".format(address))
        return
    
    print("\n=== Query Results ===")
    print(json.dumps(result, indent=2))
    print()


def cmd_export(db, output_file):
    """Export to JSON"""
    print("Exporting database to {}...".format(output_file))
    db.export_to_json(output_file)
    print("Export complete!")
    
    # Show file size
    size = os.path.getsize(output_file)
    print("File size: {:.2f} KB".format(size / 1024))


def cmd_anomalies(db):
    """Show recent anomalies"""
    import sqlite3
    
    with db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT anomaly_type, message, ip_address, mac_address, timestamp
            FROM anomalies
            ORDER BY timestamp DESC
            LIMIT 50
        """)
        
        anomalies = cursor.fetchall()
    
    if not anomalies:
        print("No anomalies detected")
        return
    
    print("\n=== Recent Anomalies ===")
    for row in anomalies:
        print("\n[{}] {}".format(row['timestamp'], row['anomaly_type']))
        print("  {}".format(row['message']))
        if row['ip_address']:
            print("  IP:  {}".format(row['ip_address']))
        if row['mac_address']:
            print("  MAC: {}".format(row['mac_address']))
    print()


def cmd_sql(db, query):
    """Execute custom SQL query"""
    import sqlite3
    
    try:
        with db._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query)
            
            # Check if it's a SELECT query
            if query.strip().upper().startswith('SELECT'):
                results = cursor.fetchall()
                
                if not results:
                    print("No results")
                    return
                
                # Print column names
                columns = [desc[0] for desc in cursor.description]
                print("\n" + " | ".join(columns))
                print("-" * (len(" | ".join(columns))))
                
                # Print rows
                for row in results:
                    print(" | ".join(str(v) for v in row))
                
                print("\n{} rows returned".format(len(results)))
            else:
                print("Query executed successfully")
                print("Rows affected: {}".format(cursor.rowcount))
        print()
        
    except sqlite3.Error as e:
        print("SQL Error: {}".format(e))
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Blacktip Database Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s arp_data.db stats
  %(prog)s arp_data.db list --limit 20
  %(prog)s arp_data.db query 192.168.1.100
  %(prog)s arp_data.db export backup.json
  %(prog)s arp_data.db anomalies
  %(prog)s arp_data.db sql "SELECT COUNT(*) FROM devices"
        """
    )
    
    parser.add_argument('database', help='Path to SQLite database file')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Stats command
    subparsers.add_parser('stats', help='Show database statistics')
    
    # List command
    list_parser = subparsers.add_parser('list', help='List recent devices')
    list_parser.add_argument('--limit', type=int, default=50, 
                           help='Maximum number of devices to show (default: 50)')
    
    # Query command
    query_parser = subparsers.add_parser('query', help='Query by IP or MAC address')
    query_parser.add_argument('address', help='IP address or MAC address to query')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export database to JSON')
    export_parser.add_argument('output', help='Output JSON file path')
    
    # Anomalies command
    subparsers.add_parser('anomalies', help='Show recent anomalies')
    
    # SQL command
    sql_parser = subparsers.add_parser('sql', help='Execute custom SQL query')
    sql_parser.add_argument('query', help='SQL query to execute')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Check database exists
    if not os.path.exists(args.database):
        print("Error: Database file not found: {}".format(args.database))
        sys.exit(1)
    
    # Initialize database
    db = BlacktipDatabase(args.database)
    
    # Execute command
    if args.command == 'stats':
        cmd_stats(db)
    elif args.command == 'list':
        cmd_list(db, args.limit)
    elif args.command == 'query':
        cmd_query(db, args.address)
    elif args.command == 'export':
        cmd_export(db, args.output)
    elif args.command == 'anomalies':
        cmd_anomalies(db)
    elif args.command == 'sql':
        cmd_sql(db, args.query)


if __name__ == '__main__':
    main()
