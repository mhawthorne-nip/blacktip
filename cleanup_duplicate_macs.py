#!/usr/bin/env python3
"""Database cleanup script to remove duplicate MAC entries with invalid IPs

This script removes device entries where the same MAC address has multiple
records, specifically targeting entries with reserved IP addresses like 0.0.0.0
that were incorrectly accepted due to validation bugs.

Usage:
    python cleanup_duplicate_macs.py /path/to/database.db [--dry-run]

The script will:
1. Identify MACs with multiple IP addresses
2. Keep the entry with the most recent valid IP
3. Remove entries with reserved IPs (0.0.0.0, 255.255.255.255)
4. Backup the database before making changes (unless --no-backup is specified)
"""

import sqlite3
import argparse
import shutil
import os
from datetime import datetime


def backup_database(db_path):
    """Create a backup of the database

    Args:
        db_path: Path to database file

    Returns:
        Path to backup file
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = "{}.backup.{}".format(db_path, timestamp)
    shutil.copy2(db_path, backup_path)
    print("Created backup: {}".format(backup_path))
    return backup_path


def find_duplicate_macs(cursor):
    """Find MAC addresses that have multiple IP entries

    Args:
        cursor: Database cursor

    Returns:
        List of (mac_address, count) tuples
    """
    cursor.execute("""
        SELECT mac_address, COUNT(*) as count
        FROM devices
        GROUP BY mac_address
        HAVING count > 1
        ORDER BY count DESC
    """)
    return cursor.fetchall()


def get_entries_for_mac(cursor, mac_address):
    """Get all device entries for a specific MAC

    Args:
        cursor: Database cursor
        mac_address: MAC address to look up

    Returns:
        List of device records (as dicts)
    """
    cursor.execute("""
        SELECT id, ip_address, mac_address, vendor, first_seen, last_seen,
               packet_count, request_count, reply_count, device_name
        FROM devices
        WHERE mac_address = ?
        ORDER BY last_seen DESC
    """, (mac_address,))

    columns = [desc[0] for desc in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def is_reserved_ip(ip_address):
    """Check if an IP address is reserved/special

    Args:
        ip_address: IP address string

    Returns:
        True if reserved, False otherwise
    """
    reserved = ["0.0.0.0", "255.255.255.255"]
    return ip_address in reserved


def cleanup_duplicate_macs(db_path, dry_run=False, no_backup=False):
    """Clean up duplicate MAC entries in the database

    Args:
        db_path: Path to database file
        dry_run: If True, only report what would be done
        no_backup: If True, skip creating backup
    """
    if not os.path.exists(db_path):
        print("ERROR: Database not found: {}".format(db_path))
        return 1

    # Create backup unless disabled
    if not dry_run and not no_backup:
        backup_database(db_path)

    # Connect to database
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Find duplicate MACs
    duplicates = find_duplicate_macs(cursor)

    if not duplicates:
        print("No duplicate MAC entries found. Database is clean.")
        conn.close()
        return 0

    print("\nFound {} MAC addresses with duplicate entries:".format(len(duplicates)))

    total_deleted = 0

    for mac_address, count in duplicates:
        entries = get_entries_for_mac(cursor, mac_address)
        print("\n  MAC: {} ({} entries)".format(mac_address, count))

        # Find the best entry to keep
        # Priority: most recent non-reserved IP
        valid_entries = [e for e in entries if not is_reserved_ip(e["ip_address"])]
        reserved_entries = [e for e in entries if is_reserved_ip(e["ip_address"])]

        if valid_entries:
            # Keep the most recent valid entry
            keep_entry = valid_entries[0]
            delete_entries = valid_entries[1:] + reserved_entries
        else:
            # All entries have reserved IPs, keep the most recent
            keep_entry = entries[0]
            delete_entries = entries[1:]

        print("    KEEP: ID={} IP={} last_seen={}".format(
            keep_entry["id"], keep_entry["ip_address"], keep_entry["last_seen"]
        ))

        for entry in delete_entries:
            print("    DELETE: ID={} IP={} last_seen={}".format(
                entry["id"], entry["ip_address"], entry["last_seen"]
            ))

            if not dry_run:
                cursor.execute("DELETE FROM devices WHERE id = ?", (entry["id"],))
                total_deleted += 1

    if dry_run:
        print("\n[DRY RUN] Would delete {} entries".format(len(duplicates) - len(duplicates)))
        print("Run without --dry-run to perform cleanup")
    else:
        conn.commit()
        print("\nDeleted {} duplicate entries".format(total_deleted))
        print("Cleanup complete!")

    conn.close()
    return 0


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Clean up duplicate MAC address entries in Blacktip database"
    )
    parser.add_argument(
        "database",
        help="Path to Blacktip database file"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip creating database backup (not recommended)"
    )

    args = parser.parse_args()

    return cleanup_duplicate_macs(args.database, args.dry_run, args.no_backup)


if __name__ == "__main__":
    exit(main())
