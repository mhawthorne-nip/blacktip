#!/usr/bin/env python3
"""
Initialize default speed test thresholds in the Blacktip database.

This script sets up reasonable default thresholds for monitoring internet connectivity:
- Download speed warnings and critical alerts
- Upload speed warnings and critical alerts  
- Latency (ping) warnings and critical alerts

Run this script once after setting up your database to establish baseline thresholds.
You can adjust these values later via the web interface or database directly.
"""

import sys
import os
import argparse

# Add parent directory to path so we can import blacktip modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.blacktip.utils.database import BlacktipDatabase
from src.blacktip.utils import logger


def init_default_thresholds(database_file, force=False):
    """Initialize default speed test thresholds
    
    Args:
        database_file: Path to the blacktip database
        force: If True, overwrite existing thresholds
    """
    logger.init(name="init_thresholds", level="info")
    
    db = BlacktipDatabase(database_file)
    
    # Check if thresholds already exist
    existing = db.get_speed_test_thresholds()
    
    if existing and not force:
        logger.info("Thresholds already configured. Use --force to overwrite.")
        logger.info("Current thresholds:")
        for threshold in existing:
            logger.info("  - {metric}: {operator} {value} {unit} ({severity})".format(**threshold))
        return
    
    # Default thresholds - adjust these based on your expected internet speeds
    default_thresholds = [
        {
            'metric': 'download_mbps',
            'operator': '<',
            'threshold_value': 50.0,
            'severity': 'critical',
            'enabled': True,
            'description': 'Download speed critically low (< 50 Mbps)'
        },
        {
            'metric': 'download_mbps',
            'operator': '<',
            'threshold_value': 100.0,
            'severity': 'warning',
            'enabled': True,
            'description': 'Download speed below expected (< 100 Mbps)'
        },
        {
            'metric': 'upload_mbps',
            'operator': '<',
            'threshold_value': 10.0,
            'severity': 'critical',
            'enabled': True,
            'description': 'Upload speed critically low (< 10 Mbps)'
        },
        {
            'metric': 'upload_mbps',
            'operator': '<',
            'threshold_value': 20.0,
            'severity': 'warning',
            'enabled': True,
            'description': 'Upload speed below expected (< 20 Mbps)'
        },
        {
            'metric': 'ping_ms',
            'operator': '>',
            'threshold_value': 100.0,
            'severity': 'critical',
            'enabled': True,
            'description': 'Latency critically high (> 100 ms)'
        },
        {
            'metric': 'ping_ms',
            'operator': '>',
            'threshold_value': 50.0,
            'severity': 'warning',
            'enabled': True,
            'description': 'Latency higher than expected (> 50 ms)'
        }
    ]
    
    logger.info("Initializing {} default thresholds...".format(len(default_thresholds)))
    
    # Clear existing thresholds if force is True
    if force and existing:
        logger.info("Force mode enabled - clearing existing thresholds")
        # Note: BlacktipDatabase should have a method to clear thresholds
        # For now we'll just overwrite by setting new thresholds
    
    # Set thresholds
    for threshold in default_thresholds:
        try:
            db.set_speed_test_threshold(
                metric=threshold['metric'],
                operator=threshold['operator'],
                threshold_value=threshold['threshold_value'],
                severity=threshold['severity'],
                enabled=threshold['enabled'],
                description=threshold['description']
            )
            logger.info("Set threshold: {description}".format(**threshold))
        except Exception as e:
            logger.error("Failed to set threshold {}: {}".format(threshold['description'], e))
    
    logger.info("Threshold initialization complete!")
    logger.info("\nTo customize thresholds:")
    logger.info("1. Use the web interface (Speed Test settings)")
    logger.info("2. Edit the database directly")
    logger.info("3. Re-run this script with custom values")


def main():
    parser = argparse.ArgumentParser(
        description='Initialize default speed test thresholds for Blacktip',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Initialize thresholds with defaults
  python init_speedtest_thresholds.py

  # Specify custom database location
  python init_speedtest_thresholds.py --database /path/to/blacktip.db

  # Force overwrite existing thresholds
  python init_speedtest_thresholds.py --force

Default Thresholds:
  Download:  < 100 Mbps (warning), < 50 Mbps (critical)
  Upload:    < 20 Mbps (warning), < 10 Mbps (critical)  
  Latency:   > 50 ms (warning), > 100 ms (critical)

Adjust these values based on your expected internet speeds.
        """
    )
    
    parser.add_argument(
        '--database',
        '-d',
        default='blacktip.db',
        help='Path to blacktip database file (default: blacktip.db)'
    )
    
    parser.add_argument(
        '--force',
        '-f',
        action='store_true',
        help='Overwrite existing thresholds'
    )
    
    args = parser.parse_args()
    
    # Check if database exists
    if not os.path.exists(args.database):
        print("Error: Database file '{}' not found!".format(args.database))
        print("\nPlease run Blacktip at least once to create the database,")
        print("or specify the correct database path with --database")
        sys.exit(1)
    
    init_default_thresholds(args.database, force=args.force)


if __name__ == '__main__':
    main()
