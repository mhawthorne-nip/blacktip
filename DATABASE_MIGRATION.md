# Database Migration Guide

## Overview

Blacktip now uses SQLite for data storage instead of JSON files. This provides better performance, concurrent access support, and is ideal for web frontend integration.

## Benefits of SQLite

- **Concurrent Access**: Multiple processes can read/write safely
- **Better Performance**: Indexed queries are much faster
- **Data Integrity**: ACID compliance prevents corruption
- **Scalability**: Handles millions of records efficiently
- **Web-Ready**: Easy integration with Flask, FastAPI, etc.

## Usage

### Starting Fresh with SQLite

Simply specify a `.db` file extension:

```bash
blacktip -f /var/lib/blacktip/arp_data.db
```

The database will be created automatically with the proper schema.

### Querying the Database

Same as before, but with SQLite backend:

```bash
# Query by IP address
blacktip -f arp_data.db -q 192.168.1.100

# Query by MAC address
blacktip -f arp_data.db -q aa:bb:cc:dd:ee:ff
```

### Exporting to JSON

For backup or legacy compatibility:

```bash
blacktip -f arp_data.db --export-json backup.json
```

## Database Schema

### Tables

**devices**: Main table storing IP-MAC associations
- `id`: Unique device association ID
- `ip_address`: IPv4 address
- `mac_address`: Hardware MAC address
- `vendor`: Hardware vendor (from OUI lookup)
- `first_seen`: First observation timestamp
- `last_seen`: Most recent observation
- `packet_count`: Total packets seen
- `request_count`: ARP request packets
- `reply_count`: ARP reply packets

**arp_events** (optional): Detailed event history
- `id`: Event ID
- `device_id`: Reference to devices table
- `event_type`: 'request' or 'reply'
- `timestamp`: Event timestamp
- `is_gratuitous`: Gratuitous ARP flag

**anomalies**: Security events
- `id`: Anomaly ID
- `anomaly_type`: Type of anomaly detected
- `message`: Description
- `ip_address`: Related IP (if applicable)
- `mac_address`: Related MAC (if applicable)
- `timestamp`: Detection timestamp

**metadata**: System metadata
- `key`: Metadata key
- `value`: Metadata value
- `updated_at`: Last update timestamp

### Indexes

- Fast lookups by IP address
- Fast lookups by MAC address
- Efficient time-based queries
- Device-event relationships

## Performance Considerations

### Event Logging

By default, individual ARP events are NOT logged to the `arp_events` table to maximize performance. The `devices` table maintains packet counts and timestamps.

To enable detailed event logging, uncomment this line in `sniffer.py`:

```python
# db.log_event(device_id, packet["op"], is_gratuitous)
```

### Database Maintenance

SQLite is very low maintenance, but for long-running deployments:

```bash
# Vacuum the database (reclaim space)
sqlite3 arp_data.db 'VACUUM;'

# Analyze for query optimization
sqlite3 arp_data.db 'ANALYZE;'
```

## Querying with SQL

You can directly query the database:

```bash
# List all devices seen in last hour
sqlite3 arp_data.db "SELECT * FROM devices WHERE last_seen > datetime('now', '-1 hour');"

# Count unique IPs
sqlite3 arp_data.db "SELECT COUNT(DISTINCT ip_address) FROM devices;"

# Find all IPs for a specific MAC
sqlite3 arp_data.db "SELECT ip_address, first_seen, last_seen FROM devices WHERE mac_address='aa:bb:cc:dd:ee:ff';"

# Recent anomalies
sqlite3 arp_data.db "SELECT * FROM anomalies ORDER BY timestamp DESC LIMIT 10;"
```

## Web Frontend Integration

Example using Flask:

```python
from flask import Flask, jsonify
from blacktip.utils.database import BlacktipDatabase

app = Flask(__name__)
db = BlacktipDatabase('/var/lib/blacktip/arp_data.db')

@app.route('/api/devices')
def get_devices():
    devices = db.get_all_devices(limit=100)
    return jsonify(devices)

@app.route('/api/stats')
def get_stats():
    stats = db.get_statistics()
    return jsonify(stats)

@app.route('/api/query/<address>')
def query_address(address):
    result = db.query_by_address(address)
    return jsonify(result)
```

## Backup Strategy

1. **Live Backup** (while blacktip is running):
   ```bash
   sqlite3 arp_data.db ".backup arp_data_backup.db"
   ```

2. **Export to JSON**:
   ```bash
   blacktip -f arp_data.db --export-json arp_data_backup.json
   ```

3. **File Copy** (when blacktip is stopped):
   ```bash
   cp arp_data.db arp_data_backup.db
   ```

## Troubleshooting

### Database Locked

If you get "database is locked" errors:
- Ensure only one blacktip instance is writing
- Increase timeout in database.py (default: 10 seconds)
- Check for zombie processes

### Performance Issues

- Run `ANALYZE` to update query planner statistics
- Consider pruning old events if events table grows large
- Use indexes appropriately (already configured)

### Corruption

SQLite is very robust, but if corruption occurs:
```bash
# Check integrity
sqlite3 arp_data.db "PRAGMA integrity_check;"

# Recovery attempt
sqlite3 arp_data.db ".recover" | sqlite3 recovered.db
```
