# Quick Start with SQLite Database

## 1. Basic Usage

Start monitoring your network with a SQLite database:

```bash
sudo blacktip -f /var/lib/blacktip/arp_data.db
```

The database will be created automatically with the proper schema.

## 2. Query the Database

Search for a specific device:

```bash
# Query by IP
blacktip -f arp_data.db -q 192.168.1.100

# Query by MAC
blacktip -f arp_data.db -q aa:bb:cc:dd:ee:ff
```

## 3. Using the Database Tool

The `db_tool.py` utility provides easy database management:

```bash
# Show statistics
python examples/db_tool.py arp_data.db stats

# List recent devices
python examples/db_tool.py arp_data.db list --limit 20

# Show anomalies
python examples/db_tool.py arp_data.db anomalies

# Export to JSON
python examples/db_tool.py arp_data.db export backup.json

# Custom SQL query
python examples/db_tool.py arp_data.db sql "SELECT * FROM devices WHERE vendor LIKE '%Apple%'"
```

## 4. Web Interface

Run the example web interface:

```bash
# Install Flask
pip install flask

# Set database path
export BLACKTIP_DB=/var/lib/blacktip/arp_data.db

# Run web server
python examples/web_example.py
```

Visit: http://localhost:5000

## 5. Direct SQL Queries

You can query the database directly with sqlite3:

```bash
# Interactive mode
sqlite3 arp_data.db

# Show all tables
.tables

# View devices
SELECT * FROM devices ORDER BY last_seen DESC LIMIT 10;

# Count devices per vendor
SELECT vendor, COUNT(*) as count FROM devices 
GROUP BY vendor ORDER BY count DESC;

# Find devices seen in last hour
SELECT ip_address, mac_address, vendor 
FROM devices 
WHERE last_seen > datetime('now', '-1 hour');

# Exit
.quit
```

## 6. Common Queries

### Find all IPs used by a MAC address
```sql
SELECT ip_address, first_seen, last_seen, packet_count 
FROM devices 
WHERE mac_address = 'aa:bb:cc:dd:ee:ff'
ORDER BY last_seen DESC;
```

### Find MAC address changes for an IP
```sql
SELECT mac_address, vendor, first_seen, last_seen 
FROM devices 
WHERE ip_address = '192.168.1.100'
ORDER BY first_seen DESC;
```

### List most active devices
```sql
SELECT ip_address, mac_address, vendor, packet_count
FROM devices
ORDER BY packet_count DESC
LIMIT 20;
```

### Find recently active devices
```sql
SELECT ip_address, mac_address, vendor, 
       datetime(last_seen) as last_seen
FROM devices
WHERE last_seen > datetime('now', '-1 day')
ORDER BY last_seen DESC;
```

### Count unique IPs and MACs
```sql
SELECT 
    COUNT(DISTINCT ip_address) as unique_ips,
    COUNT(DISTINCT mac_address) as unique_macs,
    COUNT(*) as total_associations
FROM devices;
```

## 7. Integration Examples

### Python Script
```python
from blacktip.utils.database import BlacktipDatabase

db = BlacktipDatabase('/var/lib/blacktip/arp_data.db')

# Get statistics
stats = db.get_statistics()
print(f"Unique IPs: {stats['unique_ip_addresses']}")
print(f"Unique MACs: {stats['unique_mac_addresses']}")

# Query device
result = db.query_by_address('192.168.1.100')
print(result)

# Get all devices
devices = db.get_all_devices(limit=10)
for device in devices:
    print(f"{device['ip_address']} -> {device['mac_address']} ({device['vendor']})")
```

### Shell Script
```bash
#!/bin/bash
DB="/var/lib/blacktip/arp_data.db"

# Get count of active devices in last hour
COUNT=$(sqlite3 "$DB" \
  "SELECT COUNT(*) FROM devices WHERE last_seen > datetime('now', '-1 hour')")

echo "Active devices in last hour: $COUNT"

# Send alert if threshold exceeded
if [ "$COUNT" -gt 100 ]; then
    echo "Alert: High device count!" | mail -s "Network Alert" admin@example.com
fi
```

## 8. Performance Tips

### Vacuum Database (reclaim space)
```bash
sqlite3 arp_data.db 'VACUUM;'
```

### Analyze for Query Optimization
```bash
sqlite3 arp_data.db 'ANALYZE;'
```

### Check Database Size
```bash
ls -lh arp_data.db
du -h arp_data.db
```

### View Database Info
```bash
sqlite3 arp_data.db '.dbinfo'
```

## 9. Backup

### Live Backup (while blacktip is running)
```bash
sqlite3 arp_data.db ".backup arp_data_backup.db"
```

### Export to JSON
```bash
blacktip -f arp_data.db --export-json backup.json
```

### Copy (when blacktip is stopped)
```bash
cp arp_data.db arp_data_backup_$(date +%Y%m%d).db
```

## 10. Troubleshooting

### Database locked error
```bash
# Check for processes accessing the database
lsof arp_data.db

# Kill stuck processes if needed
sudo killall blacktip
```

### Check database integrity
```bash
sqlite3 arp_data.db "PRAGMA integrity_check;"
```

### View schema
```bash
sqlite3 arp_data.db ".schema"
```
