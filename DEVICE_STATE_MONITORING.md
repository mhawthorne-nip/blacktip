# Device State Monitoring

This document explains the device state monitoring feature that tracks when devices go online and offline on your network.

## Overview

The device state monitoring system tracks actual state transitions (offline → online, online → offline) and stores them as events in the database. This is different from the previous behavior where the timeline only showed the current status of each device.

## How It Works

### 1. Database Schema

A new table `device_state_events` has been added to track state transitions:

```sql
CREATE TABLE device_state_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    event_type TEXT NOT NULL,           -- 'online' or 'offline'
    timestamp TEXT NOT NULL,
    previous_state TEXT,                -- Previous state (NULL for first event)
    new_state TEXT NOT NULL,            -- New state ('online' or 'offline')
    FOREIGN KEY (ip_address) REFERENCES devices(ip_address)
)
```

### 2. State Monitor Process

A new background process monitors device states and logs transitions:

- **Threshold**: Devices are considered offline if not seen for 10 minutes
- **Check Interval**: State is checked every 60 seconds (configurable)
- **Transition Logging**: When a device crosses the threshold in either direction, an event is logged

### 3. Timeline Display

The web frontend timeline now shows:
- **State transition events**: Actual historical events when devices went online/offline
- **Discovery events**: When devices were first seen on the network
- **Anomaly events**: Security-related events

## Installation

### 1. Update Database Schema

The database schema will be automatically updated when you restart the application. The new `device_state_events` table will be created if it doesn't exist.

### 2. Install/Reinstall Package

If you've made changes to the code, reinstall the package:

```bash
pip install -e .
```

This will install the new `blacktip-state-monitor` command.

## Usage

### Running the State Monitor

Start the state monitor in a separate terminal or as a background service:

```bash
# Basic usage
blacktip-state-monitor -f /path/to/blacktip.db

# With custom check interval (default is 60 seconds)
blacktip-state-monitor -f /path/to/blacktip.db -i 30

# With debug output
blacktip-state-monitor -f /path/to/blacktip.db -d
```

### Running as a Service

You can run the state monitor as a systemd service alongside the main blacktip service.

Create `/etc/systemd/system/blacktip-state-monitor.service`:

```ini
[Unit]
Description=Blacktip Device State Monitor
After=network.target blacktip.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/blacktip-state-monitor -f /var/lib/blacktip/blacktip.db -i 60
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable blacktip-state-monitor
sudo systemctl start blacktip-state-monitor
sudo systemctl status blacktip-state-monitor
```

### Viewing State Events

State transition events automatically appear in the web UI timeline at:
```
http://your-server:5000/#timeline
```

## Configuration

### Offline Threshold

The offline threshold is defined in `src/blacktip/utils/state_monitor.py`:

```python
# Consider device offline if not seen in this many minutes
OFFLINE_THRESHOLD_MINUTES = 10
```

This should match the threshold used in the web frontend (`web-frontend/app.py`):

```python
ONLINE_THRESHOLD_MINUTES = 10
```

### Check Interval

Control how often the monitor checks for state changes using the `-i` flag:

```bash
# Check every 30 seconds
blacktip-state-monitor -f /path/to/blacktip.db -i 30

# Check every 2 minutes (120 seconds)
blacktip-state-monitor -f /path/to/blacktip.db -i 120
```

**Recommendation**: Use 60 seconds (1 minute) for a good balance between responsiveness and resource usage.

## Database Queries

### Get All State Events

```sql
SELECT * FROM device_state_events 
ORDER BY timestamp DESC 
LIMIT 100;
```

### Get Events for Specific Device

```sql
SELECT * FROM device_state_events 
WHERE ip_address = '192.168.1.100' 
ORDER BY timestamp DESC;
```

### Count State Changes by Device

```sql
SELECT 
    ip_address, 
    mac_address, 
    COUNT(*) as transition_count
FROM device_state_events 
GROUP BY ip_address, mac_address 
ORDER BY transition_count DESC;
```

### Devices That Go Offline Frequently

```sql
SELECT 
    ip_address,
    mac_address,
    COUNT(*) as offline_count
FROM device_state_events 
WHERE new_state = 'offline'
GROUP BY ip_address, mac_address
HAVING offline_count > 10
ORDER BY offline_count DESC;
```

## Troubleshooting

### State Monitor Not Logging Events

1. **Check the monitor is running**: `ps aux | grep blacktip-state-monitor`
2. **Check database permissions**: Ensure the monitor can write to the database
3. **Enable debug mode**: Run with `-d` flag to see detailed logging
4. **Check threshold**: Verify `OFFLINE_THRESHOLD_MINUTES` matches your expectations

### Events Not Showing in Timeline

1. **Refresh the page**: The timeline may need to be refreshed
2. **Check database**: Query `device_state_events` table directly
3. **Verify events exist**: `SELECT COUNT(*) FROM device_state_events;`
4. **Check web server logs**: Look for errors in the Flask application

### Too Many Events

If you're getting too many state change events:

1. **Increase the offline threshold**: Devices may be intermittently seen
2. **Increase check interval**: Check less frequently (e.g., every 2-3 minutes)
3. **Investigate flaky devices**: Some devices may have unstable network connections

## Migration from Old System

The old timeline system showed current status as events. The new system:

- **Before**: Timeline showed "Device X went online" for every currently-online device on each page load
- **After**: Timeline shows actual historical state transitions that occurred in the past

When you first run the state monitor:
1. It initializes the current state of all devices
2. Future changes are logged as transitions
3. Old "status snapshot" events are replaced with actual transition events

## API Access

The state events are accessible via the existing timeline API:

```bash
curl http://localhost:5000/api/timeline?limit=50
```

State transition events are included with `event_type` of `'online'` or `'offline'`.

## Performance Considerations

- **Database Growth**: State events accumulate over time. Consider implementing data retention policies.
- **Check Frequency**: More frequent checks (lower interval) = more accurate but higher CPU usage
- **Memory Usage**: The state monitor keeps state in memory for all devices (~100 bytes per device)

## Future Enhancements

Possible improvements:
- Configurable thresholds per device type
- State change notifications (email, webhook, etc.)
- Advanced analytics (uptime percentage, availability reports)
- State prediction based on patterns
- Integration with alerting systems
