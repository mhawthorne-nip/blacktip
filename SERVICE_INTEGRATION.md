# Blacktip Service Integration

This document describes the integrated systemd service for Blacktip that runs the scanner, state monitor, and web frontend together on system bootup.

## Overview

The `blacktip.service` systemd unit runs three components together:

1. **Blacktip Scanner** - Main passive ARP monitoring and nmap scanning
2. **State Monitor** - Active device state tracking with ARP/ICMP probing
3. **Web Frontend** - Dashboard interface on port 5000

All components share the same database at `/var/lib/blacktip/blacktip.db`.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  blacktip.service (systemd unit)                        │
│  ├── blacktip (main scanner)          [root required]   │
│  │   └── ARP sniffing + nmap scanning                   │
│  ├── blacktip-state-monitor            [root required]  │
│  │   └── Active probing (ARP/ICMP)                      │
│  └── web-frontend (Flask app)                           │
│      └── Dashboard on http://localhost:5000             │
└─────────────────────────────────────────────────────────┘
                           │
                           ▼
              /var/lib/blacktip/blacktip.db
```

## Installation

### Quick Install

```bash
# From the blacktip repository directory
sudo ./install-service-with-frontend.sh
```

The installation script will:
1. Check that blacktip and blacktip-state-monitor are installed
2. Install web frontend dependencies (Flask, flask-cors)
3. Copy files to `/opt/blacktip/`
4. Create required directories
5. Install and enable the systemd service
6. Optionally start the service

### Manual Installation

If you prefer manual installation:

```bash
# 1. Install blacktip
pip install -e .

# 2. Install web frontend dependencies
pip install -r web-frontend/requirements.txt

# 3. Create directories
sudo mkdir -p /var/lib/blacktip /var/log/blacktip /var/run/blacktip
sudo chown -R root:root /var/lib/blacktip /var/log/blacktip /var/run/blacktip

# 4. Copy web frontend
sudo cp -r web-frontend /opt/blacktip/

# 5. Install service
sudo cp blacktip.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable blacktip.service
sudo systemctl start blacktip.service
```

## Service Management

### Start/Stop/Restart

```bash
# Start all components
sudo systemctl start blacktip.service

# Stop all components
sudo systemctl stop blacktip.service

# Restart all components
sudo systemctl restart blacktip.service

# Check status
sudo systemctl status blacktip.service
```

### Enable/Disable Autostart

```bash
# Enable autostart on boot
sudo systemctl enable blacktip.service

# Disable autostart
sudo systemctl disable blacktip.service
```

### View Logs

All components log to separate files:

```bash
# Service orchestration logs
tail -f /var/log/blacktip/service.log

# Main scanner logs
tail -f /var/log/blacktip/blacktip.log

# State monitor logs
tail -f /var/log/blacktip/state-monitor.log

# Web frontend logs
tail -f /var/log/blacktip/web-frontend.log

# Or use journalctl for systemd logs
sudo journalctl -u blacktip.service -f
```

## Configuration

### Service File Location

```
/etc/systemd/system/blacktip.service
```

### Default Settings

**Scanner:**
- Database: `/var/lib/blacktip/blacktip.db`
- Save interval: 300 seconds
- Nmap: Enabled
- Metrics: Enabled (logged every 300 seconds)

**State Monitor:**
- Check interval: 60 seconds
- Offline threshold: 300 seconds (5 minutes)
- Active probing: Enabled (requires root)
- Probe timeout: 1 second
- Probe retries: 2

**Web Frontend:**
- Port: 5000
- Database: `/var/lib/blacktip/blacktip.db`
- Host: 0.0.0.0 (accessible from network)

### Customizing Configuration

Edit the service file to change parameters:

```bash
sudo systemctl edit --full blacktip.service
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart blacktip.service
```

## File Locations

```
/etc/systemd/system/blacktip.service    # Service definition
/opt/blacktip/web-frontend/             # Web app files
/var/lib/blacktip/blacktip.db           # SQLite database
/var/log/blacktip/                      # Log directory
/var/run/blacktip/                      # PID files
```

## Process Management

The service uses a forking type with PID files for each component:

```
/var/run/blacktip/blacktip.pid          # Main scanner
/var/run/blacktip/state-monitor.pid     # State monitor
/var/run/blacktip/web-frontend.pid      # Web frontend
```

When stopping the service, all three processes are terminated gracefully.

## Security Considerations

### Root Privileges

The service runs as root because:
- **ARP sniffing** requires raw socket access
- **nmap scanning** requires root for advanced features
- **Active probing** (ARP/ICMP) requires root for packet crafting

### Database Permissions

The database file is set to mode 644 (readable by all) to allow:
- Root processes (scanner, monitor) to write
- Web frontend to read (even if running as different user in future)

### Network Access

The web frontend binds to `0.0.0.0:5000` by default, making it accessible from the network. Consider:

- Using a firewall to restrict access
- Running behind a reverse proxy (nginx, Apache)
- Implementing authentication (not currently included)

## Troubleshooting

### Service Won't Start

```bash
# Check service status
sudo systemctl status blacktip.service

# View recent logs
sudo journalctl -u blacktip.service -n 100

# Check if commands exist
which blacktip
which blacktip-state-monitor
which python3
```

### Web Frontend Not Accessible

```bash
# Check if frontend process is running
ps aux | grep "python3 app.py"

# Check frontend logs
tail -f /var/log/blacktip/web-frontend.log

# Check if port 5000 is listening
sudo netstat -tulpn | grep 5000

# Test health endpoint
curl http://localhost:5000/api/health
```

### State Monitor Not Probing

The state monitor requires root for active probing. Check:

```bash
# Check monitor logs
tail -f /var/log/blacktip/state-monitor.log

# Verify it's running as root
ps aux | grep blacktip-state-monitor

# Test manual probe (requires scapy)
sudo python3 -c "from scapy.all import *; sr1(ARP(pdst='192.168.1.1'), timeout=1)"
```

### Database Locked

If you see database locked errors:

```bash
# Check who has the database open
sudo lsof /var/lib/blacktip/blacktip.db

# Restart service to reset connections
sudo systemctl restart blacktip.service
```

## Uninstallation

### Quick Uninstall

```bash
sudo ./uninstall-service-with-frontend.sh
```

This removes the service but preserves data and logs.

### Complete Removal

To remove everything including data:

```bash
# Uninstall service
sudo ./uninstall-service-with-frontend.sh

# Remove all files
sudo rm -rf /var/lib/blacktip
sudo rm -rf /var/log/blacktip
sudo rm -rf /var/run/blacktip
sudo rm -rf /opt/blacktip

# Uninstall Python package
pip uninstall blacktip
```

## Accessing the Web Dashboard

Once the service is running:

1. Open browser to: http://localhost:5000
2. Or from another machine: http://your-server-ip:5000

The dashboard provides:
- Real-time device listing
- Online/offline status
- Device details and history
- Timeline of network events
- Search and filtering

## Performance Tuning

### Reduce Scan Frequency

Edit service file to increase intervals:

```bash
# Scanner save interval (default 300s)
--interval 600

# State monitor check interval (default 60s)
--interval 120

# Metrics logging interval (default 300s)
--metrics-interval 600
```

### Disable Features

```bash
# Disable nmap scanning
--no-nmap

# Disable active probing in state monitor
--no-probing

# Disable metrics
--no-metrics
```

### Log Rotation

Configure logrotate for blacktip logs:

```bash
sudo cat > /etc/logrotate.d/blacktip << EOF
/var/log/blacktip/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF
```

## Integration with Other Services

### Monitoring with Prometheus

The scanner can export metrics. To add Prometheus scraping:

1. Enable metrics in service (already enabled by default)
2. Configure Prometheus to scrape logs or add prometheus_client export

### Alerting

Set up alerts based on:
- New device discoveries (check timeline API)
- Devices going offline (check state events)
- Security anomalies (check anomalies table)

Example monitoring script:

```bash
#!/bin/bash
# Check for new devices in last hour
NEW_DEVICES=$(sqlite3 /var/lib/blacktip/blacktip.db \
  "SELECT COUNT(*) FROM devices WHERE datetime(first_seen) > datetime('now', '-1 hour')")

if [ "$NEW_DEVICES" -gt 0 ]; then
    echo "ALERT: $NEW_DEVICES new device(s) discovered"
    # Send notification (email, Slack, etc.)
fi
```

## Support

For issues or questions:
- Check logs in `/var/log/blacktip/`
- Review systemd status: `systemctl status blacktip.service`
- View this documentation: `SERVICE_INTEGRATION.md`
- Check main README: `README.md`
