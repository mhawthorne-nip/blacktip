# Quick Start Checklist - Device State Tracking

Follow these steps to enable device state transition tracking:

## ☐ Step 1: Reinstall Package

```bash
cd ~/blacktip
sudo pip install --break-system-packages -e .
```

**Expected output**: Installation completes successfully, `blacktip-state-monitor` command is available.

**Verify**:
```bash
which blacktip-state-monitor
# Should show: /usr/local/bin/blacktip-state-monitor
```

---

## ☐ Step 2: Test the State Monitor

Run manually first to verify it works:

```bash
# Replace with your actual database path
blacktip-state-monitor -f /var/lib/blacktip/blacktip.db -d
```

**Expected output**:
```
Initializing device state monitor...
Initialized X device states
Starting device state monitor (checking every 60 seconds)
```

Let it run for a minute, then press Ctrl+C to stop.

**Verify**: Check that state events were created:
```bash
sqlite3 /var/lib/blacktip/blacktip.db \
  "SELECT COUNT(*) FROM device_state_events;"
```

Should show a number > 0 (initial states for all devices).

---

## ☐ Step 3: Create Systemd Service (Optional but Recommended)

Create the service file:

```bash
sudo nano /etc/systemd/system/blacktip-state-monitor.service
```

Paste this content (adjust paths if needed):

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

Save and exit (Ctrl+X, Y, Enter).

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable blacktip-state-monitor
sudo systemctl start blacktip-state-monitor
```

**Verify**:
```bash
sudo systemctl status blacktip-state-monitor
```

Should show "active (running)" in green.

---

## ☐ Step 4: Verify Timeline is Working

1. Open your web browser
2. Navigate to: `http://192.168.0.103:5000/#timeline`
3. Look for "went online" or "went offline" events

**What to expect**:
- Initial states for all devices (will show up immediately)
- New transition events as devices go online/offline (wait 10+ minutes)

---

## ☐ Step 5: Test State Transitions (Optional)

To see state transitions in action:

1. Unplug a device from your network (or turn off WiFi on a phone)
2. Wait 11 minutes (past the 10-minute threshold)
3. Check the timeline - should show device went offline
4. Reconnect the device
5. Wait 1-2 minutes
6. Check timeline - should show device came online

---

## Monitoring Commands

### Check if monitor is running
```bash
ps aux | grep blacktip-state-monitor
```

### View recent state events
```bash
sqlite3 /var/lib/blacktip/blacktip.db \
  "SELECT timestamp, event_type, ip_address, new_state 
   FROM device_state_events 
   ORDER BY timestamp DESC 
   LIMIT 10;"
```

### Count state transitions per device
```bash
sqlite3 /var/lib/blacktip/blacktip.db \
  "SELECT ip_address, COUNT(*) as transitions 
   FROM device_state_events 
   GROUP BY ip_address 
   ORDER BY transitions DESC;"
```

### View monitor logs (if running as service)
```bash
sudo journalctl -u blacktip-state-monitor -f
```

---

## Troubleshooting

### ❌ Command not found: blacktip-state-monitor
**Solution**: Reinstall package (Step 1)

### ❌ Database locked error
**Solution**: Ensure main blacktip service isn't blocking the database
```bash
sudo systemctl restart blacktip
sleep 2
sudo systemctl restart blacktip-state-monitor
```

### ❌ No state events appearing
**Solution**: 
1. Check monitor is running: `ps aux | grep blacktip-state-monitor`
2. Check for errors: `sudo journalctl -u blacktip-state-monitor -n 50`
3. Run in debug mode: `blacktip-state-monitor -f /var/lib/blacktip/blacktip.db -d`

### ❌ Too many transition events
**Solution**: Increase check interval or offline threshold
```bash
# Check every 2 minutes instead of 1 minute
sudo systemctl edit blacktip-state-monitor
```
Change `ExecStart` line to include `-i 120`

---

## Configuration Files

- **Database schema**: `src/blacktip/utils/database.py`
- **State monitor**: `src/blacktip/utils/state_monitor.py`
- **Web timeline**: `web-frontend/app.py`
- **Systemd service**: `/etc/systemd/system/blacktip-state-monitor.service`

---

## Quick Reference

| Setting | Default | Location | Purpose |
|---------|---------|----------|---------|
| Offline threshold | 10 minutes | `state_monitor.py` | How long before marking offline |
| Check interval | 60 seconds | CLI flag `-i` | How often to check states |
| Timeline limit | 100 events | Web API | Max events shown on timeline |

---

## Success Criteria

✅ `blacktip-state-monitor` command exists  
✅ Service is running: `systemctl status blacktip-state-monitor`  
✅ Database has events: `SELECT COUNT(*) FROM device_state_events;`  
✅ Timeline shows transition events  
✅ No errors in logs: `journalctl -u blacktip-state-monitor`  

---

## Need Help?

- Full documentation: `DEVICE_STATE_MONITORING.md`
- Implementation details: `STATE_TRACKING_SUMMARY.md`
- Main README: `README.md`

Run with debug mode for detailed logging:
```bash
blacktip-state-monitor -f /var/lib/blacktip/blacktip.db -d
```
