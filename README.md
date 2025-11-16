# Blacktip

**Passive network security scanner for real-time ARP traffic analysis, device fingerprinting, and threat detection on Linux systems**

Blacktip is a lightweight, passive network monitoring tool that captures and analyzes ARP (Address Resolution Protocol) traffic to discover devices, track network changes, and detect potential security threats. It runs continuously in the background, automatically cataloging every device on your network with zero configuration required.

Unlike active scanners that send probe packets, Blacktip operates passively by listening to existing network traffic, making it completely invisible to other devices and ideal for security monitoring without alerting potential intruders.

## Features

- **Passive Network Monitoring**: Zero-footprint ARP packet capture with no network traffic generation
- **Real-time Device Discovery**: Instant detection of new devices the moment they join your network
- **Automated Security Scanning**: Integrated nmap scans automatically fingerprint new devices (ports, services, OS detection)
- **Anomaly Detection**: Identifies ARP spoofing, IP conflicts, gratuitous ARP abuse, and MAC address changes
- **Persistent SQLite Database**: Efficient storage with full device history, timestamps, and scan results
- **Performance Metrics**: Optional built-in metrics tracking for monitoring tool health and network activity patterns
- **Flexible Event Handling**: Execute custom scripts/commands on any network event with template substitution
- **Structured JSON Output**: Machine-readable event stream for integration with logging and SIEM systems
- **MAC Vendor Lookup**: Automatic manufacturer identification from IEEE OUI database
- **Production Ready**: Designed for 24/7 operation with robust error handling and atomic database writes

## Requirements

- **Operating System**: Linux (tested on modern distributions)
- **Python**: 3.8 or higher
- **Privileges**: Root/sudo access required for packet capture
- **Optional**: nmap for automated device scanning

## Installation

### From Source

1. Clone the repository:
```bash
git clone https://github.com/mhawthorne-nip/blacktip.git
cd blacktip
```

2. Install using pip:
```bash
# Standard installation
pip install .

# Development installation (editable mode)
pip install -e .

# Install with all optional dependencies
pip install ".[all]"
```

3. Verify installation:
```bash
blacktip --version
```

## Quick Start

### Basic Network Monitoring

Start monitoring your network and save data to a SQLite database:

```bash
sudo blacktip -f /var/lib/blacktip/network.db
```

**What happens next:**
1. Blacktip begins passively listening to ARP traffic on your default network interface
2. When a new device is detected, it outputs a JSON event to stdout
3. Nmap automatically scans the new device (can take 30-60 seconds per device)
4. All device information, scan results, and timestamps are stored in the SQLite database
5. Metrics are logged every 5 minutes showing traffic patterns and tool performance
6. The process runs continuously until you press Ctrl+C

**Expected output when a new device appears:**
```json
{"op":"reply","trigger":"new_ip_reply","ip":{"address":"192.168.1.50","new":true},"hw":{"address":"a4:83:e7:2f:1a:bc","vendor":"Apple, Inc.","new":false},"ts":"2025-01-15T14:23:45.678Z"}
```

### Query the Database

Search for information about a specific IP or MAC address:

```bash
blacktip -f /var/lib/blacktip/network.db -q 192.168.1.100
blacktip -f /var/lib/blacktip/network.db -q aa:bb:cc:dd:ee:ff
```

## Usage Examples

### Monitor Specific Interface

```bash
sudo blacktip -f network.db --interface eth0
```

### Custom Command Execution

Execute custom scripts or commands when new devices are detected. This is useful for notifications, logging, or triggering security responses:

```bash
sudo blacktip -f network.db -e "/usr/local/bin/notify.sh {IP} {HW}"
```

**Available template substitutions:**
- `{IP}` - IPv4 address (e.g., `192.168.1.100`)
- `{HW}` - Hardware/MAC address (e.g., `aa:bb:cc:dd:ee:ff`)
- `{TS}` - Full UTC timestamp (e.g., `2025-01-15T14:23:45.678901Z`)
- `{ts}` - Short UTC timestamp (e.g., `2025-01-15T14:23:45Z`)

**Example notification script** (`/usr/local/bin/notify.sh`):
```bash
#!/bin/bash
echo "New device detected: IP=$1, MAC=$2" | mail -s "Network Alert" admin@example.com
```

**Note:** When using `-e/--exec`, nmap scanning is automatically disabled. If you want nmap scans, use the default behavior (without `-e`).

### Disable Automatic Nmap Scanning

Run without nmap if you only want to track devices without port scanning:

```bash
sudo blacktip -f network.db --no-nmap
```

This significantly reduces system load and eliminates active network traffic.

### Monitor All ARP Traffic

**Default behavior** (recommended for most users):
- Only reports events when NEW IP or MAC addresses are discovered
- Minimal output, focuses on network changes

**Monitor everything** (useful for debugging or high-security environments):
```bash
sudo blacktip -f network.db --all-request --all-reply
```
This outputs EVERY ARP packet seen on the network, which can be hundreds per minute on busy networks.

### Filter Specific Traffic Types

**Monitor only ARP replies** (typical for device discovery):
```bash
sudo blacktip -f network.db --no-request
```
ARP replies are generally more reliable for device detection since they confirm actual device presence.

**Monitor only ARP requests** (useful for detecting scan attempts):
```bash
sudo blacktip -f network.db --no-reply
```
Unusual ARP request patterns can indicate network scanning or ARP probing attacks.

### Disable Metrics Collection

```bash
sudo blacktip -f network.db --no-metrics
```

### Debug Mode

Enable verbose debug output:

```bash
sudo blacktip -f network.db --debug
```

## Command-Line Options

### Datafile Arguments

| Option | Description |
|--------|-------------|
| `-f, --datafile <file>` | SQLite database for storing ARP data |
| `-i, --interval <seconds>` | Interval between database writes (default: 30) |
| `--interface <name>` | Network interface to monitor (e.g., eth0, wlan0) |

### Event Selection

| Option | Description |
|--------|-------------|
| `-req, --new-request` | Report new devices in ARP requests (default) |
| `-noreq, --no-request` | Ignore ARP request events |
| `-allreq, --all-request` | Report all ARP requests |
| `-rep, --new-reply` | Report new devices in ARP replies (default) |
| `-norep, --no-reply` | Ignore ARP reply events |
| `-allrep, --all-reply` | Report all ARP replies |

### Command Execution

| Option | Description |
|--------|-------------|
| `-e, --exec <command>` | Execute command on ARP events |
| `-n, --nmap` | Run nmap on new devices (default) |
| `--no-nmap` | Disable automatic nmap scanning |
| `-u, --user <username>` | Execute commands as specified user |

### Run Modes

| Option | Description |
|--------|-------------|
| `-q, --query <address>` | Query database for IP or MAC address |
| `-v, --version` | Display version information |
| `-d, --debug` | Enable debug output |
| `--metrics` | Enable metrics collection (default) |
| `--no-metrics` | Disable metrics collection |
| `--metrics-interval <seconds>` | Metrics logging interval (default: 300) |

## Database Management

### SQLite Database (Recommended)

Blacktip uses SQLite for efficient data storage:

```bash
# Create a new database
sudo blacktip -f /var/lib/blacktip/network.db

# The database automatically stores:
# - IP addresses and first/last seen timestamps
# - MAC addresses and vendor information
# - Nmap scan results (ports, services, OS detection)
# - ARP event history
# - Network statistics
```

## Output Format

Blacktip outputs structured JSON objects for each detected ARP event to stdout:

```json
{
  "op": "reply",
  "trigger": "new_ip_reply",
  "ip": {
    "address": "192.168.1.100",
    "new": true
  },
  "hw": {
    "address": "aa:bb:cc:dd:ee:ff",
    "vendor": "Apple, Inc.",
    "new": false
  },
  "ts": "2025-01-15T10:30:45.123456Z",
  "gratuitous": false,
  "anomalies": []
}
```

**Field descriptions:**
- `op`: Operation type - `"request"` or `"reply"`
- `trigger`: Why this event was reported (e.g., `"new_ip_reply"`, `"all_request"`)
- `ip.address`: IPv4 address involved in the ARP event
- `ip.new`: `true` if this IP has never been seen before
- `hw.address`: MAC address (hardware address)
- `hw.vendor`: Device manufacturer from OUI lookup (e.g., "Apple, Inc.", "Intel Corporate")
- `hw.new`: `true` if this MAC address is new to the network
- `ts`: UTC timestamp in ISO 8601 format
- `gratuitous`: `true` for gratuitous ARP (unsolicited announcements, often legitimate but can indicate spoofing)
- `anomalies`: Array of detected anomalies (e.g., `["ip_conflict"]`, `["mac_change"]`)

**Common trigger types:**
- `new_ip_reply` - New IP address seen in an ARP reply (most common)
- `new_hw_reply` - New MAC address seen in an ARP reply
- `new_ip_request` - New IP making an ARP request
- `all_reply` - All ARP replies (when using `--all-reply`)
- `all_request` - All ARP requests (when using `--all-request`)

## Security Considerations

### Privilege Requirements

Blacktip requires root privileges to:
- Capture raw network packets (CAP_NET_RAW capability)
- Open network interfaces in promiscuous mode
- Run nmap port scans (if enabled)

**Always run with sudo or as root:**
```bash
sudo blacktip -f network.db
```

**Security implications:**
- Root access allows packet capture on all interfaces
- Nmap scans are active and may be detected by IDS/IPS systems
- Command execution (if used) runs with elevated privileges

---

### Running Commands as Different User

For defense in depth, execute triggered commands as a non-privileged user:

```bash
sudo blacktip -f network.db -e "/path/to/script.sh {IP}" -u nobody
```

This limits the blast radius if the executed command is compromised. The script runs as `nobody` while Blacktip retains root for packet capture.

**Example use case:** Send notifications without giving the notification script root access.

---

### Network Security Best Practices

**Deployment security:**
- Run on dedicated monitoring systems or security appliances when possible
- Isolate monitoring systems from production networks
- Use SPAN/mirror ports for monitoring high-security networks
- Restrict SSH access to monitoring systems

**Data protection:**
```bash
# Restrict database file permissions
sudo chmod 600 /var/lib/blacktip/network.db
sudo chown root:root /var/lib/blacktip/network.db

# Store database on encrypted filesystem
sudo cryptsetup luksFormat /dev/sdb1
```

**Operational security:**
- Review nmap scan results regularly for unauthorized devices
- **Monitor anomalies array** - ARP spoofing attempts will appear here
- Set up alerts for common attack patterns (IP conflicts, MAC changes)
- Maintain audit logs of all detected devices
- Keep blacktip and dependencies updated

**Detection capabilities:**
Blacktip can help detect:
- **ARP spoofing/poisoning** - Same IP with different MACs or vice versa
- **MAC address cloning** - Anomaly detection flags suspicious changes
- **Rogue devices** - Any new device triggers alerts
- **Network reconnaissance** - Unusual ARP request patterns
- **IP conflicts** - Multiple devices claiming same IP

**Integration with security tools:**
```bash
# Send events to SIEM
sudo blacktip -f network.db 2>&1 | \
  tee >(jq -c . | nc siem-server 514)

# Alert on anomalies only
sudo blacktip -f network.db | \
  jq 'select(.anomalies | length > 0)' | \
  /usr/local/bin/send-alert.sh
```

## Development

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/mhawthorne-nip/blacktip.git
cd blacktip

# Install in development mode with all dependencies
pip install -e ".[all]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src/blacktip --cov-report=html

# Run specific test types
pytest -m unit
pytest -m integration
```

### Project Structure

```
blacktip/
├── src/blacktip/          # Main package
│   ├── blacktip.py        # Core monitoring logic
│   ├── cli/               # CLI entry points
│   ├── utils/             # Utility modules
│   │   ├── database.py    # Database operations
│   │   ├── sniffer.py     # Packet sniffing
│   │   ├── security.py    # Security utilities
│   │   ├── metrics.py     # Metrics collection
│   │   └── nmap_parser.py # Nmap result parsing
│   └── exceptions/        # Custom exceptions
├── tests/                 # Test suite
├── pyproject.toml         # Project configuration
└── requirements.txt       # Dependencies
```

## Troubleshooting

### Permission Denied Error

**Symptom:**
```
ERROR: blacktip requires root privileges to sniff network interfaces!
```

**Cause:** Packet capture requires CAP_NET_RAW capability, which is restricted to root.

**Solution:** Run with sudo:
```bash
sudo blacktip -f network.db
```

**Alternative (for advanced users):** Grant capabilities to Python interpreter:
```bash
sudo setcap cap_net_raw=eip $(readlink -f $(which python3))
```
⚠️ **Warning:** This grants packet capture to all Python scripts. Only use in controlled environments.

---

### No Packets Captured / No Output

**Symptom:** Blacktip runs but never outputs any events.

**Possible causes:**
1. **Wrong network interface** - Listening on interface with no ARP traffic
2. **Quiet network** - No new devices joining (normal during idle periods)
3. **Firewall/SELinux** - Blocking raw socket access
4. **Virtual environment** - Running in VM/container without proper network access

**Diagnostic steps:**
```bash
# 1. List available interfaces and their traffic
ip -s link show

# 2. Verify ARP traffic exists on your interface
sudo tcpdump -i eth0 arp -c 5

# 3. Specify the correct interface explicitly
sudo blacktip -f network.db --interface eth0 --debug

# 4. Monitor all traffic to verify Blacktip is working
sudo blacktip -f network.db --all-request --all-reply --debug
```

**If still no output:** Check that there's actual network activity. Ping another device to generate ARP traffic:
```bash
# In another terminal
ping 192.168.1.1
```

---

### Nmap Not Found or Scanning Fails

**Symptom:** Nmap scans don't appear to run or you see nmap-related errors in debug output.

**Cause:** Nmap not installed or not in PATH.

**Solution:**
```bash
# Install nmap
sudo apt-get install nmap  # Debian/Ubuntu
sudo dnf install nmap      # Fedora
sudo yum install nmap      # RHEL/CentOS

# Verify installation
which nmap
nmap --version
```

**If you don't want nmap scanning:**
```bash
sudo blacktip -f network.db --no-nmap
```

---

### Database Locked Error

**Symptom:** `database is locked` error when querying.

**Cause:** Another blacktip instance or process is writing to the database.

**Solution:**
1. Ensure only one blacktip instance writes to the database
2. Use separate databases for separate monitoring interfaces
3. Query operations are safe while monitoring is running

---

### High CPU Usage

**Symptom:** Blacktip consuming significant CPU.

**Common causes:**
1. **High ARP traffic** - Busy network with many devices
2. **All-traffic mode** - Using `--all-request --all-reply` on busy network
3. **Continuous nmap scans** - Many new devices being detected simultaneously

**Solutions:**
```bash
# Reduce load by monitoring only new devices (default behavior)
sudo blacktip -f network.db

# Disable nmap if not needed
sudo blacktip -f network.db --no-nmap

# Disable metrics collection
sudo blacktip -f network.db --no-metrics

# Increase database write interval
sudo blacktip -f network.db -i 60
```

---

### MAC Vendor Lookup Fails

**Symptom:** `hw.vendor` is `null` or missing.

**Cause:** MAC address not in OUI database or network connectivity issue during lookup.

**This is normal for:**
- Locally administered MAC addresses (LAA)
- Private/randomized MAC addresses
- Very new devices not yet in the database

**Solution:** Not usually a problem. The tool will still function correctly; vendor information is supplementary.

## Performance Tuning

### For High-Traffic Networks (100+ devices)

**Challenge:** High packet rates can cause CPU spikes and excessive disk I/O.

**Optimizations:**
```bash
# Minimal overhead configuration
sudo blacktip -f network.db \
  --no-nmap \          # Disable CPU-intensive port scanning
  --no-metrics \       # Reduce metrics overhead
  -i 120              # Less frequent database writes (2 minutes)

# Discovery-only mode (no active scanning)
sudo blacktip -f network.db --no-nmap --no-metrics
```

**Expected performance:**
- CPU: < 5% on modern hardware
- Memory: ~50-100 MB
- Disk I/O: Minimal (writes every 2 minutes)

---

### For Low-Traffic Networks (< 20 devices)

**Goal:** Maximum visibility and rapid detection.

**Optimizations:**
```bash
# Aggressive monitoring configuration
sudo blacktip -f network.db \
  -i 10 \                    # Frequent database updates (10 seconds)
  --metrics-interval 60 \    # Frequent metrics logging
  --all-request --all-reply  # See all ARP activity

# High-security mode (detect all activity)
sudo blacktip -f network.db --all-request --all-reply --debug
```

**Use cases:**
- Security-critical networks
- Debugging network issues
- Detecting stealth scanning attempts
- Monitoring for ARP spoofing

---

### Production Deployment Best Practices

**1. Run as a systemd service** (recommended):
```bash
# Create /etc/systemd/system/blacktip.service
[Unit]
Description=Blacktip Network Monitor
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/blacktip -f /var/lib/blacktip/network.db --no-metrics
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**2. Log rotation for output**:
```bash
# Run with output redirection
sudo blacktip -f /var/lib/blacktip/network.db 2>&1 | \
  logger -t blacktip -p local0.info
```

**3. Resource limits**:
```bash
# Limit memory and CPU in systemd service
MemoryMax=256M
CPUQuota=20%
```

**4. Database maintenance**:
```bash
# Periodic database optimization (weekly cron job)
sqlite3 /var/lib/blacktip/network.db 'VACUUM; ANALYZE;'
```

---

### Monitoring Multiple Networks

Run separate instances for each network interface:
```bash
# Terminal 1: Monitor LAN
sudo blacktip -f /var/lib/blacktip/lan.db --interface eth0

# Terminal 2: Monitor DMZ
sudo blacktip -f /var/lib/blacktip/dmz.db --interface eth1

# Terminal 3: Monitor Guest WiFi
sudo blacktip -f /var/lib/blacktip/guest.db --interface wlan0
```

Each instance maintains its own database and operates independently.

## License

This software is private and proprietary. All rights reserved.

## Author

**Michael Hawthorne**
- Email: mph005@gmail.com
- GitHub: [@mhawthorne-nip](https://github.com/mhawthorne-nip)

## Acknowledgments

Built with:
- [Scapy](https://scapy.net/) - Packet manipulation library
- [psutil](https://github.com/giampaolo/psutil) - System utilities
- [mac-vendor-lookup](https://github.com/bauerj/mac_vendor_lookup) - MAC address vendor lookup
- [nmap](https://nmap.org/) - Network scanning and security auditing

## Links

- **Homepage**: https://github.com/mhawthorne-nip/blacktip
- **Documentation**: https://github.com/mhawthorne-nip/blacktip/blob/main/README.md
- **Repository**: https://github.com/mhawthorne-nip/blacktip
- **Issues**: https://github.com/mhawthorne-nip/blacktip/issues

---

**Version 1.0.0** | For private use only
