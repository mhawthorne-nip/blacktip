# Blacktip

**Passive network security scanner for real-time ARP traffic analysis, device fingerprinting, and threat detection on Linux systems**

Blacktip is a modern network monitoring tool that captures and analyzes ARP (Address Resolution Protocol) traffic to detect network changes, new devices, and potential security threats. It provides JSON-formatted outputs and flexible options to execute commands when network events are observed.

## Features

- **Passive Network Monitoring**: Non-intrusive ARP packet sniffing to detect network activity
- **Real-time Device Discovery**: Automatically detect new devices joining the network
- **Automated Security Scanning**: Built-in nmap integration for automatic device fingerprinting
- **Anomaly Detection**: Identify suspicious ARP activity and potential security threats
- **Database Storage**: SQLite database for efficient data storage and querying
- **Metrics Collection**: Built-in performance and activity metrics tracking
- **Flexible Event Handling**: Execute custom commands on network events
- **JSON Output**: Structured, machine-readable output format
- **MAC Vendor Lookup**: Identify device manufacturers from MAC addresses
- **Linux Optimized**: Designed specifically for Linux systems with security best practices

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

This will:
- Monitor all network interfaces for ARP traffic
- Detect new IP and MAC addresses
- Automatically run nmap scans on new devices
- Store all data in a SQLite database
- Log metrics every 5 minutes

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

Run a custom script when new devices are detected:

```bash
sudo blacktip -f network.db -e "/usr/local/bin/notify.sh {IP} {HW}"
```

Available substitutions:
- `{IP}` - IPv4 address
- `{HW}` - Hardware (MAC) address
- `{TS}` - Full UTC timestamp
- `{ts}` - Short UTC timestamp

### Disable Automatic Nmap Scanning

```bash
sudo blacktip -f network.db --no-nmap
```

### Monitor All ARP Traffic

By default, blacktip only reports new devices. To see all ARP traffic:

```bash
sudo blacktip -f network.db --all-request --all-reply
```

### Focus on Specific Traffic Types

Monitor only ARP replies:

```bash
sudo blacktip -f network.db --no-request
```

Monitor only ARP requests:

```bash
sudo blacktip -f network.db --no-reply
```

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

Blacktip outputs JSON objects for each ARP event:

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

## Security Considerations

### Privilege Requirements

Blacktip requires root privileges to:
- Capture raw network packets
- Open network interfaces in promiscuous mode

Always run with sudo or as root:
```bash
sudo blacktip -f network.db
```

### Running Commands as Different User

For security, you can execute triggered commands as a non-privileged user:

```bash
sudo blacktip -f network.db -e "/path/to/script.sh {IP}" -u nobody
```

### Network Security Best Practices

- Run on dedicated monitoring systems when possible
- Restrict database file permissions: `chmod 600 network.db`
- Review nmap scan results regularly for unauthorized devices
- Monitor for ARP spoofing attempts (watch for anomalies)
- Keep blacktip and dependencies updated

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

```
ERROR: blacktip requires root privileges to sniff network interfaces!
```

**Solution**: Run with sudo: `sudo blacktip -f network.db`

### No Packets Captured

**Possible causes**:
- Wrong network interface (specify with `--interface`)
- No ARP traffic on network
- Firewall blocking packet capture

**Solution**:
```bash
# List available interfaces
ip link show

# Specify correct interface
sudo blacktip -f network.db --interface eth0
```

### Nmap Not Found

If nmap is not installed, automatic scanning will fail silently.

**Solution**: Install nmap or disable it:
```bash
# Install nmap
sudo apt-get install nmap  # Debian/Ubuntu
sudo yum install nmap      # RHEL/CentOS

# Or disable nmap scanning
sudo blacktip -f network.db --no-nmap
```

## Performance Tuning

### For High-Traffic Networks

```bash
# Reduce database write frequency
sudo blacktip -f network.db -i 60

# Disable metrics for minimal overhead
sudo blacktip -f network.db --no-metrics

# Monitor only new devices
sudo blacktip -f network.db  # default behavior
```

### For Low-Traffic Networks

```bash
# More frequent database updates
sudo blacktip -f network.db -i 10

# Monitor all traffic
sudo blacktip -f network.db --all-request --all-reply

# Frequent metrics logging
sudo blacktip -f network.db --metrics-interval 60
```

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
