# blacktip

A modern network monitoring tool that captures ARP packets and stores network device information in a SQLite database with JSON output support.

## Features

- **SQLite Database**: Fast, reliable storage with concurrent access support
- **Real-time Monitoring**: Capture and analyze ARP packets on your network
- **Anomaly Detection**: Detect ARP spoofing and IP/MAC conflicts
- **Command Execution**: Run custom commands when new devices are detected
- **Metrics Support**: Built-in performance monitoring
- **Web-Ready**: Database structure optimized for web frontend integration
- **Legacy Support**: Export to JSON for backward compatibility

## Installation

### Using Python Virtual Environment (recommended)
```shell
# Create virtual environment
user@computer:~$ python3 -m venv ~/blacktip-venv

# Activate virtual environment
user@computer:~$ source ~/blacktip-venv/bin/activate

# Install blacktip
(blacktip-venv) user@computer:~$ pip install blacktip
```

### Installing from source (development)
```shell
# Create and activate virtual environment
user@computer:~$ python3 -m venv ~/blacktip-venv
user@computer:~$ source ~/blacktip-venv/bin/activate

# Install in editable mode
(blacktip-venv) user@computer:~$ cd /path/to/blacktip
(blacktip-venv) user@computer:~$ pip install -e .
```

## Command line usage

### Basic Usage with SQLite Database (Recommended)
```shell
# Start monitoring and store data in SQLite database
user@computer:~$ sudo blacktip -f /var/lib/blacktip/arp_data.db

# Run nmap against all new hosts
user@computer:~$ sudo blacktip --nmap -f /var/lib/blacktip/arp_data.db

# Query the database for a specific IP or MAC
user@computer:~$ blacktip -f /var/lib/blacktip/arp_data.db -q 192.168.1.100
user@computer:~$ blacktip -f /var/lib/blacktip/arp_data.db -q aa:bb:cc:dd:ee:ff
```

### Export Database to JSON
```shell
# Export for backup or legacy compatibility
user@computer:~$ blacktip -f /var/lib/blacktip/arp_data.db --export-json backup.json
```

### Advanced Options
```shell
# Monitor specific interface with metrics
user@computer:~$ sudo blacktip --interface eth0 -f /var/lib/blacktip/arp_data.db --metrics

# Custom command execution on new devices
user@computer:~$ sudo blacktip -f arp_data.db -e "echo 'New device: {IP} / {HW}' >> /var/log/new_devices.log"
```

### Run as systemd service (recommended for production)
```shell
user@computer:~$ sudo cp docs/blacktip.service /etc/systemd/system/
user@computer:~$ sudo systemctl enable --now blacktip
```

## Database

Blacktip now uses **SQLite** for data storage, providing:
- Better performance with indexed queries
- Safe concurrent access for web frontends
- ACID compliance to prevent data corruption
- Efficient storage of millions of records

See [DATABASE_MIGRATION.md](DATABASE_MIGRATION.md) for complete documentation on:
- Database schema
- SQL query examples
- Web frontend integration
- Backup strategies
- Performance tuning

## Legacy JSON Support

While SQLite is recommended, you can still export to JSON format:
```shell
blacktip -f arp_data.db --export-json output.json
```
