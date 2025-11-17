# Blacktip Systemd Service Setup Guide

This guide explains how to set up Blacktip to run as a systemd service on Ubuntu with automatic startup on boot and file-based logging.

## Prerequisites

- Ubuntu 16.04 or later (or any systemd-based Linux distribution)
- Python 3.8 or later
- Root/sudo access
- Network interface access for packet capture

## Installation Steps

### 1. Install Blacktip

First, install the package system-wide. On modern Ubuntu/Debian systems (22.04+), you need to use the `--break-system-packages` flag:

```bash
# Install from the repository directory
cd /path/to/blacktip

# Ubuntu 22.04+ / Debian 12+ (externally-managed environment)
sudo pip install --break-system-packages .

# Or install in development mode if you plan to modify the code
sudo pip install --break-system-packages -e .

# Alternative: Use pipx (recommended for application installation)
sudo apt install pipx
sudo pipx install .
```

**Note:** The `--break-system-packages` flag is safe for installing applications (not libraries) that will run as system services. This is the standard approach for system-level tools that require root privileges.

Verify the installation:

```bash
blacktip --version
```

### 2. Create Required Directories

Create directories for data storage and logging:

```bash
# Create data directory
sudo mkdir -p /var/lib/blacktip
sudo chmod 755 /var/lib/blacktip

# Create log directory
sudo mkdir -p /var/log/blacktip
sudo chmod 755 /var/log/blacktip

# Create application directory (optional, for config files)
sudo mkdir -p /opt/blacktip
sudo chmod 755 /opt/blacktip
```

### 3. Install the Systemd Service File

Copy the service file to the systemd directory:

```bash
# Copy the service file
sudo cp blacktip.service /etc/systemd/system/

# Set correct permissions
sudo chmod 644 /etc/systemd/system/blacktip.service
```

### 4. Configure the Service

Edit the service file to customize parameters for your environment:

```bash
sudo nano /etc/systemd/system/blacktip.service
```

Key configuration options in the `ExecStart` line:

- `--datafile`: SQLite database path (default: `/var/lib/blacktip/blacktip.db`)
- `--interval`: Seconds between database writes (default: 300)
- `--interface`: Network interface to monitor (e.g., `eth0`, `wlan0`)
- `--nmap`: Enable automatic nmap scanning (default: enabled)
- `--no-nmap`: Disable automatic nmap scanning
- `--metrics`: Enable metrics collection (default: enabled)
- `--metrics-interval`: Seconds between metrics logging (default: 300)

Example with interface specified:

```ini
ExecStart=/usr/local/bin/blacktip \
    --datafile /var/lib/blacktip/blacktip.db \
    --interface eth0 \
    --interval 300 \
    --nmap \
    --metrics \
    --metrics-interval 300
```

### 5. Enable and Start the Service

```bash
# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable the service to start on boot
sudo systemctl enable blacktip.service

# Start the service now
sudo systemctl start blacktip.service

# Check the service status
sudo systemctl status blacktip.service
```

## Managing the Service

### Check Service Status

```bash
sudo systemctl status blacktip.service
```

### Start the Service

```bash
sudo systemctl start blacktip.service
```

### Stop the Service

```bash
sudo systemctl stop blacktip.service
```

### Restart the Service

```bash
sudo systemctl restart blacktip.service
```

### Disable Auto-Start on Boot

```bash
sudo systemctl disable blacktip.service
```

### View Service Logs

```bash
# View recent logs
sudo journalctl -u blacktip.service -n 100

# Follow logs in real-time
sudo journalctl -u blacktip.service -f

# View logs from the log file
sudo tail -f /var/log/blacktip/blacktip.log

# View all logs from today
sudo journalctl -u blacktip.service --since today
```

## Log Management

### Log Rotation

To prevent log files from growing indefinitely, set up log rotation:

Create a logrotate configuration file:

```bash
sudo nano /etc/logrotate.d/blacktip
```

Add the following content:

```
/var/log/blacktip/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
    sharedscripts
    postrotate
        systemctl reload blacktip.service >/dev/null 2>&1 || true
    endscript
}
```

This configuration:
- Rotates logs daily
- Keeps 30 days of logs
- Compresses old logs
- Creates new log files with proper permissions

### Manual Log Cleanup

```bash
# View log file size
du -h /var/log/blacktip/blacktip.log

# Clear the log file (service must be stopped first)
sudo systemctl stop blacktip.service
sudo truncate -s 0 /var/log/blacktip/blacktip.log
sudo systemctl start blacktip.service
```

## Querying the Database

While the service is running, you can query the database:

```bash
# Query for a specific IP address
blacktip --datafile /var/lib/blacktip/blacktip.db --query 192.168.1.100

# Query for a MAC address
blacktip --datafile /var/lib/blacktip/blacktip.db --query aa:bb:cc:dd:ee:ff
```

## Troubleshooting

### Service Won't Start

1. Check the service status:
   ```bash
   sudo systemctl status blacktip.service
   ```

2. Check for errors in the logs:
   ```bash
   sudo journalctl -u blacktip.service -n 50
   ```

3. Verify permissions:
   ```bash
   # Check if blacktip is executable
   which blacktip
   ls -l $(which blacktip)
   
   # Check directory permissions
   ls -ld /var/lib/blacktip
   ls -ld /var/log/blacktip
   ```

4. Test blacktip manually:
   ```bash
   sudo blacktip --datafile /tmp/test.db --interface eth0
   ```

### Permission Errors

Blacktip requires root privileges for packet capture. Ensure the service runs as root or grant CAP_NET_RAW capability:

```bash
# Grant capability (alternative to running as root)
sudo setcap cap_net_raw+ep $(which blacktip)
```

Then modify the service file to run as a non-root user:

```ini
[Service]
User=blacktip
Group=blacktip
```

### High CPU/Memory Usage

1. Increase the save interval to reduce database writes:
   ```ini
   ExecStart=/usr/local/bin/blacktip --datafile /var/lib/blacktip/blacktip.db --interval 600
   ```

2. Disable nmap scanning if not needed:
   ```ini
   ExecStart=/usr/local/bin/blacktip --datafile /var/lib/blacktip/blacktip.db --no-nmap
   ```

3. Monitor with:
   ```bash
   sudo systemctl status blacktip.service
   top -p $(pgrep -f blacktip)
   ```

## Uninstalling

To completely remove the service:

```bash
# Stop and disable the service
sudo systemctl stop blacktip.service
sudo systemctl disable blacktip.service

# Remove the service file
sudo rm /etc/systemd/system/blacktip.service

# Reload systemd
sudo systemctl daemon-reload

# Optionally remove data and logs
sudo rm -rf /var/lib/blacktip
sudo rm -rf /var/log/blacktip
sudo rm /etc/logrotate.d/blacktip

# Uninstall the package
sudo pip uninstall blacktip
```

## Security Considerations

1. **Run as non-root**: Consider using capabilities instead of root privileges
2. **File permissions**: Ensure log and data directories are properly secured
3. **Network access**: Limit which interfaces blacktip monitors
4. **Database security**: Consider encrypting the SQLite database
5. **Log sensitivity**: Logs may contain network information - secure appropriately

## Additional Resources

- [Systemd Service Documentation](https://www.freedesktop.org/software/systemd/man/systemd.service.html)
- [Logrotate Documentation](https://linux.die.net/man/8/logrotate)
- [Blacktip Repository](https://github.com/mhawthorne-nip/blacktip)
