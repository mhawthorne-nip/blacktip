# Blacktip Web Frontend

A web-based dashboard for viewing and managing devices discovered by the Blacktip network scanner.

## Features

- **Device List**: View all discovered devices with real-time status
- **Online/Offline Status**: Automatically determine device status based on last seen time
- **Sortable Columns**: Sort by any column (IP, MAC, vendor, hostname, last seen, etc.)
- **Search**: Filter devices by IP, MAC address, vendor, or hostname
- **Filter by Status**: Show only online or offline devices
- **Device Details**: Click any device to view detailed information including:
  - Basic device info (IP, MAC, vendor, hostname)
  - Port scan results from nmap
  - NetBIOS/SMB information
  - Security anomalies
  - Recent ARP events
- **Auto-refresh**: Dashboard automatically refreshes every 30 seconds
- **Responsive Design**: Works on desktop and mobile devices

## Installation

### Prerequisites

- Python 3.8 or higher
- Blacktip scanner installed and running
- Access to Blacktip's SQLite database

### Setup

1. Install dependencies:

```bash
cd web-frontend
pip install -r requirements.txt
```

2. Set the database path (if not using default):

```bash
export BLACKTIP_DB=/path/to/blacktip.db
```

Default path: `/var/lib/blacktip/blacktip.db`

## Running the Web Frontend

### Development Mode

```bash
cd web-frontend
python app.py
```

The web interface will be available at: `http://localhost:5000`

### Production Mode

For production, use a WSGI server like Gunicorn:

```bash
# Install gunicorn
pip install gunicorn

# Run with gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Running as a Service

Create a systemd service file at `/etc/systemd/system/blacktip-web.service`:

```ini
[Unit]
Description=Blacktip Web Frontend
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/blacktip/web-frontend
Environment="BLACKTIP_DB=/var/lib/blacktip/blacktip.db"
ExecStart=/usr/bin/gunicorn -w 4 -b 0.0.0.0:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable blacktip-web.service
sudo systemctl start blacktip-web.service
```

## Configuration

### Environment Variables

- `BLACKTIP_DB`: Path to Blacktip SQLite database (default: `/var/lib/blacktip/blacktip.db`)
- `PORT`: Web server port (default: `5000`)
- `DEBUG`: Enable Flask debug mode (default: `false`)

### Online/Offline Threshold

Devices are considered "online" if they were seen within the last 10 minutes. This can be adjusted in `app.py`:

```python
ONLINE_THRESHOLD_MINUTES = 10  # Adjust as needed
```

## API Endpoints

The web frontend provides a RESTful API:

### GET /api/devices

Returns all devices with enriched data.

**Response:**
```json
[
  {
    "id": 1,
    "ip_address": "192.168.1.100",
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "vendor": "Apple, Inc.",
    "is_online": true,
    "time_ago": "2 minutes ago",
    "open_port_count": 5,
    ...
  }
]
```

### GET /api/devices/:ip_address

Returns detailed information for a specific device.

**Response:**
```json
{
  "ip_address": "192.168.1.100",
  "mac_address": "aa:bb:cc:dd:ee:ff",
  "vendor": "Apple, Inc.",
  "is_online": true,
  "nmap_scan": {
    "scan_start": "2025-01-15T10:30:00Z",
    "ports": [...],
    "netbios": {...}
  },
  "anomalies": [...],
  "recent_events": [...]
}
```

### GET /api/statistics

Returns database statistics.

**Response:**
```json
{
  "total_devices": 42,
  "online_devices": 28,
  "unique_macs": 42,
  "total_scans": 156,
  "total_anomalies": 3,
  "metadata": {...}
}
```

### GET /api/health

Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "database": "/var/lib/blacktip/blacktip.db"
}
```

## Architecture

```
web-frontend/
├── app.py                 # Flask backend API
├── requirements.txt       # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css     # Stylesheet
│   └── js/
│       └── app.js        # Frontend JavaScript
└── templates/
    └── index.html        # Main HTML page
```

### Technology Stack

- **Backend**: Flask (Python)
- **Frontend**: Vanilla JavaScript (no framework dependencies)
- **Database**: Read-only access to Blacktip's SQLite database
- **Styling**: Custom CSS with modern design

## Security Considerations

- **Read-only Database Access**: The web frontend only reads from the database
- **No Authentication**: This is designed for internal use only. If exposing to a network, add authentication
- **XSS Protection**: All user input is escaped before rendering
- **CORS**: Enabled for development; configure appropriately for production

## Troubleshooting

### Database Not Found

```
ERROR: Blacktip database not found at: /var/lib/blacktip/blacktip.db
```

**Solution**: Set the correct database path:

```bash
export BLACKTIP_DB=/actual/path/to/blacktip.db
python app.py
```

### Permission Denied

```
PermissionError: Cannot read Blacktip database
```

**Solution**: Ensure the web frontend process has read access to the database:

```bash
sudo chmod 644 /var/lib/blacktip/blacktip.db
```

### No Devices Showing

**Possible causes:**
1. Blacktip scanner is not running
2. No devices have been discovered yet
3. Database path is incorrect

**Solution**: Verify Blacktip is running and discovering devices:

```bash
sudo systemctl status blacktip.service
sqlite3 /var/lib/blacktip/blacktip.db "SELECT COUNT(*) FROM devices;"
```

## Development

### Making Changes

1. **Backend API Changes**: Edit `app.py`
2. **Frontend UI Changes**: Edit `templates/index.html` and `static/css/style.css`
3. **Frontend Logic Changes**: Edit `static/js/app.js`

### Running in Debug Mode

```bash
export DEBUG=true
python app.py
```

Debug mode enables:
- Auto-reload on code changes
- Detailed error messages
- Flask debug toolbar

## Future Enhancements

Potential features for future versions:

- [ ] User authentication and authorization
- [ ] Device grouping and tagging
- [ ] Custom alerts and notifications
- [ ] Network topology visualization
- [ ] Historical data and trending
- [ ] Export to CSV/PDF
- [ ] Dark mode theme
- [ ] Multi-user support with roles
- [ ] Vulnerability scanning integration
- [ ] Device notes and annotations

## License

Same as Blacktip main project.

## Support

For issues or questions:
1. Check the troubleshooting section above
2. Review Blacktip main documentation
3. Check if the Blacktip scanner is running properly
