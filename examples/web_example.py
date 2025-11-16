"""
Simple Flask web frontend for Blacktip SQLite database

Installation:
    pip install flask

Usage:
    export BLACKTIP_DB=/var/lib/blacktip/arp_data.db
    python web_example.py
    
Then visit: http://localhost:5000
"""

from flask import Flask, jsonify, render_template_string, request
import os
import sys

# Add blacktip to path if running from source
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from blacktip.utils.database import BlacktipDatabase

app = Flask(__name__)

# Get database path from environment or use default
DB_PATH = os.environ.get('BLACKTIP_DB', '/var/lib/blacktip/arp_data.db')

if not os.path.exists(DB_PATH):
    print("ERROR: Database file not found: {}".format(DB_PATH))
    print("Set BLACKTIP_DB environment variable or create database first")
    sys.exit(1)

db = BlacktipDatabase(DB_PATH)

# Simple HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Blacktip Network Monitor</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        .stats { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-box { background: #e3f2fd; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #1976d2; }
        .stat-label { color: #666; margin-top: 5px; }
        table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th { background: #1976d2; color: white; padding: 12px; text-align: left; }
        td { padding: 10px; border-bottom: 1px solid #ddd; }
        tr:hover { background: #f5f5f5; }
        .search-box { margin-bottom: 20px; }
        input[type="text"] { padding: 10px; width: 300px; border: 1px solid #ddd; border-radius: 4px; }
        button { padding: 10px 20px; background: #1976d2; color: white; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #1565c0; }
        .vendor { color: #666; font-size: 0.9em; }
        .new-badge { background: #4caf50; color: white; padding: 2px 8px; border-radius: 3px; font-size: 0.8em; }
        .anomaly { background: #ff5722; color: white; padding: 8px; border-radius: 4px; margin: 5px 0; }
        .timestamp { color: #999; font-size: 0.9em; }
    </style>
</head>
<body>
    <h1>🦈 Blacktip Network Monitor</h1>
    
    <div class="stats">
        <h2>Statistics</h2>
        <div class="stats-grid">
            <div class="stat-box">
                <div class="stat-value" id="ip-count">-</div>
                <div class="stat-label">Unique IP Addresses</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" id="mac-count">-</div>
                <div class="stat-label">Unique MAC Addresses</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" id="assoc-count">-</div>
                <div class="stat-label">Total Associations</div>
            </div>
            <div class="stat-box">
                <div class="stat-value" id="anomaly-count">-</div>
                <div class="stat-label">Anomalies Detected</div>
            </div>
        </div>
    </div>
    
    <div class="search-box">
        <input type="text" id="search-input" placeholder="Search by IP or MAC address...">
        <button onclick="searchAddress()">Search</button>
        <button onclick="loadDevices()">Show All</button>
    </div>
    
    <div id="search-results"></div>
    
    <h2>Recent Devices</h2>
    <table id="devices-table">
        <thead>
            <tr>
                <th>IP Address</th>
                <th>MAC Address</th>
                <th>Vendor</th>
                <th>First Seen</th>
                <th>Last Seen</th>
                <th>Packets</th>
            </tr>
        </thead>
        <tbody id="devices-body">
            <tr><td colspan="6">Loading...</td></tr>
        </tbody>
    </table>
    
    <script>
        function loadStats() {
            fetch('/api/stats')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('ip-count').textContent = data.unique_ip_addresses;
                    document.getElementById('mac-count').textContent = data.unique_mac_addresses;
                    document.getElementById('assoc-count').textContent = data.total_associations;
                    document.getElementById('anomaly-count').textContent = data.total_anomalies;
                });
        }
        
        function loadDevices() {
            fetch('/api/devices?limit=50')
                .then(r => r.json())
                .then(devices => {
                    const tbody = document.getElementById('devices-body');
                    if (devices.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6">No devices found</td></tr>';
                        return;
                    }
                    tbody.innerHTML = devices.map(d => `
                        <tr>
                            <td>${d.ip_address}</td>
                            <td>${d.mac_address}</td>
                            <td class="vendor">${d.vendor || 'Unknown'}</td>
                            <td class="timestamp">${d.first_seen}</td>
                            <td class="timestamp">${d.last_seen}</td>
                            <td>${d.packet_count} (${d.request_count}/${d.reply_count})</td>
                        </tr>
                    `).join('');
                });
        }
        
        function searchAddress() {
            const address = document.getElementById('search-input').value;
            if (!address) return;
            
            fetch('/api/query/' + encodeURIComponent(address))
                .then(r => r.json())
                .then(data => {
                    const resultsDiv = document.getElementById('search-results');
                    if (Object.keys(data).length === 0) {
                        resultsDiv.innerHTML = '<div class="anomaly">No results found for: ' + address + '</div>';
                        return;
                    }
                    resultsDiv.innerHTML = '<h3>Search Results</h3><pre>' + 
                        JSON.stringify(data, null, 2) + '</pre>';
                });
        }
        
        // Load data on page load
        loadStats();
        loadDevices();
        
        // Refresh every 10 seconds
        setInterval(() => {
            loadStats();
            loadDevices();
        }, 10000);
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    """Main page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/stats')
def api_stats():
    """Get database statistics"""
    stats = db.get_statistics()
    return jsonify(stats)

@app.route('/api/devices')
def api_devices():
    """Get all devices (with optional limit)"""
    limit = request.args.get('limit', type=int, default=100)
    devices = db.get_all_devices(limit=limit)
    return jsonify(devices)

@app.route('/api/query/<address>')
def api_query(address):
    """Query by IP or MAC address"""
    result = db.query_by_address(address)
    return jsonify(result)

@app.route('/api/export')
def api_export():
    """Export database to JSON"""
    import tempfile
    import json
    
    # Create temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        db.export_to_json(f.name)
        
        # Read and return
        with open(f.name, 'r') as rf:
            data = json.load(rf)
        
        os.unlink(f.name)
        return jsonify(data)

if __name__ == '__main__':
    print("Starting Blacktip Web Interface")
    print("Database: {}".format(DB_PATH))
    print("Visit: http://localhost:5000")
    print("")
    app.run(host='0.0.0.0', port=5000, debug=True)
