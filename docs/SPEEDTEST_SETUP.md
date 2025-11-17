# Speed Test Feature Setup Guide

This guide explains how to configure and use the automatic speed test monitoring feature in Blacktip.

## Features

- **Automatic Speed Testing**: Schedule internet speed tests at regular intervals
- **Threshold Monitoring**: Set alerts for degraded internet performance
- **Historical Tracking**: View speed test history and trends over time
- **Web Dashboard**: Monitor current and historical performance via web UI

## Prerequisites

The speed test feature requires these dependencies (already in requirements.txt):
```bash
pip install speedtest-cli APScheduler
```

## Initial Setup

### 1. Initialize Default Thresholds

Run the threshold initialization script to set up default monitoring thresholds:

```bash
python scripts/init_speedtest_thresholds.py --database blacktip.db
```

**Default Thresholds:**
- Download Speed:
  - Warning: < 100 Mbps
  - Critical: < 50 Mbps
- Upload Speed:
  - Warning: < 20 Mbps
  - Critical: < 10 Mbps
- Latency (Ping):
  - Warning: > 50 ms
  - Critical: > 100 ms

**Customize for Your Connection:**

Adjust these values based on your expected internet speeds:

```bash
# View current thresholds
sqlite3 blacktip.db "SELECT * FROM speed_test_thresholds;"

# Update a threshold (example: change download warning to 200 Mbps)
sqlite3 blacktip.db "UPDATE speed_test_thresholds 
  SET threshold_value = 200.0 
  WHERE metric = 'download_mbps' AND severity = 'warning';"
```

Or use `--force` to reinitialize with modified script values:

```bash
# Edit scripts/init_speedtest_thresholds.py first, then:
python scripts/init_speedtest_thresholds.py --database blacktip.db --force
```

### 2. Enable Speed Test Scheduler

Run Blacktip with speed test scheduling enabled:

```bash
# Run speed test every hour (default)
sudo blacktip -f blacktip.db --enable-speedtest

# Run speed test every 2 hours
sudo blacktip -f blacktip.db --enable-speedtest --speedtest-interval 2

# Run speed test every 6 hours with metrics enabled
sudo blacktip -f blacktip.db --enable-speedtest --speedtest-interval 6 --metrics
```

**Important Notes:**
- First test runs 60 seconds after startup
- Minimum test interval is 5 minutes (enforced by SpeedTestService)
- Tests run in background while monitoring continues
- Scheduler shuts down gracefully on CTRL+C

## Web Interface

### Access the Dashboard

1. Start the web frontend:
   ```bash
   cd web-frontend
   ./run.sh
   ```

2. Open browser to: `http://localhost:5000`

3. Click **"Internet"** in the navigation menu

### Dashboard Features

**Latest Speed Test Card:**
- Current download/upload speeds
- Latency measurement
- Server location
- Test status and timestamp

**Network Information Card:**
- ISP name
- Public IP address
- Geographic location
- Timezone

**Trend Statistics:**
- Average speeds over time
- Selectable periods (7, 30, 90 days)
- Total tests run

**Test History Table:**
- Last 20 completed tests
- Download/upload/ping metrics
- Server locations
- Timestamps

### Manual Speed Tests

Click the **"Run Speed Test"** button to trigger an on-demand test. The UI will:
1. Show running state with spinner
2. Poll for results every 3 seconds
3. Auto-refresh when complete (20-30 seconds)
4. Display results or error messages

## Command Line Usage

### Run Manual Speed Test

```bash
# Via API (requires web frontend running)
curl -X POST http://localhost:5000/api/speed-tests/run

# Check latest results
curl http://localhost:5000/api/speed-tests?limit=1 | jq
```

### View Speed Test History

```bash
# Last 10 tests
curl http://localhost:5000/api/speed-tests?limit=10 | jq

# Get statistics for last 30 days
curl http://localhost:5000/api/speed-tests/statistics?days=30 | jq
```

## Configuration

### Scheduler Configuration

Edit `src/blacktip/__init__.py` to change defaults:

```python
# Speed test scheduler configuration
__speedtest_scheduler_enabled__ = False  # Enable by default
__speedtest_interval_hours__ = 1  # Default interval
```

### Database Schema

Speed tests are stored in these tables:

**speed_tests:**
- test_id (primary key)
- test_start, test_end
- test_status (running/completed/failed)
- download_mbps, upload_mbps, ping_ms
- server_name, server_location
- isp_name, public_ip
- triggered_by (manual/scheduled/auto)

**speed_test_thresholds:**
- threshold_id (primary key)
- metric (download_mbps/upload_mbps/ping_ms)
- operator (</>)
- threshold_value
- severity (warning/critical)
- enabled (boolean)

**network_info:**
- public_ip, isp_name
- city, region, country
- latitude, longitude
- last_seen

## Troubleshooting

### No Speed Tests Running

Check if scheduler is enabled:
```bash
# Should see "Speed test scheduler enabled" in logs
sudo blacktip -f blacktip.db --enable-speedtest --debug
```

### Dependencies Missing

Install required packages:
```bash
pip install speedtest-cli APScheduler
```

### Threshold Violations Not Appearing

1. Check thresholds are enabled:
   ```bash
   sqlite3 blacktip.db "SELECT * FROM speed_test_thresholds WHERE enabled = 1;"
   ```

2. Verify test results are being recorded:
   ```bash
   sqlite3 blacktip.db "SELECT * FROM speed_tests ORDER BY test_start DESC LIMIT 5;"
   ```

3. Check anomalies table:
   ```bash
   sqlite3 blacktip.db "SELECT * FROM anomalies WHERE anomaly_type = 'speed_degradation';"
   ```

### Speed Test Fails

Common causes:
- Network connectivity issues
- Firewall blocking speedtest-cli
- No available speedtest servers
- Timeout (tests take 20-30 seconds)

Check logs for detailed error messages:
```bash
sudo blacktip -f blacktip.db --enable-speedtest --debug
```

## Advanced Usage

### Custom Test Intervals

For very frequent testing (not recommended - may impact network):
```bash
# Every 30 minutes (0.5 hours)
sudo blacktip -f blacktip.db --enable-speedtest --speedtest-interval 0.5
```

### Integration with Monitoring Systems

Export metrics for external monitoring:

```bash
# Export to JSON
sqlite3 -json blacktip.db "
  SELECT 
    datetime(test_start) as time,
    download_mbps,
    upload_mbps,
    ping_ms
  FROM speed_tests 
  WHERE test_status = 'completed'
  ORDER BY test_start DESC 
  LIMIT 100
" > speedtest_metrics.json

# Export violations
sqlite3 -json blacktip.db "
  SELECT * FROM anomalies 
  WHERE anomaly_type = 'speed_degradation'
  ORDER BY timestamp DESC
" > speedtest_violations.json
```

### Scheduled Testing with Cron (Alternative)

If you don't want the scheduler, use cron instead:

```bash
# Run speed test every 2 hours via cron
# Add to crontab: crontab -e
0 */2 * * * curl -X POST http://localhost:5000/api/speed-tests/run
```

## Performance Considerations

- Each test takes 20-30 seconds and uses bandwidth
- Recommended minimum interval: 1 hour
- Tests run in background thread (non-blocking)
- Database writes are atomic
- Concurrent tests are prevented (5-minute minimum between tests)

## Security Notes

- Speed tests expose your public IP address
- ISP and location data is stored in database
- Web API has no authentication by default
- Consider firewall rules if exposing web UI
- Public IP and ISP information visible in web UI

## Support

For issues or questions:
1. Check logs with `--debug` flag
2. Verify dependencies are installed
3. Review database schema
4. Check GitHub issues

---

**Note:** Speed testing can consume bandwidth and may affect your internet usage. Configure intervals appropriate for your connection and usage patterns.
