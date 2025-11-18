"""
Speedtest service for measuring internet connection performance.

Uses Ookla's speedtest binary to perform download/upload speed tests and latency measurements.
"""

import logging
import subprocess
import json
import time
import shutil
from typing import Dict, Optional
from datetime import datetime

from .utils import timestamp
from .network_info import NetworkInfoCollector

_logger = logging.getLogger(__name__)

# Path to speedtest binary (installed via deploy.sh)
SPEEDTEST_BINARY = "/usr/local/bin/speedtest"


class SpeedTestService:
    """Service for running internet speed tests"""
    
    def __init__(self, database=None):
        """Initialize speedtest service
        
        Args:
            database: BlacktipDatabase instance for storing results
        """
        self.database = database
        self._last_test_time = None
        self._min_test_interval = 300  # Minimum 5 minutes between tests
        self._network_collector = NetworkInfoCollector()
        
        # Verify speedtest binary is available
        if not shutil.which(SPEEDTEST_BINARY):
            _logger.warning(
                "Speedtest binary not found at {}. "
                "Speed tests will fail until binary is installed.".format(SPEEDTEST_BINARY)
            )
    
    def run_speed_test(self, triggered_by: str = 'manual') -> Dict:
        """Run a speed test and return results
        
        Args:
            triggered_by: How the test was triggered ('manual', 'scheduled', 'auto')
            
        Returns:
            Dictionary with test results
        """
        _logger.info("Starting speed test (triggered by: {})".format(triggered_by))
        
        test_start = timestamp()
        start_time = time.time()
        test_id = None
        
        try:
            # Insert initial test record if database available
            if self.database:
                test_id = self.database.insert_speed_test({
                    'test_start': test_start,
                    'test_status': 'running',
                    'triggered_by': triggered_by
                })
            
            # Run speedtest binary with JSON output
            _logger.debug("Running speedtest binary...")
            result = subprocess.run(
                [SPEEDTEST_BINARY, '-f', 'json', '--accept-license', '--accept-gdpr'],
                capture_output=True,
                text=True,
                timeout=120  # 2 minute timeout
            )
            
            if result.returncode != 0:
                raise Exception("Speedtest failed with exit code {}: {}".format(
                    result.returncode, result.stderr))
            
            # Parse JSON output
            data = json.loads(result.stdout)
            
            # Extract server info
            server = data.get('server', {})
            _logger.info("Selected server: {} ({}, {})".format(
                server.get('name', 'Unknown'),
                server.get('location', 'Unknown'),
                server.get('country', 'Unknown')
            ))
            
            # Convert bandwidth from bytes/sec to Mbps
            download_bps = data.get('download', {}).get('bandwidth', 0)
            upload_bps = data.get('upload', {}).get('bandwidth', 0)
            download_mbps = (download_bps * 8) / 1_000_000  # bytes/sec -> Mbps
            upload_mbps = (upload_bps * 8) / 1_000_000
            
            # Extract latency metrics
            ping = data.get('ping', {})
            ping_ms = ping.get('latency', 0)
            jitter_ms = ping.get('jitter', 0)
            
            # Extract packet loss (0 if not available)
            packet_loss = data.get('packetLoss', 0)
            
            # Extract download/upload latency details
            download_latency = data.get('download', {}).get('latency', {})
            upload_latency = data.get('upload', {}).get('latency', {})
            
            # Calculate test duration
            test_end = timestamp()
            duration = time.time() - start_time
            
            # Extract client/ISP info
            isp = data.get('isp', 'Unknown')
            interface = data.get('interface', {})
            public_ip = interface.get('externalIp', '')
            
            # Extract result URL
            result_data = data.get('result', {})
            result_url = result_data.get('url', '')
            
            # Prepare result data
            results = {
                'test_id': test_id,
                'test_start': test_start,
                'test_end': test_end,
                'test_status': 'completed',
                'test_duration_seconds': duration,
                'download_mbps': round(download_mbps, 2),
                'upload_mbps': round(upload_mbps, 2),
                'ping_ms': round(ping_ms, 2),
                'jitter_ms': round(jitter_ms, 2),
                'packet_loss_percent': packet_loss,
                'download_latency_iqm': round(download_latency.get('iqm', 0), 2),
                'download_latency_low': round(download_latency.get('low', 0), 2),
                'download_latency_high': round(download_latency.get('high', 0), 2),
                'upload_latency_iqm': round(upload_latency.get('iqm', 0), 2),
                'upload_latency_low': round(upload_latency.get('low', 0), 2),
                'upload_latency_high': round(upload_latency.get('high', 0), 2),
                'server_name': server.get('name'),
                'server_host': server.get('host'),
                'server_location': server.get('location'),
                'server_country': server.get('country'),
                'server_distance_km': 0,  # Not provided in new format
                'isp_name': isp,
                'public_ip': public_ip,
                'result_url': result_url,
                'triggered_by': triggered_by
            }
            
            _logger.info("Speed test completed: {:.2f} Mbps down, {:.2f} Mbps up, {:.2f} ms ping".format(
                download_mbps, upload_mbps, ping_ms))
            
            # Update database record
            if self.database and test_id:
                self.database.update_speed_test(test_id, results)
                
                # Collect comprehensive network info with reverse DNS and geolocation
                network_info = self._network_collector.collect_network_info(
                    public_ip=public_ip,
                    isp_name=isp
                )
                
                # Update network info in database
                if network_info:
                    self.database.upsert_network_info(network_info)
                
                # Check thresholds and create anomalies if needed
                violations = self.database.check_speed_test_thresholds(results)
                for violation in violations:
                    self.database.log_anomaly(
                        anomaly_type='speed_degradation',
                        message=violation['message'],
                        ip_address=public_ip
                    )
                    _logger.warning("Threshold violation: {}".format(violation['message']))
            
            self._last_test_time = time.time()
            return results
            
        except subprocess.TimeoutExpired:
            error_msg = "Speedtest timed out after 120 seconds"
            _logger.error(error_msg)
            return self._handle_test_error(test_id, test_start, error_msg, triggered_by)
            
        except json.JSONDecodeError as e:
            error_msg = "Failed to parse speedtest JSON output: {}".format(str(e))
            _logger.error(error_msg)
            return self._handle_test_error(test_id, test_start, error_msg, triggered_by)
            
        except FileNotFoundError:
            error_msg = "Speedtest binary not found at {}".format(SPEEDTEST_BINARY)
            _logger.error(error_msg)
            return self._handle_test_error(test_id, test_start, error_msg, triggered_by)
            
        except Exception as e:
            error_msg = "Unexpected error during speed test: {}".format(str(e))
            _logger.error(error_msg, exc_info=True)
            return self._handle_test_error(test_id, test_start, error_msg, triggered_by)
    
    def _handle_test_error(self, test_id: Optional[int], test_start: str, 
                          error_msg: str, triggered_by: str) -> Dict:
        """Handle speed test error and update database
        
        Args:
            test_id: Test ID if database record was created
            test_start: Test start timestamp
            error_msg: Error message
            triggered_by: How test was triggered
            
        Returns:
            Error result dictionary
        """
        test_end = timestamp()
        
        error_result = {
            'test_id': test_id,
            'test_start': test_start,
            'test_end': test_end,
            'test_status': 'failed',
            'error_message': error_msg,
            'triggered_by': triggered_by
        }
        
        # Update database if test was recorded
        if self.database and test_id:
            self.database.update_speed_test(test_id, error_result)
        
        return error_result
    
    def can_run_test(self) -> bool:
        """Check if enough time has passed since last test
        
        Returns:
            True if test can be run, False otherwise
        """
        if self._last_test_time is None:
            return True
        
        elapsed = time.time() - self._last_test_time
        return elapsed >= self._min_test_interval
    
    def get_recent_results(self, limit: int = 10) -> list:
        """Get recent speed test results from database
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of speed test result dictionaries
        """
        if not self.database:
            return []
        
        return self.database.get_speed_tests(limit=limit)
    
    def get_statistics(self, days: Optional[int] = None) -> Dict:
        """Get speed test statistics
        
        Args:
            days: Calculate stats for last N days (None for all time)
            
        Returns:
            Dictionary with average speeds and other stats
        """
        if not self.database:
            return {}
        
        return self.database.get_speed_test_statistics(days=days)
    
    def set_min_test_interval(self, seconds: int):
        """Set minimum interval between tests
        
        Args:
            seconds: Minimum seconds between tests
        """
        self._min_test_interval = max(60, seconds)  # Minimum 1 minute
        _logger.info("Set minimum test interval to {} seconds".format(self._min_test_interval))
