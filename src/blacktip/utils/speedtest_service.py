"""
Speedtest service for measuring internet connection performance.

Uses speedtest-cli library to perform download/upload speed tests and latency measurements.
"""

import logging
import speedtest
import time
from typing import Dict, Optional
from datetime import datetime

from .utils import timestamp
from .network_info import NetworkInfoCollector

_logger = logging.getLogger(__name__)


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
            
            # Initialize speedtest
            st = speedtest.Speedtest()
            
            # Get server list and select best server
            _logger.debug("Getting server list...")
            st.get_servers()
            st.get_best_server()
            
            server_info = st.best
            _logger.info("Selected server: {} ({}, {})".format(
                server_info.get('sponsor', 'Unknown'),
                server_info.get('name', 'Unknown'),
                server_info.get('country', 'Unknown')
            ))
            
            # Run download test
            _logger.debug("Testing download speed...")
            download_bps = st.download()
            download_mbps = download_bps / 1_000_000
            
            # Run upload test
            _logger.debug("Testing upload speed...")
            upload_bps = st.upload()
            upload_mbps = upload_bps / 1_000_000
            
            # Get ping/latency
            ping_ms = st.results.ping
            
            # Calculate test duration
            test_end = timestamp()
            duration = time.time() - start_time
            
            # Get client info
            client_info = st.results.client
            
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
                'server_name': server_info.get('sponsor'),
                'server_host': server_info.get('host'),
                'server_location': server_info.get('name'),
                'server_country': server_info.get('country'),
                'server_distance_km': round(server_info.get('d', 0), 2),
                'isp_name': client_info.get('isp'),
                'public_ip': client_info.get('ip'),
                'triggered_by': triggered_by
            }
            
            _logger.info("Speed test completed: {:.2f} Mbps down, {:.2f} Mbps up, {:.2f} ms ping".format(
                download_mbps, upload_mbps, ping_ms))
            
            # Update database record
            if self.database and test_id:
                self.database.update_speed_test(test_id, results)
                
                # Collect comprehensive network info with reverse DNS and geolocation
                network_info = self._network_collector.collect_network_info(
                    public_ip=client_info.get('ip'),
                    isp_name=client_info.get('isp')
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
                        ip_address=client_info.get('ip')
                    )
                    _logger.warning("Threshold violation: {}".format(violation['message']))
            
            self._last_test_time = time.time()
            return results
            
        except speedtest.ConfigRetrievalError as e:
            error_msg = "Failed to retrieve speedtest configuration: {}".format(str(e))
            _logger.error(error_msg)
            return self._handle_test_error(test_id, test_start, error_msg, triggered_by)
            
        except speedtest.NoMatchedServers as e:
            error_msg = "No speedtest servers matched criteria: {}".format(str(e))
            _logger.error(error_msg)
            return self._handle_test_error(test_id, test_start, error_msg, triggered_by)
            
        except speedtest.SpeedtestException as e:
            error_msg = "Speedtest error: {}".format(str(e))
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
