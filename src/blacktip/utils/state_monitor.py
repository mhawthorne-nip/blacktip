"""
Device state monitoring - tracks online/offline transitions
"""

import logging
import time
from typing import Dict, Set, Optional
from datetime import datetime, timezone

from .database import BlacktipDatabase
from .active_probe import ActiveProber

_logger = logging.getLogger(__name__)

# Default offline threshold (5 minutes)
DEFAULT_OFFLINE_THRESHOLD_SECONDS = 300


class DeviceStateMonitor:
    """Monitor device state changes and log transitions"""
    
    def __init__(self, db: BlacktipDatabase, 
                 offline_threshold_seconds: int = DEFAULT_OFFLINE_THRESHOLD_SECONDS,
                 enable_active_probing: bool = True,
                 probe_timeout: float = 1.0,
                 probe_retry_count: int = 2,
                 probe_failure_threshold: int = 2,
                 enable_icmp_fallback: bool = True,
                 probe_before_offline: bool = True,
                 periodic_probe_interval: int = 5,
                 interface: Optional[str] = None):
        """Initialize state monitor
        
        Args:
            db: BlacktipDatabase instance
            offline_threshold_seconds: Seconds before marking device offline (default: 300)
            enable_active_probing: Enable active ARP/ICMP probing
            probe_timeout: Timeout in seconds per probe attempt
            probe_retry_count: Number of retries for failed probes
            probe_failure_threshold: Consecutive failures before marking offline
            enable_icmp_fallback: Fall back to ICMP if ARP fails
            probe_before_offline: Probe device before marking offline
            periodic_probe_interval: Probe all online devices every N cycles (0 = disabled)
            interface: Network interface for probing
        """
        self.db = db
        self.offline_threshold_seconds = offline_threshold_seconds
        self.probe_before_offline = probe_before_offline
        self.periodic_probe_interval = periodic_probe_interval
        self._known_states: Dict[str, str] = {}  # key: "ip:mac", value: "online" or "offline"
        self._probe_failure_counts: Dict[str, int] = {}  # Track consecutive probe failures
        self._cycle_count: int = 0  # Track monitoring cycles for periodic probing
        
        # Initialize active prober
        self.prober = None
        if enable_active_probing:
            self.prober = ActiveProber(
                interface=interface,
                timeout=probe_timeout,
                retry_count=probe_retry_count,
                enable_icmp_fallback=enable_icmp_fallback
            )
            if self.prober.available:
                _logger.info(
                    "Active probing enabled: timeout={}s, retries={}, "
                    "failure_threshold={}, icmp_fallback={}, probe_before_offline={}, "
                    "periodic_interval={} cycles".format(
                        probe_timeout, probe_retry_count, probe_failure_threshold,
                        enable_icmp_fallback, probe_before_offline, periodic_probe_interval
                    )
                )
            else:
                _logger.warning(
                    "Active probing requested but not available - "
                    "falling back to passive monitoring only"
                )
                self.prober = None
        else:
            _logger.info("Active probing disabled - using passive monitoring only")
        
        self.probe_failure_threshold = probe_failure_threshold
        self._initialize_known_states()
    
    def _initialize_known_states(self):
        """Initialize known states from database"""
        _logger.info("Initializing device state monitor...")
        
        # Get all devices and their current states
        devices = self.db.get_all_devices()
        
        for device in devices:
            # Skip invalid/reserved IP addresses
            if device['ip_address'] in ['0.0.0.0', '255.255.255.255']:
                continue
            key = "{}:{}".format(device['ip_address'], device['mac_address'])
            
            # Check last known state from state events
            last_state = self.db.get_last_device_state(
                device['ip_address'], 
                device['mac_address']
            )
            
            if last_state:
                self._known_states[key] = last_state
            else:
                # No state history - determine current state
                current_state = self._calculate_current_state(device['last_seen'])
                self._known_states[key] = current_state
                
                # Log initial state
                self.db.log_state_transition(
                    device['ip_address'],
                    device['mac_address'],
                    current_state,
                    None,  # No previous state
                    current_state
                )
        
        _logger.info("Initialized {} device states".format(len(self._known_states)))
    
    def _calculate_current_state(self, last_seen: str) -> str:
        """Calculate if device is currently online or offline
        
        Args:
            last_seen: ISO 8601 timestamp string
            
        Returns:
            'online' or 'offline'
        """
        try:
            # Parse timestamp - handle various ISO 8601 formats
            # Try Python 3.7+ fromisoformat first (handles +00:00 timezone)
            try:
                # Replace 'Z' with '+00:00' for consistency
                timestamp_str = last_seen.replace('Z', '+00:00')
                last_seen_dt = datetime.fromisoformat(timestamp_str)
            except (ValueError, AttributeError):
                # Fallback for older formats or manual parsing
                timestamp_str = last_seen.rstrip('Z').split('+')[0].split('-')[0]
                
                if '.' in timestamp_str:
                    last_seen_dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
                else:
                    last_seen_dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
                
                # Make timezone-aware if not already
                if last_seen_dt.tzinfo is None:
                    last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
            
            # Ensure we have a timezone-aware datetime
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            time_diff = now - last_seen_dt
            seconds_ago = time_diff.total_seconds()
            
            return 'online' if seconds_ago <= self.offline_threshold_seconds else 'offline'
            
        except Exception as e:
            _logger.error("Error calculating state for last_seen {}: {}".format(last_seen, e))
            return 'offline'
    
    def _probe_device(self, ip: str, mac: str) -> bool:
        """
        Probe a device to check if it's actually online.
        
        Args:
            ip: Device IP address
            mac: Device MAC address
            
        Returns:
            True if device responded to probe, False otherwise
        """
        if not self.prober or not self.prober.available:
            return False
        
        is_online, method, error = self.prober.probe_device(ip, mac)
        
        if is_online:
            _logger.info("Active probe successful for {} via {}".format(ip, method))
            # Update last_seen timestamp since device is responsive
            now = datetime.now(timezone.utc).isoformat()
            self.db.update_device_last_seen(ip, mac, now)
            return True
        else:
            _logger.debug("Active probe failed for {}: {}".format(ip, error))
            return False
    
    def check_state_changes(self):
        """Check all devices for state changes and log transitions"""
        devices = self.db.get_all_devices()
        transitions = 0
        
        # Increment cycle counter for periodic probing
        self._cycle_count += 1
        periodic_probe_this_cycle = (
            self.periodic_probe_interval > 0 and 
            self._cycle_count % self.periodic_probe_interval == 0
        )
        
        if periodic_probe_this_cycle and self.prober and self.prober.available:
            _logger.info(
                "Periodic probe cycle {} - probing all online devices".format(
                    self._cycle_count
                )
            )
        
        for device in devices:
            # Skip invalid/reserved IP addresses
            if device['ip_address'] in ['0.0.0.0', '255.255.255.255']:
                continue
            
            key = "{}:{}".format(device['ip_address'], device['mac_address'])
            ip = device['ip_address']
            mac = device['mac_address']
            previous_state = self._known_states.get(key)
            
            # Periodic probing: probe online devices to keep them fresh
            if periodic_probe_this_cycle and previous_state == 'online':
                self._probe_device(ip, mac)
                # Re-fetch device to get updated last_seen
                device = self.db.get_device(ip, mac)
            
            # Calculate what state device should be in based on last_seen
            calculated_state = self._calculate_current_state(device['last_seen'])
            
            # If device would transition to offline, probe it first (if enabled)
            if (calculated_state == 'offline' and 
                previous_state == 'online' and 
                self.probe_before_offline):
                
                _logger.info(
                    "Device {} ({}) would go offline - attempting active probe".format(
                        ip, mac
                    )
                )
                
                probe_success = self._probe_device(ip, mac)
                
                if probe_success:
                    # Device responded! Update failure count and recalculate state
                    self._probe_failure_counts[key] = 0
                    device = self.db.get_device(ip, mac)
                    calculated_state = self._calculate_current_state(device['last_seen'])
                    _logger.info(
                        "Active probe prevented false offline for {} ({})".format(ip, mac)
                    )
                else:
                    # Probe failed - increment failure count
                    self._probe_failure_counts[key] = self._probe_failure_counts.get(key, 0) + 1
                    failure_count = self._probe_failure_counts[key]
                    
                    _logger.debug(
                        "Probe failure {}/{} for {} ({})".format(
                            failure_count, self.probe_failure_threshold, ip, mac
                        )
                    )
                    
                    # Only mark offline if failure threshold reached
                    if failure_count < self.probe_failure_threshold:
                        _logger.info(
                            "Device {} ({}) probe failed but under threshold - "
                            "keeping online".format(ip, mac)
                        )
                        calculated_state = 'online'  # Keep online until threshold reached
            else:
                # Not transitioning to offline, reset failure count
                if calculated_state == 'online' and key in self._probe_failure_counts:
                    del self._probe_failure_counts[key]
            
            # Check if state changed
            if previous_state != calculated_state:
                _logger.info("State transition detected: {} ({}) {} -> {}".format(
                    ip, 
                    mac,
                    previous_state or 'unknown',
                    calculated_state
                ))
                
                # Log the transition
                self.db.log_state_transition(
                    ip,
                    mac,
                    calculated_state,
                    previous_state,
                    calculated_state
                )
                
                # Update known state and reset failure count on transition
                self._known_states[key] = calculated_state
                if calculated_state == 'offline':
                    # Clear failure count after successful offline transition
                    self._probe_failure_counts.pop(key, None)
                transitions += 1
        
        if transitions > 0:
            _logger.info("Logged {} state transition(s)".format(transitions))
        
        return transitions
    
    def run_forever(self, check_interval_seconds: int = 60):
        """Run state monitoring loop forever
        
        Args:
            check_interval_seconds: How often to check for state changes
        """
        _logger.info("Starting device state monitor (checking every {} seconds)".format(
            check_interval_seconds))
        
        try:
            while True:
                try:
                    self.check_state_changes()
                except Exception as e:
                    _logger.error("Error checking state changes: {}".format(e))
                
                time.sleep(check_interval_seconds)
                
        except KeyboardInterrupt:
            _logger.info("State monitor stopped by user")
        except Exception as e:
            _logger.error("State monitor crashed: {}".format(e))
            raise
