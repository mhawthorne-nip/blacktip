"""
Device state monitoring - tracks online/offline transitions
"""

import logging
import time
from typing import Dict, Set
from datetime import datetime, timezone

from .database import BlacktipDatabase

_logger = logging.getLogger(__name__)

# Consider device offline if not seen in this many minutes
OFFLINE_THRESHOLD_MINUTES = 10


class DeviceStateMonitor:
    """Monitor device state changes and log transitions"""
    
    def __init__(self, db: BlacktipDatabase):
        """Initialize state monitor
        
        Args:
            db: BlacktipDatabase instance
        """
        self.db = db
        self._known_states: Dict[str, str] = {}  # key: "ip:mac", value: "online" or "offline"
        self._initialize_known_states()
    
    def _initialize_known_states(self):
        """Initialize known states from database"""
        _logger.info("Initializing device state monitor...")
        
        # Get all devices and their current states
        devices = self.db.get_all_devices()
        
        for device in devices:
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
            # Parse timestamp
            timestamp_str = last_seen.rstrip('Z')
            
            if '.' in timestamp_str:
                last_seen_dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S.%f')
            else:
                last_seen_dt = datetime.strptime(timestamp_str, '%Y-%m-%dT%H:%M:%S')
            
            # Make timezone-aware
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
            
            now = datetime.now(timezone.utc)
            time_diff = now - last_seen_dt
            minutes_ago = time_diff.total_seconds() / 60
            
            return 'online' if minutes_ago <= OFFLINE_THRESHOLD_MINUTES else 'offline'
            
        except Exception as e:
            _logger.error("Error calculating state for last_seen {}: {}".format(last_seen, e))
            return 'offline'
    
    def check_state_changes(self):
        """Check all devices for state changes and log transitions"""
        devices = self.db.get_all_devices()
        transitions = 0
        
        for device in devices:
            key = "{}:{}".format(device['ip_address'], device['mac_address'])
            current_state = self._calculate_current_state(device['last_seen'])
            previous_state = self._known_states.get(key)
            
            # Check if state changed
            if previous_state != current_state:
                _logger.info("State transition detected: {} ({}) {} -> {}".format(
                    device['ip_address'], 
                    device['mac_address'],
                    previous_state or 'unknown',
                    current_state
                ))
                
                # Log the transition
                self.db.log_state_transition(
                    device['ip_address'],
                    device['mac_address'],
                    current_state,
                    previous_state,
                    current_state
                )
                
                # Update known state
                self._known_states[key] = current_state
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
